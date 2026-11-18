//! Controlled receiver implementation shared by native operational proofs and
//! integration tests. These are real owned loopback listeners, not providers.
use super::io::RamaIo;
use super::{Limits, capture, http2, network, protocol};
use crate::domain::values::Digest;
use crate::protocol::error::ProofResult;
use rama::http::core::body::Incoming;
use rama::http::core::h2;
use rama::http::{Body, Request, Response};
use rama::service::service_fn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::{JoinHandle, JoinSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverRecord {
    pub sequence: u64,
    pub method: String,
    pub target: String,
    pub authority: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body_sha256: Digest,
    pub body_bytes: u64,
    pub started_us: u64,
    pub finished_us: u64,
    pub stream_id: u32,
    pub http_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[derive(Default)]
pub(crate) struct Receiver {
    records: Mutex<Vec<ReceiverRecord>>,
    arrivals: std::sync::atomic::AtomicU64,
    connections: std::sync::atomic::AtomicU64,
}
impl Receiver {
    pub fn count(&self) -> u64 {
        self.arrivals.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn connections(&self) -> u64 {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn connected(&self) {
        self.connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn records(&self) -> ProofResult<Vec<ReceiverRecord>> {
        Ok(self.records.lock().map_err(|_| network())?.clone())
    }
    fn arrive(&self) -> u64 {
        self.arrivals
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }
    fn finish(&self, record: ReceiverRecord) -> ProofResult<()> {
        let mut records = self.records.lock().map_err(|_| network())?;
        if records.len() >= 4096 {
            return Err(super::bounded());
        }
        records.push(record);
        Ok(())
    }
}

pub(crate) struct Endpoint {
    pub address: SocketAddr,
    pub receiver: Arc<Receiver>,
    _tasks: Vec<super::io::OwnedTask<()>>,
}
impl Endpoint {
    pub fn url(&self, tls: bool, host: &str, path: &str) -> String {
        format!(
            "{}://{host}:{}{path}",
            if tls { "https" } else { "http" },
            self.address.port()
        )
    }
    pub fn start(
        runtime: &Runtime,
        tls: Option<Arc<rustls::ServerConfig>>,
        h2_mode: bool,
        limits: Limits,
        redirect: Option<String>,
        dual: bool,
    ) -> ProofResult<Self> {
        runtime.block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| network())?;
            let address = listener.local_addr().map_err(|_| network())?;
            let receiver = Arc::new(Receiver::default());
            let mut tasks = vec![super::io::OwnedTask::new(spawn_listener(
                listener,
                Arc::clone(&receiver),
                tls.clone(),
                h2_mode,
                limits.clone(),
                redirect.clone(),
            ))];
            if dual {
                let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, address.port()))
                    .await
                    .map_err(|_| network())?;
                tasks.push(super::io::OwnedTask::new(spawn_listener(
                    listener,
                    Arc::clone(&receiver),
                    tls,
                    h2_mode,
                    limits,
                    redirect,
                )));
            }
            Ok(Self {
                address,
                receiver,
                _tasks: tasks,
            })
        })
    }
    pub fn raw(runtime: &Runtime, bytes: Vec<u8>, limits: Limits) -> ProofResult<Self> {
        let bytes = rama::bytes::Bytes::from(bytes);
        runtime.block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| network())?;
            let address = listener.local_addr().map_err(|_| network())?;
            let receiver = Arc::new(Receiver::default());
            let observed = Arc::clone(&receiver);
            let task = tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    observed.connected();
                    let bytes = bytes.clone();
                    let connection_observed = Arc::clone(&observed);
                    connections.spawn(async move {
                        let mut request = [0; 65_536];
                        if stream.read(&mut request).await.is_ok_and(|read| read > 0) {
                            connection_observed.arrive();
                            // Deliberately malformed origin wire bytes exercise
                            // Rama's real framing decoder, never a homegrown parser.
                            let _ = stream.write_all(&bytes).await;
                            let _ = stream.shutdown().await;
                        }
                    });
                    while connections.try_join_next().is_some() {}
                    if observed.count() > limits.requests as u64 * 4 {
                        break;
                    }
                }
                connections.shutdown().await;
            });
            Ok(Self {
                address,
                receiver,
                _tasks: vec![super::io::OwnedTask::new(task)],
            })
        })
    }
}
fn spawn_listener(
    listener: TcpListener,
    receiver: Arc<Receiver>,
    tls: Option<Arc<rustls::ServerConfig>>,
    h2_mode: bool,
    limits: Limits,
    redirect: Option<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            receiver.connected();
            let receiver = Arc::clone(&receiver);
            let tls = tls.clone();
            let limits = limits.clone();
            let redirect = redirect.clone();
            connections.spawn(async move {
                let result = async {
                    if let Some(tls) = tls {
                        let stream = rama::tls::rustls::dep::tokio_rustls::TlsAcceptor::from(tls)
                            .accept(stream)
                            .await
                            .map_err(|_| super::tls_error())?;
                        if h2_mode {
                            serve_h2(stream, receiver, limits).await
                        } else {
                            serve_http1(stream, receiver, limits, redirect).await
                        }
                    } else {
                        serve_http1(stream, receiver, limits, redirect).await
                    }
                };
                let _ = tokio::time::timeout(limits_deadline(), result).await;
            });
            while connections.try_join_next().is_some() {}
        }
        connections.shutdown().await;
    })
}
fn limits_deadline() -> std::time::Duration {
    std::time::Duration::from_secs(10)
}
fn header_map(headers: &rama::http::HeaderMap) -> ProofResult<BTreeMap<String, Vec<String>>> {
    let mut map = BTreeMap::new();
    for header in capture::headers(headers)? {
        map.entry(header.name)
            .or_insert_with(Vec::new)
            .push(header.value);
    }
    Ok(map)
}
fn target<BodyType>(request: &Request<BodyType>) -> String {
    let path = request.uri().path_or_root();
    match request.uri().query() {
        Some(query) => format!("{path}?{query}"),
        None => path.into_owned(),
    }
}
async fn serve_http1<IO>(
    stream: IO,
    receiver: Arc<Receiver>,
    limits: Limits,
    redirect: Option<String>,
) -> ProofResult<()>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let receiver = Arc::clone(&receiver);
        let limits = limits.clone();
        let redirect = redirect.clone();
        async move {
            let sequence = receiver.arrive();
            let started_us = super::clock_us();
            let method = request.method().as_str().to_owned();
            let path = target(&request);
            let authority = observed_authority(&request);
            let version = format!("{:?}", request.version());
            let headers = header_map(request.headers());
            let result = capture::collect(request.into_body(), &limits).await;
            let response = match (headers, result) {
                (Ok(headers), Ok(body)) => {
                    let content_length = headers
                        .get("x-razen-framing")
                        .and_then(|v| v.first())
                        .is_some_and(|v| v == "content-length")
                        || sequence.is_multiple_of(2);
                    let record = ReceiverRecord {
                        sequence,
                        method,
                        authority,
                        target: path.clone(),
                        headers,
                        body_sha256: Digest::of(&body.bytes),
                        body_bytes: body.bytes.len() as u64,
                        started_us,
                        finished_us: super::clock_us(),
                        stream_id: 0,
                        http_version: version,
                        error: None,
                    };
                    let _ = receiver.finish(record);
                    if let Some(location) = redirect {
                        Response::builder()
                            .status(307)
                            .header("location", location)
                            .body(Body::empty())
                            .expect("fixture redirect")
                    } else {
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .header("x-razen-duplicate", "first")
                            .header("x-razen-duplicate", "second")
                            .body(if content_length {
                                Body::from(body.bytes)
                            } else {
                                Body::from_stream(rama::futures::stream::iter([
                                    Ok::<_, Infallible>(rama::bytes::Bytes::from(body.bytes)),
                                ]))
                            })
                            .expect("fixture echo")
                    }
                }
                _ => Response::builder()
                    .status(400)
                    .body(Body::from("Invalid fixture request"))
                    .expect("fixture rejection"),
            };
            Ok::<_, Infallible>(response)
        }
    });
    rama::http::core::server::conn::http1::Builder::new()
        .with_max_headers(256)
        .try_with_max_buf_size(65_536)
        .map_err(|_| protocol())?
        .serve_connection(RamaIo::new(stream), service)
        .await
        .map_err(|_| protocol())
}
async fn serve_h2<IO>(stream: IO, receiver: Arc<Receiver>, limits: Limits) -> ProofResult<()>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut connection = h2::server::Builder::new()
        .with_max_concurrent_streams(2)
        .with_max_header_list_size(65_536)
        .handshake::<_, rama::bytes::Bytes>(RamaIo::new(stream))
        .await
        .map_err(|_| protocol())?;
    let mut streams = JoinSet::new();
    while let Some(request) = connection.accept().await {
        let (request, mut respond) = request.map_err(|_| protocol())?;
        let receiver = Arc::clone(&receiver);
        let limits = limits.clone();
        streams.spawn(async move {
            let sequence = receiver.arrive();
            let started_us = super::clock_us();
            let id = u32::from(respond.stream_id());
            let method = request.method().as_str().to_owned();
            let path = target(&request);
            let authority = observed_authority(&request);
            let version = format!("{:?}", request.version());
            let headers = header_map(request.headers());
            let result = http2::receive(request.into_body(), &limits).await;
            if let (Ok(headers), Ok((body, _))) = (headers, result) {
                // A real receiver-side hold makes overlap observable. Cancellation
                // is polled while held, not inferred from a dropped client handle.
                let reset = tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(120)) => None,
                    reset = std::future::poll_fn(|cx| respond.poll_reset(cx)) => Some(reset),
                };
                let error = reset.map(|result| match result {
                    Ok(reason) => format!("reset:{reason:?}"),
                    Err(_) => "stream-error".to_owned(),
                });
                let record = ReceiverRecord {
                    sequence,
                    method,
                    authority,
                    target: path,
                    headers,
                    body_sha256: Digest::of(&body),
                    body_bytes: body.len() as u64,
                    started_us,
                    finished_us: super::clock_us(),
                    stream_id: id,
                    http_version: version,
                    error: error.clone(),
                };
                let _ = receiver.finish(record);
                if error.is_none() {
                    let response = Response::builder()
                        .status(200)
                        .version(rama::http::Version::HTTP_2)
                        .header("content-type", "application/octet-stream")
                        .header("x-razen-duplicate", "first")
                        .header("x-razen-duplicate", "second")
                        .body(())
                        .expect("fixture H2 response");
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = http2::send_bytes(&mut stream, &body, &limits).await;
                    }
                }
            }
        });
        while streams.try_join_next().is_some() {}
    }
    streams.shutdown().await;
    Ok(())
}

fn observed_authority<B>(request: &Request<B>) -> String {
    request
        .uri()
        .authority()
        .map(|authority| authority.to_string())
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}
