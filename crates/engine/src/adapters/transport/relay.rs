use super::http1::{self, Received};
use super::io::RamaIo;
use super::scope_connector::{self, Authority};
use super::{Limits, Mode, TransportConfig, capture, invalid, network};
use crate::domain::evidence::Header;
use crate::domain::values::{Digest, EntityId};
use crate::protocol::error::{ProofError, ProofResult};
use rama::http::core::body::Incoming;
use rama::http::io::upgrade::{Upgraded, handle_upgrade};
use rama::http::{Body, Request, Response, Version};
use rama::service::service_fn;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

#[derive(Default)]
pub(crate) struct Facts {
    pub upstream_tls: Option<(String, Digest)>,
    pub ingress_tls: Option<String>,
    pub connect_authority: Option<String>,
    pub tls_server_name: Option<String>,
    pub errors: Vec<ProofError>,
    pub stream_errors: Vec<(u32, ProofError)>,
    pub stream_links: Vec<super::StreamLink>,
    pub tunnel_bytes: Option<(u64, u64)>,
    pub redirects: usize,
    pub redirect_chain: Vec<super::scope_connector::RedirectFact>,
    pub partials: Vec<Received>,
}
pub(crate) type SharedFacts = Arc<Mutex<Facts>>;
type Tasks = Arc<Mutex<Vec<super::io::OwnedTask<()>>>>;

pub(crate) struct Exchange {
    pub received: ProofResult<Received>,
    pub stream_id: u32,
    pub started_us: u64,
    pub finished_us: u64,
}
pub(crate) async fn direct(
    authority: Arc<Authority>,
    config: TransportConfig,
    limits: Limits,
    request: super::RequestData,
) -> ProofResult<Outcome> {
    let super::RequestData {
        url,
        method,
        headers,
        body,
    } = request;
    if config.mode != Mode::Http1Forward {
        return Err(super::protocol());
    }
    let request = http1::request(&url, &method, &headers, body, Version::HTTP_11)?;
    let started = Instant::now();
    let received = match tokio::time::timeout(
        limits.deadline,
        http1::upstream(authority, &config, &url, request, &limits),
    )
    .await
    {
        Ok(received) => received,
        Err(_) => Err(super::timeout()),
    };
    Ok(Outcome {
        exchanges: vec![Exchange {
            received,
            stream_id: 0,
            started_us: 0,
            finished_us: started.elapsed().as_micros() as u64,
        }],
        connection_id: EntityId::new(),
        facts: Facts::default(),
    })
}

pub(crate) struct Outcome {
    pub exchanges: Vec<Exchange>,
    pub connection_id: EntityId,
    pub facts: Facts,
}

pub(crate) async fn run(
    authority: Arc<Authority>,
    config: TransportConfig,
    limits: Limits,
    request: super::RequestData,
    count: usize,
    reset_first: bool,
) -> ProofResult<Outcome> {
    let super::RequestData {
        url,
        method,
        headers,
        body,
    } = request;
    let deadline = tokio::time::Instant::now() + limits.deadline;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| network())?;
    let address = listener.local_addr().map_err(|_| network())?;
    authority.recheck()?;
    let owned_client = tokio::time::timeout_at(deadline, TcpStream::connect(address))
        .await
        .map_err(|_| super::timeout())?
        .map_err(|_| network())?;
    let owned_peer = owned_client.local_addr().map_err(|_| network())?;
    let facts = Arc::new(Mutex::new(Facts::default()));
    let upgrades: Tasks = Arc::new(Mutex::new(Vec::new()));
    let server_authority = Arc::clone(&authority);
    let server_config = config.clone();
    let server_limits = limits.clone();
    let server_url = url.clone();
    let server_facts = Arc::clone(&facts);
    let server_upgrades = Arc::clone(&upgrades);
    let server = tokio::spawn(async move {
        async {
            let (stream, peer) = listener.accept().await.map_err(|_| network())?;
            if peer != owned_peer {
                return Err(super::tls_error());
            }
            let service = service_fn(move |request: Request<Incoming>| {
                let authority = Arc::clone(&server_authority);
                let config = server_config.clone();
                let limits = server_limits.clone();
                let url = server_url.clone();
                let facts = Arc::clone(&server_facts);
                let tasks = Arc::clone(&server_upgrades);
                async move {
                    if request.method() == rama::http::Method::CONNECT {
                        let result = connect_request(
                            request,
                            authority,
                            config,
                            limits,
                            url,
                            Arc::clone(&facts),
                            tasks,
                        )
                        .await;
                        return Ok::<_, Infallible>(match result {
                            Ok(response) => response,
                            Err(error) => {
                                record(&facts, error);
                                error_response()
                            }
                        });
                    }
                    let result = forward(
                        request,
                        authority,
                        &config,
                        &limits,
                        &url,
                        Arc::clone(&facts),
                    )
                    .await;
                    Ok::<_, Infallible>(match result {
                        Ok(response) => response,
                        Err(error) => {
                            record(&facts, error);
                            error_response()
                        }
                    })
                }
            });
            rama::http::core::server::conn::http1::Builder::new()
                .with_max_headers(256)
                .try_with_max_buf_size(65_536)
                .map_err(|_| invalid())?
                .serve_connection(RamaIo::new(stream), service)
                .with_upgrades()
                .await
                .map_err(|_| super::protocol())
        }
        .await
    });
    let server = super::io::OwnedTask::new(server);
    let start = Instant::now();
    let client = async {
        authority.recheck()?;
        let stream = owned_client;
        if !config.mode.tls() {
            let request = http1::request(&url, &method, &headers, body, Version::HTTP_11)?;
            let received = http1::send(stream, request, &limits).await;
            return Ok(vec![Exchange {
                received,
                stream_id: 0,
                started_us: 0,
                finished_us: start.elapsed().as_micros() as u64,
            }]);
        }
        let authority_text = config.connect_authority.as_ref().ok_or_else(invalid)?;
        let upgraded = connect_client(stream, authority_text).await?;
        let name = config.tls_server_name.as_ref().ok_or_else(invalid)?;
        let (tls, client_alpn, certificate) = super::intercept::client_tls(
            upgraded,
            Arc::clone(&config.client_roots),
            name,
            config.mode.alpn(),
        )
        .await?;
        if config.mode == Mode::HttpsConnectTunnel {
            facts.lock().map_err(|_| network())?.ingress_tls = Some(client_alpn.clone());
        }
        if config.mode == Mode::HttpsHttp2Intercept {
            let results = super::http2::client(
                tls,
                super::RequestData {
                    url,
                    method,
                    headers,
                    body,
                },
                count,
                reset_first,
                &limits,
            )
            .await?;
            Ok(results
                .into_iter()
                .map(|result| Exchange {
                    received: result.received,
                    stream_id: result.stream_id,
                    started_us: result.started_us,
                    finished_us: result.finished_us,
                })
                .collect())
        } else {
            let request = http1::request(&url, &method, &headers, body, Version::HTTP_11)?;
            if config.mode == Mode::HttpsConnectTunnel {
                authority.recheck()?;
                authority.note_request(
                    rama::http::StreamingBody::size_hint(request.body())
                        .exact()
                        .ok_or_else(invalid)?,
                )?;
            }
            let mut received = http1::send(tls, request, &limits).await;
            if config.mode == Mode::HttpsConnectTunnel {
                if let Ok(response) = &received {
                    authority.note_response(response.bytes.len() as u64)?;
                }
                if let Ok(received) = &mut received {
                    received.certificate = Some(certificate);
                    received.upstream_alpn = Some(client_alpn);
                }
            }
            Ok(vec![Exchange {
                received,
                stream_id: 0,
                started_us: 0,
                finished_us: start.elapsed().as_micros() as u64,
            }])
        }
    };
    let client = match tokio::time::timeout_at(deadline, client).await {
        Ok(result) => result,
        Err(_) => Err(super::timeout()),
    };
    server.abort();
    let _ = server.await;
    let tasks = std::mem::take(&mut *upgrades.lock().map_err(|_| network())?);
    for mut task in tasks {
        if tokio::time::timeout(std::time::Duration::from_millis(100), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
    let captured = std::mem::take(&mut *facts.lock().map_err(|_| network())?);
    // A proxy's explicit error is authoritative; a generated HTTP error response
    // must never be reported as a successful exchange or empty capture.
    let mut exchanges = match client {
        Ok(exchanges) => exchanges,
        Err(error) => vec![Exchange {
            received: Err(error),
            stream_id: 0,
            started_us: 0,
            finished_us: start.elapsed().as_micros() as u64,
        }],
    };
    if let Some(error) = captured.errors.first() {
        for exchange in &mut exchanges {
            if exchange
                .received
                .as_ref()
                .is_ok_and(|response| response.status == 502)
            {
                exchange.received = Err(error.clone());
            }
        }
    }
    if let Some((alpn, certificate)) = &captured.upstream_tls {
        for exchange in &mut exchanges {
            if let Ok(response) = &mut exchange.received {
                response.upstream_alpn = Some(alpn.clone());
                response.certificate = Some(*certificate);
            }
        }
    }
    Ok(Outcome {
        exchanges,
        connection_id: EntityId::new(),
        facts: captured,
    })
}

async fn connect_client(stream: TcpStream, authority: &str) -> ProofResult<Upgraded> {
    let (mut sender, connection) = rama::http::core::client::conn::http1::Builder::new()
        .with_max_headers(256)
        .try_with_max_buf_size(65_536)
        .map_err(|_| invalid())?
        .handshake::<_, Body>(RamaIo::new(stream))
        .await
        .map_err(|_| network())?;
    let driver = super::io::OwnedTask::new(tokio::spawn(connection.with_upgrades()));
    let request = Request::builder()
        .method("CONNECT")
        .uri(rama::net::uri::Uri::parse_authority_form(authority).map_err(|_| invalid())?)
        .header("host", authority)
        .body(Body::empty())
        .map_err(|_| invalid())?;
    let response = sender.send_request(request).await.map_err(|_| network())?;
    if response.status().as_u16() != 200 {
        driver.abort();
        let _ = driver.await;
        return Err(super::tls_error());
    }
    let upgraded = handle_upgrade(response).await.map_err(|_| network())?;
    // Upgrade consumes the socket and completes the HTTP connection driver.
    drop(sender);
    driver
        .await
        .map_err(|_| network())?
        .map_err(|_| network())?;
    Ok(upgraded)
}

async fn connect_request(
    request: Request<Incoming>,
    authority: Arc<Authority>,
    config: TransportConfig,
    limits: Limits,
    url: String,
    facts: SharedFacts,
    tasks: Tasks,
) -> ProofResult<Response> {
    let expected = config.connect_authority.as_ref().ok_or_else(invalid)?;
    let actual = request.uri().as_str();
    if actual.as_ref() != expected.as_str() {
        return Err(super::tls_error());
    }
    facts.lock().map_err(|_| network())?.connect_authority = Some(actual.into_owned());
    let destination = scope_connector::normalize(&url)?;
    let addresses = config.resolver.resolve(&destination).await?;
    authority.authorize(
        &destination,
        &addresses,
        *addresses.first().ok_or_else(network)?,
        Some(expected),
        None,
        None,
    )?;
    let upstream = if config.mode == Mode::HttpsConnectTunnel {
        Some(
            scope_connector::connect(&authority, &config, &url, Some(expected))
                .await?
                .0,
        )
    } else {
        None
    };
    let upgrade = handle_upgrade(request);
    let task_facts = Arc::clone(&facts);
    let task = tokio::spawn(async move {
        let result = async {
            let upgraded = upgrade.await.map_err(|_| network())?;
            if let Some(upstream) = upstream {
                let counts = super::tunnel::copy(upgraded, upstream).await?;
                task_facts.lock().map_err(|_| network())?.tunnel_bytes = Some(counts);
                return Ok(());
            }
            let (tls, name, alpn) = super::intercept::server_tls(upgraded, &config).await?;
            {
                let mut facts = task_facts.lock().map_err(|_| network())?;
                facts.ingress_tls = Some(alpn);
                facts.tls_server_name = Some(name);
            }
            if config.mode == Mode::HttpsHttp2Intercept {
                super::http2::relay(tls, authority, config, url, limits, Arc::clone(&task_facts))
                    .await
            } else {
                serve_decrypted(tls, authority, config, url, limits, Arc::clone(&task_facts)).await
            }
        }
        .await;
        if let Err(error) = result {
            record(&task_facts, error);
        }
    });
    tasks
        .lock()
        .map_err(|_| network())?
        .push(super::io::OwnedTask::new(task));
    Response::builder()
        .status(200)
        .body(Body::empty())
        .map_err(|_| invalid())
}

async fn serve_decrypted<IO>(
    io: IO,
    authority: Arc<Authority>,
    config: TransportConfig,
    url: String,
    limits: Limits,
    facts: SharedFacts,
) -> ProofResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let authority = Arc::clone(&authority);
        let config = config.clone();
        let url = url.clone();
        let limits = limits.clone();
        let facts = Arc::clone(&facts);
        async move {
            let result = forward(
                request,
                authority,
                &config,
                &limits,
                &url,
                Arc::clone(&facts),
            )
            .await;
            Ok::<_, Infallible>(match result {
                Ok(response) => response,
                Err(error) => {
                    record(&facts, error);
                    error_response()
                }
            })
        }
    });
    rama::http::core::server::conn::http1::Builder::new()
        .with_max_headers(256)
        .try_with_max_buf_size(65_536)
        .map_err(|_| super::protocol())?
        .serve_connection(RamaIo::new(io), service)
        .await
        .map_err(|_| super::protocol())
}

async fn forward(
    request: Request<Incoming>,
    authority: Arc<Authority>,
    config: &TransportConfig,
    limits: &Limits,
    initial_url: &str,
    facts: SharedFacts,
) -> ProofResult<Response> {
    capture::encoding(request.headers())?;
    let actual_authority = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid)?;
    let destination = scope_connector::normalize(initial_url)?;
    if request.uri().authority().is_some() {
        if scope_connector::normalize(&request.uri().as_str())? != destination {
            return Err(super::tls_error());
        }
    } else {
        let expected = url::Url::parse(initial_url).map_err(|_| invalid())?;
        let target = match expected.query() {
            Some(query) => format!("{}?{query}", expected.path()),
            None => expected.path().to_owned(),
        };
        if request.uri().as_str() != target {
            return Err(super::tls_error());
        }
    }
    let addresses = config.resolver.resolve(&destination).await?;
    authority.authorize(
        &destination,
        &addresses,
        *addresses.first().ok_or_else(network)?,
        config.connect_authority.as_deref(),
        config.tls_server_name.as_deref(),
        Some(actual_authority),
    )?;
    let method = request.method().as_str().to_owned();
    let headers = capture::headers(request.headers())?;
    let body = rama::bytes::Bytes::from(
        capture::collect(request.into_body(), limits)
            .await
            .map_err(|failure| failure.error)?
            .bytes,
    );
    let mut url = initial_url.to_owned();
    for redirect in 0..=limits.redirects {
        authority.recheck()?;
        let parsed = url::Url::parse(&url).map_err(|_| invalid())?;
        let mut current_headers: Vec<_> = headers
            .iter()
            .filter(|h| !h.name.eq_ignore_ascii_case("host"))
            .cloned()
            .collect();
        current_headers.push(Header {
            name: "host".to_owned(),
            value: parsed.authority().to_owned(),
        });
        let request = http1::request(
            &url,
            &method,
            &current_headers,
            body.clone(),
            Version::HTTP_11,
        )?;
        let response =
            http1::upstream(Arc::clone(&authority), config, &url, request, limits).await?;
        if let (Some(alpn), Some(certificate)) = (&response.upstream_alpn, response.certificate) {
            facts.lock().map_err(|_| network())?.upstream_tls = Some((alpn.clone(), certificate));
        }
        if let Some(error) = response.error.clone() {
            facts.lock().map_err(|_| network())?.partials.push(response);
            return Err(error);
        }
        if [301, 302, 303, 307, 308].contains(&response.status) {
            facts.lock().map_err(|_| network())?.redirects += 1;
            let location = response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(invalid)?;
            let next = parsed.join(location).map_err(|_| invalid())?;
            facts.lock().map_err(|_| network())?.redirect_chain.push(
                super::scope_connector::RedirectFact {
                    from_url: url.clone(),
                    to_url: next.to_string(),
                    status: response.status,
                    capture: response.capture,
                },
            );
            if redirect == limits.redirects {
                return Err(super::bounded());
            }
            if parsed.scheme() == "https" && next.scheme() != "https" {
                return Err(super::tls_error());
            }
            // No credential-bearing automatic cross-origin redirects. Scope is
            // rechecked by the connector before the next socket can exist.
            if next.origin() != parsed.origin()
                && headers.iter().any(|header| {
                    ["authorization", "cookie", "proxy-authorization"]
                        .iter()
                        .any(|name| header.name.eq_ignore_ascii_case(name))
                })
            {
                return Err(super::tls_error());
            }
            url = next.to_string();
            continue;
        }
        return http1::response(response);
    }
    Err(super::bounded())
}
fn error_response() -> Response {
    Response::builder()
        .status(502)
        .body(Body::from("Transport failed explicitly"))
        .expect("static error response")
}
fn record(facts: &SharedFacts, error: ProofError) {
    if let Ok(mut facts) = facts.lock()
        && facts.errors.len() < 32
    {
        facts.errors.push(error);
    }
}
