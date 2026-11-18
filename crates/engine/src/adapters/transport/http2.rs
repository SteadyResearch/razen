use super::capture::{self, CaptureFact};
use super::http1::Received;
use super::io::RamaIo;
use super::scope_connector::{self, Authority};
use super::{Limits, TransportConfig, bounded, invalid, network, protocol};
use crate::protocol::error::{ProofError, ProofResult};
use rama::bytes::Bytes;
use rama::http::core::h2::{self, Reason, RecvStream, SendStream};
use rama::http::{Request, Response, Version};
use std::future::poll_fn;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

pub(crate) fn classify_error(error: h2::Error) -> ProofError {
    // Remote connection closure/GOAWAY does not prove that a POST was rejected.
    // Only a measured stream reset or library-detected protocol error is known.
    if error.is_io() || (error.is_go_away() && !error.is_library()) || error.reason().is_none() {
        return network();
    }
    protocol()
}

pub(crate) async fn receive(
    mut stream: RecvStream,
    limits: &Limits,
) -> Result<(Vec<u8>, CaptureFact), capture::CaptureFailure> {
    let mut bytes = Vec::new();
    while let Some(data) = stream.data().await {
        let data = match data {
            Ok(data) => data,
            Err(error) => {
                return Err(capture::failure(
                    classify_error(error),
                    bytes,
                    limits.chunk_bytes,
                ));
            }
        };
        for chunk in data.chunks(limits.chunk_bytes) {
            let available = limits.body_bytes.saturating_sub(bytes.len());
            if chunk.len() > available {
                if let Err(error) =
                    capture::append(&mut bytes, &chunk[..available], limits.body_bytes)
                {
                    return Err(capture::failure(error, bytes, limits.chunk_bytes));
                }
                return Err(capture::failure(bounded(), bytes, limits.chunk_bytes));
            }
            if let Err(error) = capture::append(&mut bytes, chunk, limits.body_bytes) {
                return Err(capture::failure(error, bytes, limits.chunk_bytes));
            }
        }
        if let Err(error) = stream.flow_control().release_capacity(data.len()) {
            return Err(capture::failure(
                classify_error(error),
                bytes,
                limits.chunk_bytes,
            ));
        }
    }
    match stream.trailers().await {
        Ok(None) => {}
        Ok(Some(_)) => return Err(capture::failure(protocol(), bytes, limits.chunk_bytes)),
        Err(error) => {
            return Err(capture::failure(
                classify_error(error),
                bytes,
                limits.chunk_bytes,
            ));
        }
    }
    let fact = capture::fact(&bytes, limits.chunk_bytes, false);
    Ok((bytes, fact))
}

pub(crate) async fn send_bytes(
    stream: &mut SendStream<Bytes>,
    bytes: &[u8],
    limits: &Limits,
) -> ProofResult<()> {
    if bytes.len() > limits.body_bytes {
        return Err(bounded());
    }
    if bytes.is_empty() {
        return stream.send_data(Bytes::new(), true).map_err(classify_error);
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let requested = (bytes.len() - offset).min(limits.chunk_bytes);
        stream.reserve_capacity(requested);
        let available = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(network)?
            .map_err(classify_error)?;
        let length = available.min(requested);
        if length == 0 {
            continue;
        }
        let end = offset + length;
        stream
            .send_data(
                Bytes::copy_from_slice(&bytes[offset..end]),
                end == bytes.len(),
            )
            .map_err(classify_error)?;
        offset = end;
    }
    Ok(())
}

pub(crate) struct ClientExchange {
    pub stream_id: u32,
    pub received: ProofResult<Received>,
    pub started_us: u64,
    pub finished_us: u64,
}

pub(crate) async fn client<IO>(
    io: IO,
    request: super::RequestData,
    count: usize,
    reset_first: bool,
    limits: &Limits,
) -> ProofResult<Vec<ClientExchange>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let super::RequestData {
        url,
        method,
        headers,
        body,
    } = request;
    let (mut sender, connection) = h2::client::Builder::new()
        .with_max_header_list_size(65_536)
        .with_max_concurrent_streams(2)
        .handshake::<_, Bytes>(RamaIo::new(io))
        .await
        .map_err(classify_error)?;
    let connection = super::io::OwnedTask::new(tokio::spawn(connection));
    let mut in_flight = Vec::new();
    for index in 0..if reset_first { 2 } else { count } {
        sender = sender.ready().await.map_err(classify_error)?;
        let request = super::http1::request(&url, &method, &headers, Vec::new(), Version::HTTP_2)?
            .map(|_| ());
        let (response, mut stream) = sender
            .send_request(request, false)
            .map_err(classify_error)?;
        let id = u32::from(stream.stream_id());
        let started = super::clock_us();
        send_bytes(&mut stream, &body, limits).await?;
        in_flight.push((index, id, response, stream, started));
        // A pair is deliberately outstanding on the same connection. More than
        // two requests are sent in bounded pairs by the caller.
    }
    let mut tasks = JoinSet::new();
    for (index, id, response, mut stream, started) in in_flight {
        let limits = limits.clone();
        tasks.spawn(async move {
            if reset_first && index == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                stream.send_reset(Reason::CANCEL);
                let observed = response.await;
                let received = match observed {
                    Err(error) => Err(classify_error(error)),
                    Ok(_) => Err(invalid()),
                };
                return (
                    index,
                    ClientExchange {
                        stream_id: id,
                        received,
                        started_us: started,
                        finished_us: super::clock_us(),
                    },
                );
            }
            let result = async {
                let response = response.await.map_err(classify_error)?;
                capture::encoding(response.headers())?;
                let status = response.status().as_u16();
                let version = format!("{:?}", response.version());
                let headers = response.headers().clone();
                let (bytes, capture, error) = match receive(response.into_body(), &limits).await {
                    Ok((bytes, capture)) => (bytes, capture, None),
                    Err(failure) => {
                        let (captured, error) = failure.into_parts();
                        (captured.bytes, captured.fact, Some(error))
                    }
                };
                Ok(Received {
                    status,
                    headers,
                    bytes,
                    capture,
                    version,
                    upstream_alpn: None,
                    certificate: None,
                    error,
                })
            }
            .await;
            (
                index,
                ClientExchange {
                    stream_id: id,
                    received: result,
                    started_us: started,
                    finished_us: super::clock_us(),
                },
            )
        });
    }
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.map_err(|_| network())?);
    }
    results.sort_by_key(|(index, _)| *index);
    if reset_first {
        sender = sender.ready().await.map_err(classify_error)?;
        let request = super::http1::request(&url, &method, &headers, Vec::new(), Version::HTTP_2)?
            .map(|_| ());
        let (response, mut stream) = sender
            .send_request(request, false)
            .map_err(classify_error)?;
        let id = u32::from(stream.stream_id());
        let started = super::clock_us();
        send_bytes(&mut stream, &body, limits).await?;
        let received = async {
            let response = response.await.map_err(classify_error)?;
            capture::encoding(response.headers())?;
            let status = response.status().as_u16();
            let version = format!("{:?}", response.version());
            let headers = response.headers().clone();
            let (bytes, capture, error) = match receive(response.into_body(), limits).await {
                Ok((bytes, capture)) => (bytes, capture, None),
                Err(failure) => {
                    let (captured, error) = failure.into_parts();
                    (captured.bytes, captured.fact, Some(error))
                }
            };
            Ok(Received {
                status,
                headers,
                bytes,
                capture,
                version,
                upstream_alpn: None,
                certificate: None,
                error,
            })
        }
        .await;
        results.push((
            2,
            ClientExchange {
                stream_id: id,
                received,
                started_us: started,
                finished_us: super::clock_us(),
            },
        ));
    }
    drop(sender);
    connection.abort();
    let _ = connection.await;
    Ok(results.into_iter().map(|(_, result)| result).collect())
}

pub(crate) async fn relay<IO>(
    io: IO,
    authority: Arc<Authority>,
    config: TransportConfig,
    url: String,
    limits: Limits,
    facts: super::relay::SharedFacts,
) -> ProofResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let destination = scope_connector::normalize(&url)?;
    let expected = format!("{}:{}", destination.host(), destination.port());
    let (upstream, _) =
        scope_connector::connect(&authority, &config, &url, Some(&expected)).await?;
    let (upstream, alpn, certificate) = super::intercept::client_tls(
        upstream,
        Arc::clone(&config.upstream_roots),
        destination.host(),
        b"h2",
    )
    .await?;
    facts.lock().map_err(|_| network())?.upstream_tls = Some((alpn, certificate));
    let (sender, driver) = h2::client::Builder::new()
        .with_max_header_list_size(65_536)
        .with_max_concurrent_streams(2)
        .handshake::<_, Bytes>(RamaIo::new(upstream))
        .await
        .map_err(classify_error)?;
    let driver = super::io::OwnedTask::new(tokio::spawn(driver));
    let mut server = h2::server::Builder::new()
        .with_max_concurrent_streams(2)
        .with_max_header_list_size(65_536)
        .handshake::<_, Bytes>(RamaIo::new(io))
        .await
        .map_err(classify_error)?;
    let mut streams = JoinSet::new();
    while let Some(request) = server.accept().await {
        let (request, mut respond) = request.map_err(classify_error)?;
        let mut upstream = sender.clone();
        let authority = Arc::clone(&authority);
        let config = config.clone();
        let limits = limits.clone();
        let facts = Arc::clone(&facts);
        let destination = scope_connector::normalize(&url)?;
        let expected = expected.clone();
        streams.spawn(async move {
            let stream_id = u32::from(respond.stream_id());
            let result = async {
                authority.recheck()?;
                let actual = request
                    .uri()
                    .authority()
                    .map(|authority| authority.to_string())
                    .unwrap_or_default();
                let actual_destination = scope_connector::normalize(&request.uri().as_str())?;
                if actual_destination != destination
                    || request
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|host| host != expected)
                {
                    return Err(super::tls_error());
                }
                let addresses = config.resolver.resolve(&destination).await?;
                authority.authorize(
                    &actual_destination,
                    &addresses,
                    *addresses.first().ok_or_else(network)?,
                    config.connect_authority.as_deref(),
                    config.tls_server_name.as_deref(),
                    Some(&actual),
                )?;
                if actual != expected {
                    return Err(super::tls_error());
                }
                capture::encoding(request.headers())?;
                let (parts, body) = request.into_parts();
                let (body, _) = receive(body, &limits)
                    .await
                    .map_err(|failure| failure.error)?;
                let request = Request::from_parts(parts, ());
                upstream = upstream.ready().await.map_err(classify_error)?;
                authority.recheck()?;
                authority.note_request(body.len() as u64)?;
                let (response, mut sending) = {
                    let mut observed = facts.lock().map_err(|_| network())?;
                    if observed.stream_links.len() >= 3 {
                        return Err(super::bounded());
                    }
                    let (response, sending) = upstream
                        .send_request(request, false)
                        .map_err(classify_error)?;
                    observed.stream_links.push(super::StreamLink {
                        downstream_stream_id: stream_id,
                        upstream_stream_id: u32::from(sending.stream_id()),
                    });
                    (response, sending)
                };
                send_bytes(&mut sending, &body, &limits).await?;
                let response = tokio::select! {
                    response = response => response.map_err(classify_error)?,
                    reset = poll_fn(|cx| respond.poll_reset(cx)) => {
                        let _ = reset.map_err(classify_error)?;
                        sending.send_reset(Reason::CANCEL);
                        return Err(protocol());
                    }
                };
                capture::encoding(response.headers())?;
                let (parts, body) = response.into_parts();
                let body = match receive(body, &limits).await {
                    Ok((body, _)) => body,
                    Err(failure) => {
                        let (captured, error) = failure.into_parts();
                        authority.note_response(captured.bytes.len() as u64)?;
                        facts
                            .lock()
                            .map_err(|_| network())?
                            .partials
                            .push(Received {
                                status: parts.status.as_u16(),
                                headers: parts.headers.clone(),
                                bytes: captured.bytes,
                                capture: captured.fact,
                                version: format!("{:?}", parts.version),
                                upstream_alpn: None,
                                certificate: None,
                                error: Some(error.clone()),
                            });
                        return Err(error);
                    }
                };
                authority.note_response(body.len() as u64)?;
                let mut stream = respond
                    .send_response(Response::from_parts(parts, ()), false)
                    .map_err(classify_error)?;
                send_bytes(&mut stream, &body, &limits).await?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                if let Ok(mut facts) = facts.lock() {
                    facts.stream_errors.push((stream_id, error));
                }
                respond.send_reset(Reason::CANCEL);
            }
        });
        while streams.try_join_next().is_some() {}
    }
    streams.shutdown().await;
    driver.abort();
    let _ = driver.await;
    Ok(())
}
