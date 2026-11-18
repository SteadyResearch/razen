use super::capture::{self, CaptureFact};
use super::io::RamaIo;
use super::scope_connector::{self, Authority};
use super::{Limits, TransportConfig, invalid, network};
use crate::domain::evidence::Header;
use crate::protocol::error::ProofResult;
use rama::http::{Body, HeaderMap, Request, Response, Version};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) struct Received {
    pub status: u16,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
    pub capture: CaptureFact,
    pub version: String,
    pub upstream_alpn: Option<String>,
    pub certificate: Option<crate::domain::values::Digest>,
    pub error: Option<crate::protocol::error::ProofError>,
}

pub(crate) fn request(
    url: &str,
    method: &str,
    headers: &[Header],
    body: impl Into<Body>,
    version: Version,
) -> ProofResult<Request> {
    let mut builder = Request::builder().method(method).uri(url).version(version);
    for header in headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }
    builder.body(body.into()).map_err(|_| invalid())
}

pub(crate) async fn send<IO>(io: IO, request: Request, limits: &Limits) -> ProofResult<Received>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = rama::http::core::client::conn::http1::Builder::new()
        .with_max_headers(256)
        .try_with_max_buf_size(65_536)
        .map_err(|_| invalid())?
        .handshake::<_, Body>(RamaIo::new(io))
        .await
        .map_err(|_| network())?;
    let connection = super::io::OwnedTask::new(tokio::spawn(connection.with_upgrades()));
    let result = async {
        let response = sender.send_request(request).await.map_err(classify_error)?;
        capture::encoding(response.headers())?;
        let status = response.status().as_u16();
        let version = format!("{:?}", response.version());
        let headers = response.headers().clone();
        let (body, error) = match capture::collect_http1(response.into_body(), limits).await {
            Ok(body) => (body, None),
            Err(failure) => {
                let (captured, error) = failure.into_parts();
                (captured, Some(error))
            }
        };
        Ok(Received {
            status,
            headers,
            bytes: body.bytes,
            capture: body.fact,
            version,
            upstream_alpn: None,
            certificate: None,
            error,
        })
    }
    .await;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    result
}

pub(crate) fn classify_error(error: rama::http::core::Error) -> crate::protocol::error::ProofError {
    // Rama's maintained predicates distinguish a measured malformed message from
    // EOF, cancellation and other IO failures. A lost response is not proof that
    // the peer rejected a request that may already have been consumed.
    if error.is_parse() {
        return super::protocol();
    }
    if error.is_timeout() {
        return super::timeout();
    }
    network()
}

pub(crate) async fn upstream(
    authority: Arc<Authority>,
    config: &TransportConfig,
    url: &str,
    request: Request,
    limits: &Limits,
) -> ProofResult<Received> {
    let destination = scope_connector::normalize(url)?;
    let expected_authority = url::Url::parse(url)
        .map_err(|_| invalid())?
        .authority()
        .to_owned();
    let (stream, _) =
        scope_connector::connect(&authority, config, url, Some(&expected_authority)).await?;
    authority.recheck()?;
    if destination.scheme() == "https" {
        let (stream, alpn, certificate) = super::intercept::client_tls(
            stream,
            Arc::clone(&config.upstream_roots),
            destination.host(),
            b"http/1.1",
        )
        .await?;
        authority.recheck()?;
        let mut received = monitored(&authority, stream, request, limits).await?;
        received.upstream_alpn = Some(alpn);
        received.certificate = Some(certificate);
        Ok(received)
    } else {
        monitored(&authority, stream, request, limits).await
    }
}

async fn monitored<IO>(
    authority: &Authority,
    io: IO,
    request: Request,
    limits: &Limits,
) -> ProofResult<Received>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    authority.recheck()?;
    let bytes = rama::http::StreamingBody::size_hint(request.body())
        .exact()
        .ok_or_else(invalid)?;
    authority.note_request(bytes)?;
    let response = send(io, request, limits).await?;
    authority.note_response(response.bytes.len() as u64)?;
    Ok(response)
}

pub(crate) fn response(received: Received) -> ProofResult<Response> {
    let mut builder = Response::builder().status(received.status);
    // The application body has already been dechunked by Rama. Preserve semantic
    // end-to-end headers and regenerate framing, never send a stale transfer code.
    for (name, value) in &received.headers {
        if ![
            "transfer-encoding",
            "connection",
            "proxy-connection",
            "keep-alive",
            "content-length",
        ]
        .contains(&name.as_str())
        {
            builder = builder.header(name, value);
        }
    }
    builder
        .header("content-length", received.bytes.len().to_string())
        .body(Body::from(received.bytes))
        .map_err(|_| invalid())
}
