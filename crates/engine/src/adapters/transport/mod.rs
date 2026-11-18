//! Bounded Rama transport. Keys, resolvers and effect permits are host-only inputs.
use std::sync::Arc;
use std::time::Duration;

use crate::application::profile::LoadedProfile;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};

/// Reviewed compiled dependency pin (`rama = "=0.4.0"` in workspace Cargo.toml).
/// Rama 0.4 exposes no maintained runtime version query; update with that pin.
pub const RAMA_VERSION: &str = "0.4.0";

/// HTTP/2 stream identifiers belong to one connection leg, not both proxy legs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamLink {
    pub downstream_stream_id: u32,
    pub upstream_stream_id: u32,
}

pub mod capture;
pub(crate) mod fixture;
pub mod http1;
pub mod http2;
pub mod intercept;
pub(crate) mod io;
pub(crate) mod relay;
pub mod scope_connector;
pub mod tunnel;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Http1Forward,
    HttpsConnectTunnel,
    HttpsHttp1Intercept,
    HttpsHttp2Intercept,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1Forward => "http1_forward",
            Self::HttpsConnectTunnel => "https_connect_tunnel",
            Self::HttpsHttp1Intercept => "https_http1_intercept",
            Self::HttpsHttp2Intercept => "https_http2_intercept",
        }
    }
    pub(crate) fn alpn(self) -> &'static [u8] {
        if self == Self::HttpsHttp2Intercept {
            b"h2"
        } else {
            b"http/1.1"
        }
    }
    pub(crate) fn tls(self) -> bool {
        self != Self::Http1Forward
    }
}

#[derive(Clone)]
pub struct Limits {
    pub body_bytes: usize,
    pub chunk_bytes: usize,
    pub deadline: Duration,
    pub redirects: usize,
    pub requests: usize,
}
impl Limits {
    pub fn from_profile(profile: &LoadedProfile) -> ProofResult<Self> {
        let p = &profile.config().transport;
        Ok(Self {
            body_bytes: usize::try_from(p.body_limit_bytes.get()).map_err(|_| invalid())?,
            chunk_bytes: usize::try_from(p.chunk_limit_bytes.get()).map_err(|_| invalid())?,
            deadline: Duration::from_millis(p.request_timeout_ms.get()),
            redirects: usize::try_from(p.redirect_limit.get()).map_err(|_| invalid())?,
            requests: usize::try_from(p.requests_per_case.get()).map_err(|_| invalid())?,
        })
    }
}

pub(crate) struct RequestData {
    pub url: String,
    pub method: String,
    pub headers: Vec<crate::domain::evidence::Header>,
    pub body: Vec<u8>,
}

/// Never deserialized: selecting roots, ingress credentials or a resolver is a
/// trusted-controller decision, not authority carried in a tool input.
#[derive(Clone)]
pub struct TransportConfig {
    pub mode: Mode,
    pub resolver: scope_connector::Resolver,
    pub upstream_roots: Arc<rustls::RootCertStore>,
    pub client_roots: Arc<rustls::RootCertStore>,
    pub ingress_tls: Option<Arc<rustls::ServerConfig>>,
    pub tls_server_name: Option<String>,
    pub connect_authority: Option<String>,
}

pub(crate) fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Transport input violates the bounded HTTP contract",
    )
}
pub(crate) fn protocol() -> ProofError {
    ProofError::new(
        ErrorCode::UnsupportedProtocol,
        "Transport protocol, framing or encoding is not supported",
    )
}
pub(crate) fn network() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Transport connection or HTTP exchange failed",
    )
}
pub(crate) fn tls_error() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "TLS verification or authority binding failed",
    )
}
pub(crate) fn bounded() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Transport body or exchange limit exceeded",
    )
}
pub(crate) fn timeout() -> ProofError {
    ProofError::new(
        ErrorCode::Timeout,
        "Transport exchange exceeded its deadline",
    )
}

// Client and independent receiver tasks share this process-local monotonic epoch;
// these timestamps are not ControlService barrier timestamps.
pub(crate) fn clock_us() -> u64 {
    static EPOCH: std::sync::LazyLock<std::time::Instant> =
        std::sync::LazyLock::new(std::time::Instant::now);
    EPOCH.elapsed().as_micros() as u64
}
