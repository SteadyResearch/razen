use super::{TransportConfig, tls_error};
use crate::domain::values::Digest;
use crate::protocol::error::ProofResult;
use rama::tls::rustls::dep::tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) struct IsolatedAuthority {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pub roots: Arc<rustls::RootCertStore>,
    pub public_der: Vec<u8>,
    private_der: Mutex<Vec<Vec<u8>>>,
}
impl IsolatedAuthority {
    pub fn create() -> ProofResult<Self> {
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|_| tls_error())?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().map_err(|_| tls_error())?,
        )
        .map_err(|_| tls_error())?;
        let public_der = issuer.der().to_vec();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(issuer.der().clone()).map_err(|_| tls_error())?;
        let private_der = Mutex::new(vec![issuer.key().serialize_der()]);
        Ok(Self {
            issuer,
            roots: Arc::new(roots),
            public_der,
            private_der,
        })
    }
    pub fn server_config(&self, host: &str, alpn: &[u8]) -> ProofResult<Arc<rustls::ServerConfig>> {
        self.server_config_names(vec![host.to_owned()], alpn)
    }
    pub fn server_config_names(
        &self,
        names: Vec<String>,
        alpn: &[u8],
    ) -> ProofResult<Arc<rustls::ServerConfig>> {
        let key = rcgen::KeyPair::generate().map_err(|_| tls_error())?;
        let params = rcgen::CertificateParams::new(names).map_err(|_| tls_error())?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| tls_error())?;
        let key_der = key.serialize_der();
        let mut private = self.private_der.lock().map_err(|_| tls_error())?;
        if private.len() >= 512 {
            return Err(super::bounded());
        }
        private.push(key_der.clone());
        drop(private);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| tls_error())?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone(), self.issuer.der().clone()],
                PrivatePkcs8KeyDer::from(key_der).into(),
            )
            .map_err(|_| tls_error())?;
        config.alpn_protocols = vec![alpn.to_vec()];
        Ok(Arc::new(config))
    }
    pub fn ensure_public(&self, bytes: &[u8]) -> ProofResult<()> {
        let private = self.private_der.lock().map_err(|_| tls_error())?;
        for key in private.iter() {
            if bytes
                .windows(key.len())
                .any(|window| window == key.as_slice())
            {
                return Err(tls_error());
            }
        }
        Ok(())
    }
    pub fn protected_key_count(&self) -> ProofResult<usize> {
        Ok(self.private_der.lock().map_err(|_| tls_error())?.len())
    }
}

pub(crate) fn client_config(
    roots: Arc<rustls::RootCertStore>,
    alpn: &[u8],
) -> ProofResult<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| tls_error())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    // The default NoKeyLog remains installed. Environment key logging is never read.
    Ok(Arc::new(config))
}

pub(crate) async fn client_tls<IO>(
    io: IO,
    roots: Arc<rustls::RootCertStore>,
    name: &str,
    alpn: &[u8],
) -> ProofResult<(client::TlsStream<IO>, String, Digest)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(name.to_owned()).map_err(|_| tls_error())?;
    let stream = TlsConnector::from(client_config(roots, alpn)?)
        .connect(name, io)
        .await
        .map_err(|_| tls_error())?;
    let connection = stream.get_ref().1;
    if connection.alpn_protocol() != Some(alpn) {
        return Err(tls_error());
    }
    let certificate: &CertificateDer<'_> = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(tls_error)?;
    let digest = Digest::of(certificate.as_ref());
    let negotiated = String::from_utf8(connection.alpn_protocol().ok_or_else(tls_error)?.to_vec())
        .map_err(|_| tls_error())?;
    Ok((stream, negotiated, digest))
}

pub(crate) async fn server_tls<IO>(
    io: IO,
    config: &TransportConfig,
) -> ProofResult<(server::TlsStream<IO>, String, String)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let stream = TlsAcceptor::from(config.ingress_tls.clone().ok_or_else(tls_error)?)
        .accept(io)
        .await
        .map_err(|_| tls_error())?;
    let connection = stream.get_ref().1;
    let name = connection.server_name().ok_or_else(tls_error)?;
    let expected = super::scope_connector::normalize(&format!(
        "https://{}/",
        config.connect_authority.as_deref().ok_or_else(tls_error)?
    ))?;
    if name != expected.host() || connection.alpn_protocol() != Some(config.mode.alpn()) {
        return Err(tls_error());
    }
    let name = name.to_owned();
    let negotiated = String::from_utf8(connection.alpn_protocol().ok_or_else(tls_error)?.to_vec())
        .map_err(|_| tls_error())?;
    Ok((stream, name, negotiated))
}
