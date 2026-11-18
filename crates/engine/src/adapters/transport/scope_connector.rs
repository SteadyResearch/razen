use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use super::{TransportConfig, invalid, network};
use crate::application::admission::{EffectPermit, HostAdmission, TrustedBinding};
use crate::domain::authority::{Destination, DestinationCheck, normalized_ip};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionFact {
    pub host: String,
    pub addresses: Vec<IpAddr>,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionFact {
    pub url: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub connected_peer: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_authority: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectFact {
    pub from_url: String,
    pub to_url: String,
    pub status: u16,
    pub capture: super::capture::CaptureFact,
}
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoUsage {
    pub attempted_request_body_bytes: u64,
    pub captured_response_body_bytes: u64,
}

/// A closed, explicit fixture DNS zone; it is never installed globally or used as
/// a fallback for unresolved production names. Each lookup reads the current zone.
#[derive(Default)]
pub struct FixtureZone {
    records: Mutex<BTreeMap<String, Vec<IpAddr>>>,
    lookups: Mutex<Vec<ResolutionFact>>,
}
impl FixtureZone {
    pub fn publish(&self, host: &str, addresses: Vec<IpAddr>) -> ProofResult<()> {
        if !host.ends_with(".razen.invalid") || addresses.is_empty() || addresses.len() > 16 {
            return Err(invalid());
        }
        self.records
            .lock()
            .map_err(|_| network())?
            .insert(host.to_owned(), addresses);
        Ok(())
    }
    pub fn lookups(&self) -> ProofResult<Vec<ResolutionFact>> {
        Ok(self.lookups.lock().map_err(|_| network())?.clone())
    }
}
#[derive(Clone)]
pub enum Resolver {
    System,
    Fixture(Arc<FixtureZone>),
}
impl Resolver {
    pub async fn resolve(&self, destination: &Destination) -> ProofResult<Vec<IpAddr>> {
        if let Ok(address) = destination.host().parse::<IpAddr>() {
            return Ok(vec![address]);
        }
        match self {
            Self::System => {
                let mut addresses = Vec::new();
                for answer in tokio::net::lookup_host((destination.host(), destination.port()))
                    .await
                    .map_err(|_| network())?
                {
                    if !addresses.contains(&answer.ip()) {
                        addresses.push(answer.ip());
                    }
                    if addresses.len() > 16 {
                        return Err(invalid());
                    }
                }
                if addresses.is_empty() {
                    return Err(network());
                }
                Ok(addresses)
            }
            Self::Fixture(zone) => {
                let addresses = zone
                    .records
                    .lock()
                    .map_err(|_| network())?
                    .get(destination.host())
                    .cloned()
                    .ok_or_else(network)?;
                let mut lookups = zone.lookups.lock().map_err(|_| network())?;
                if lookups.len() >= 4096 {
                    return Err(super::bounded());
                }
                let sequence = lookups.len() as u64 + 1;
                lookups.push(ResolutionFact {
                    host: destination.host().to_owned(),
                    addresses: addresses.clone(),
                    sequence,
                });
                Ok(addresses)
            }
        }
    }
}

pub(crate) struct Authority {
    pub admission: Arc<HostAdmission>,
    pub binding: Arc<TrustedBinding>,
    permit: Mutex<Option<EffectPermit>>,
    connections: Mutex<Vec<ConnectionFact>>,
    io: Mutex<IoUsage>,
}
impl Authority {
    pub fn new(
        admission: Arc<HostAdmission>,
        binding: Arc<TrustedBinding>,
        permit: EffectPermit,
    ) -> Self {
        Self {
            admission,
            binding,
            permit: Mutex::new(Some(permit)),
            connections: Mutex::new(Vec::new()),
            io: Mutex::new(IoUsage::default()),
        }
    }
    pub fn take_permit(&self) -> ProofResult<EffectPermit> {
        self.permit
            .lock()
            .map_err(|_| network())?
            .take()
            .ok_or_else(network)
    }
    pub fn connection_facts(&self) -> ProofResult<Vec<ConnectionFact>> {
        Ok(self.connections.lock().map_err(|_| network())?.clone())
    }
    pub fn io_usage(&self) -> ProofResult<IoUsage> {
        Ok(*self.io.lock().map_err(|_| network())?)
    }
    pub fn note_request(&self, bytes: u64) -> ProofResult<()> {
        let mut io = self.io.lock().map_err(|_| network())?;
        io.attempted_request_body_bytes = io
            .attempted_request_body_bytes
            .checked_add(bytes)
            .ok_or_else(super::bounded)?;
        Ok(())
    }
    pub fn note_response(&self, bytes: u64) -> ProofResult<()> {
        let mut io = self.io.lock().map_err(|_| network())?;
        io.captured_response_body_bytes = io
            .captured_response_body_bytes
            .checked_add(bytes)
            .ok_or_else(super::bounded)?;
        Ok(())
    }
    pub fn recheck(&self) -> ProofResult<()> {
        let guard = self.permit.lock().map_err(|_| network())?;
        self.admission
            .recheck_effect(&self.binding, guard.as_ref().ok_or_else(network)?)
    }
    pub fn authorize(
        &self,
        destination: &Destination,
        addresses: &[IpAddr],
        chosen: IpAddr,
        connect_authority: Option<&str>,
        server_name: Option<&str>,
        request_authority: Option<&str>,
    ) -> ProofResult<()> {
        let guard = self.permit.lock().map_err(|_| network())?;
        self.admission.authorize_destination(
            &self.binding,
            guard.as_ref().ok_or_else(network)?,
            &DestinationCheck {
                destination,
                resolved_addresses: addresses,
                chosen_address: chosen,
                connect_authority,
                server_name,
                request_authority,
            },
        )
    }
}

pub fn normalize(value: &str) -> ProofResult<Destination> {
    let destination = Destination::parse(value)?;
    let authority = value
        .split_once("://")
        .ok_or_else(invalid)?
        .1
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(invalid)?;
    // URL parsers accept historical numeric IPv4 spellings and silently normalize
    // them. They are not admissible network authority in the host contract.
    let raw_host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .ok_or_else(invalid)?
            .0
            .trim_start_matches('[')
    } else {
        authority.split(':').next().ok_or_else(invalid)?
    };
    if let Ok(address) = raw_host.parse::<IpAddr>() {
        if normalized_ip(address).to_string() != destination.host() {
            return Err(invalid());
        }
    } else if raw_host.to_ascii_lowercase() != destination.host() {
        return Err(invalid());
    }
    if authority.ends_with(':') || raw_host.ends_with('.') || raw_host.is_empty() {
        return Err(invalid());
    }
    Ok(destination)
}

pub(crate) async fn connect(
    authority: &Authority,
    config: &TransportConfig,
    url: &str,
    request_authority: Option<&str>,
) -> ProofResult<(TcpStream, Vec<IpAddr>)> {
    let destination = normalize(url)?;
    authority.recheck()?;
    let addresses = config.resolver.resolve(&destination).await?;
    let chosen = *addresses.first().ok_or_else(network)?;
    authority.authorize(
        &destination,
        &addresses,
        chosen,
        config.connect_authority.as_deref(),
        config.tls_server_name.as_deref(),
        request_authority,
    )?;
    // No hostname is passed to connect: the checked address is pinned. Every
    // answer was authorized above, not merely the first convenient answer.
    if authority.connections.lock().map_err(|_| network())?.len() >= 32 {
        return Err(super::bounded());
    }
    let stream = TcpStream::connect(SocketAddr::new(chosen, destination.port()))
        .await
        .map_err(|_| network())?;
    let peer = stream.peer_addr().map_err(|_| network())?;
    if normalized_ip(peer.ip()) != normalized_ip(chosen) || peer.port() != destination.port() {
        return Err(ProofError::new(
            ErrorCode::OutOfScope,
            "Connected peer does not match the pinned destination",
        ));
    }
    authority.authorize(
        &destination,
        &addresses,
        peer.ip(),
        config.connect_authority.as_deref(),
        config.tls_server_name.as_deref(),
        request_authority,
    )?;
    authority
        .connections
        .lock()
        .map_err(|_| network())?
        .push(ConnectionFact {
            url: url.to_owned(),
            resolved_addresses: addresses.clone(),
            connected_peer: peer,
            connect_authority: config.connect_authority.clone(),
            declared_server_name: config.tls_server_name.clone(),
            request_authority: request_authority.map(str::to_owned),
        });
    Ok((stream, addresses))
}
