use super::{
    integrity,
    preflight::{self, DurableCapacity, HostOccupancy, OwnedTransport, PreparedGuest},
    unavailable,
};
use crate::domain::values::{EntityId, WireInt};
use crate::protocol::error::ProofResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Debug, Eq, PartialEq)]
pub enum LeaseDecision {
    Refreshed,
    Duplicate,
}
/// Host-side invariant checker. The independent guest owns the operational timer.
pub struct LeaseClock {
    lease: EntityId,
    revision: WireInt,
    deadline: Instant,
    wall: Instant,
    ttl: Duration,
    seen: BTreeSet<EntityId>,
    terminal: bool,
}
impl LeaseClock {
    pub fn new(
        lease: EntityId,
        revision: WireInt,
        now: Instant,
        ttl: Duration,
        wall: Duration,
    ) -> ProofResult<Self> {
        if ttl.is_zero() || wall.is_zero() || ttl > wall {
            return Err(integrity("Invalid lease bounds"));
        }
        Ok(Self {
            lease,
            revision,
            deadline: now + ttl,
            wall: now + wall,
            ttl,
            seen: BTreeSet::new(),
            terminal: false,
        })
    }
    pub fn expired(&mut self, now: Instant) -> bool {
        self.terminal |= now >= self.deadline || now >= self.wall;
        self.terminal
    }
    pub fn refresh(
        &mut self,
        message: EntityId,
        lease: EntityId,
        revision: WireInt,
        now: Instant,
    ) -> ProofResult<LeaseDecision> {
        if self.expired(now) || lease != self.lease || revision != self.revision {
            return Err(integrity("Expired, foreign or stale guest lease"));
        }
        if self.seen.contains(&message) {
            return Ok(LeaseDecision::Duplicate);
        }
        if self.seen.len() == 256 {
            return Err(integrity(
                "Lease refresh history exceeds bounded invocation",
            ));
        }
        self.seen.insert(message);
        self.deadline = (now + self.ttl).min(self.wall);
        Ok(LeaseDecision::Refreshed)
    }
    pub fn close(&mut self, revision: WireInt) -> ProofResult<()> {
        if revision < self.revision {
            return Err(integrity("Stale lease closure"));
        }
        self.revision = revision;
        self.terminal = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Containment {
    pub invocation_id: EntityId,
    pub empty_cgroup: bool,
    pub vm_force_stopped: bool,
    pub observed_vm_status: String,
    pub elapsed_us: u64,
}
/// Constructed only after the caller authenticates the durable owner under the stable flock.
struct StopAuthority<'a> {
    capacity: &'a DurableCapacity,
    occupancy: Option<HostOccupancy>,
}
impl StopAuthority<'_> {
    fn validate(&self, guest: &PreparedGuest) -> ProofResult<()> {
        match &self.occupancy {
            Some(expected) => {
                guest.validate_occupancy(&self.capacity.require_stop_occupancy(expected)?)?;
            }
            None => self.capacity.ensure_empty()?,
        }
        Ok(())
    }
}

/// Every invocation-scoped escalation authenticates the exact current durable owner here.
pub(crate) fn force_stop_invocation(
    guest: &PreparedGuest,
    capacity: &DurableCapacity,
    expected: &HostOccupancy,
) -> ProofResult<Containment> {
    let current = capacity.require_stop_occupancy(expected)?;
    guest.validate_occupancy(&current)?;
    let authority = StopAuthority {
        capacity,
        occupancy: Some(current),
    };
    let start = Instant::now();
    stop_owned_machine(guest, &authority)?;
    Ok(Containment {
        invocation_id: expected.invocation_id,
        empty_cgroup: false,
        vm_force_stopped: true,
        observed_vm_status: "Stopped".into(),
        elapsed_us: start.elapsed().as_micros() as u64,
    })
}

/// Orphan guards have no inherited flock. Authenticate all original launch bindings after reacquiring.
pub(crate) fn force_stop_orphan(
    guest: &PreparedGuest,
    launch: &crate::protocol::messages::SupervisorLaunch,
    occupancy_id: EntityId,
) -> ProofResult<Containment> {
    let capacity = guest.raw_capacity_lock()?;
    let current = capacity.host_record()?.ok_or_else(|| {
        integrity(
            "Orphan occupancy has already been released; no idle VM or successor may be stopped",
        )
    })?;
    if current.occupancy_id != occupancy_id
        || current.binding_id != launch.binding_id
        || current.invocation_id != launch.invocation_id
        || current.run_id != launch.run_id
        || current.attestation_id != launch.attestation_id
        || current.lease_id != launch.lease_id
        || current.profile_sha256 != launch.profile_sha256
        || current.initial_revision != launch.control_revision
    {
        return Err(integrity(
            "Orphan guard does not own current durable invocation; no successor may be stopped",
        ));
    }
    force_stop_invocation(guest, &capacity, &current)
}

impl PreparedGuest {
    /// Explicit cleanup is run-scoped, not merely VM-resource-owner-scoped.
    pub fn stop_for_run(&self, run_id: EntityId) -> ProofResult<()> {
        let capacity = self.raw_capacity_lock()?;
        let occupancy = capacity.host_record()?;
        if let Some(current) = &occupancy {
            self.validate_occupancy(current)?;
            if current.run_id != run_id {
                return Err(integrity(
                    "Selected run does not own current durable guest invocation; no foreign run is stopped",
                ));
            }
            if current.transport.is_none() {
                return Err(integrity(
                    "Partial launch has no authenticated transport; explicit stop cannot adopt unknown occupancy",
                ));
            }
        }
        let authority = StopAuthority {
            capacity: &capacity,
            occupancy,
        };
        stop_owned_machine(self, &authority)?;
        if let Some(current) = &authority.occupancy {
            if let Some(transport) = &current.transport {
                observe_owned_exit(transport)?;
            }
            capacity.clear(current)?;
        }
        Ok(())
    }
}

/// No caller can invoke the raw manager stop without a private, locked stop authority.
fn stop_owned_machine(guest: &PreparedGuest, authority: &StopAuthority<'_>) -> ProofResult<()> {
    authority.validate(guest)?;
    guest.validate_stop_identity()?;
    let manager = OwnedTransport {
        pid: guest.record.manager_identity.pid,
        birth_sha256: preflight::process_identity(guest.record.manager_identity.pid)?
            .ok_or_else(|| unavailable("Owned VM manager disappeared before stop"))?,
    };
    // Recheck at the destructive boundary; observations or a free flock alone never grant authority.
    authority.validate(guest)?;
    guest.validate_manager_identity()?;
    guest.manager(
        &["stop", "--force", guest.instance()],
        None,
        Duration::from_secs(30),
    )?;
    let state = guest.manager(
        &["list", "--json", guest.instance()],
        None,
        Duration::from_secs(5),
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&state).map_err(|_| integrity("Invalid stopped VM observation"))?;
    if value["name"] != guest.instance() || value["status"] != "Stopped" {
        return Err(integrity("Owned VM force-stop was not observed stopped"));
    }
    observe_owned_exit(&manager)
}

pub(super) fn observe_owned_exit(transport: &OwnedTransport) -> ProofResult<()> {
    let start = Instant::now();
    loop {
        if preflight::process_identity(transport.pid)? != Some(transport.birth_sha256) {
            return Ok(());
        }
        let pid = rustix::process::Pid::from_raw(transport.pid as i32)
            .ok_or_else(|| integrity("Owned transport PID is invalid"))?;
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(rustix::io::Errno::CHILD) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(unavailable("Cannot reap actual owned cleanup process")),
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err(unavailable(
                "Actual owned transport/resource exit was not observed; durable occupancy remains sealed",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
