//! The simulated decision maker is a real fixed Linux workload in the approved guest.
//! No host-process simulation or implicit preparation exists here.
use crate::{
    adapters::guest::{preflight::PreparedGuest, transport::GuestInvocation},
    application::{admission::TrustedBinding, profile::LoadedProfile},
    domain::{
        runtime::{Lease, LeaseState, RuntimeBinding, RuntimeCapability, RuntimeState},
        values::{AuditTime, CatalogId, ContractVersion, Digest, EntityId, WireInt},
    },
    ports::runtime::{Runtime, RuntimeContainment},
    protocol::{
        codec::{ChannelRole, Direction, decode_frame},
        error::{ErrorCode, ProofError, ProofResult},
        messages::{CompletionState, Message, SupervisorLaunch},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub struct SimulatedRuntime {
    guest: GuestInvocation,
    authority: Arc<TrustedBinding>,
    binding: RuntimeBinding,
    lease: Lease,
    frame_limit: usize,
    output_limit: usize,
    pending: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    supervisor: Vec<Value>,
    start_id: Option<EntityId>,
    request_id: Option<EntityId>,
    call_id: Option<EntityId>,
    reply_id: Option<EntityId>,
    cancel_id: Option<EntityId>,
    close_id: Option<EntityId>,
    seen: BTreeMap<EntityId, Digest>,
    sequence: WireInt,
    terminated: bool,
    pub transport_pid: u32,
}
impl SimulatedRuntime {
    pub fn launch(
        guest: &Arc<PreparedGuest>,
        profile: &LoadedProfile,
        authority: &Arc<TrustedBinding>,
        launch: SupervisorLaunch,
    ) -> ProofResult<Self> {
        if launch.binding_id != authority.binding_id()
            || launch.control_revision != authority.control_revision()
            || !matches!(
                launch.approved_fixture_id.as_str(),
                "runtime" | "runtime_blocked"
            )
        {
            return Err(invalid(
                "Runtime launch is not the actual reviewed host binding",
            ));
        }
        let runtime_digest = Digest::parse(
            guest.provenance()["binary_digests"]["adversary"]
                .as_str()
                .ok_or_else(|| invalid("Prepared native runtime digest missing"))?,
        )?;
        let binding = RuntimeBinding {
            binding_id: authority.binding_id(),
            run_id: launch.run_id,
            adapter_id: CatalogId::parse("offline-simulated-runtime")?,
            adapter_version: ContractVersion::V0_1_0,
            runtime_digest,
            capabilities: RuntimeCapability::REQUIRED.to_vec(),
            investigation_id: authority.investigation_id(),
            session_id: authority.session_id(),
            state: RuntimeState::Created,
        };
        let lease = Lease {
            lease_id: launch.lease_id,
            invocation_id: launch.invocation_id,
            owner_binding_id: authority.binding_id(),
            control_revision: launch.control_revision,
            expires_at: AuditTime::now().checked_add(Duration::from_millis(
                profile.config().external_runner.orphan_lease_ms.get(),
            ))?,
            state: LeaseState::Active,
        };
        let invocation = guest.launch(launch, profile)?;
        let transport_pid = invocation.transport_pid;
        Ok(Self {
            guest: invocation,
            authority: Arc::clone(authority),
            binding,
            lease,
            frame_limit: profile.config().protocol.message_limit_bytes.get() as usize,
            output_limit: profile
                .config()
                .protocol
                .invocation_output_limit_bytes
                .get() as usize,
            pending: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            supervisor: Vec::new(),
            start_id: None,
            request_id: None,
            call_id: None,
            reply_id: None,
            cancel_id: None,
            close_id: None,
            seen: BTreeMap::new(),
            sequence: WireInt::ZERO,
            terminated: false,
            transport_pid,
        })
    }
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
    pub fn supervisor_frames(&self) -> &[Value] {
        &self.supervisor
    }
    pub fn terminated(&self) -> bool {
        self.terminated
    }
    pub fn supervisor_started(&self) -> bool {
        self.supervisor
            .iter()
            .any(|frame| frame["kind"] == "started")
    }
    pub fn termination_record(&self) -> ProofResult<Value> {
        self.guest.read_termination_record()
    }
    pub fn refresh_old_lease(&mut self, revision: WireInt) -> ProofResult<()> {
        self.guest.refresh(self.lease.lease_id, revision)
    }

    fn accept_runtime(&mut self, bytes: &[u8]) -> ProofResult<()> {
        let envelope = decode_frame(
            bytes,
            self.frame_limit,
            ChannelRole::Runtime,
            Direction::PeerToHost,
        )?;
        let digest = Digest::of(bytes);
        if let Some(previous) = self.seen.get(&envelope.message_id) {
            return if *previous == digest {
                Ok(())
            } else {
                Err(invalid("Runtime message ID changed immutable content"))
            };
        }
        if self.seen.len() >= 256 {
            return Err(invalid("Runtime message retention exhausted"));
        }
        let correlation = envelope.correlation_id;
        match envelope.message() {
            Message::RuntimeStarted(value) => {
                if self.binding.state != RuntimeState::Created
                    || correlation != self.start_id
                    || self.start_id.is_none()
                {
                    return Err(invalid(
                        "Runtime started is not correlated to its current start",
                    ));
                }
                RuntimeCapability::validate_set(&value.capabilities)?;
                self.binding.capabilities = value.capabilities.clone();
                self.binding.transition(RuntimeState::Running)?;
            }
            Message::ToolRequest(request) => {
                if self.binding.state != RuntimeState::Running
                    || correlation != self.start_id
                    || self.request_id.is_some()
                    || request.source_control_revision != self.lease.control_revision
                {
                    return Err(invalid(
                        "Runtime tool request has stale origin, lifecycle or correlation",
                    ));
                }
                self.request_id = Some(envelope.message_id);
                self.call_id = Some(request.call_id);
            }
            Message::RuntimeEvent(event) => {
                let expected = self.reply_id.or(self.start_id);
                if !matches!(
                    self.binding.state,
                    RuntimeState::Running | RuntimeState::Cancelling
                ) || correlation != expected
                    || event.source_control_revision != self.lease.control_revision
                    || event.sequence != self.sequence.checked_add(WireInt::new(1)?)?
                {
                    return Err(invalid(
                        "Runtime event has wrong sequence, origin or causality",
                    ));
                }
                self.sequence = event.sequence;
            }
            Message::RuntimeResult(result) => {
                let expected = if result.state == CompletionState::Cancelled {
                    self.cancel_id
                } else {
                    self.reply_id
                };
                if !matches!(
                    self.binding.state,
                    RuntimeState::Running | RuntimeState::Cancelling
                ) || correlation != expected
                    || correlation.is_none()
                    || result.source_control_revision != self.lease.control_revision
                {
                    return Err(invalid(
                        "Runtime result has wrong lifecycle, origin or causality",
                    ));
                }
                let next = match result.state {
                    CompletionState::Completed => RuntimeState::Completed,
                    CompletionState::Cancelled => RuntimeState::Cancelled,
                    _ => RuntimeState::Failed,
                };
                if next == RuntimeState::Cancelled && self.binding.state != RuntimeState::Cancelling
                {
                    self.binding.transition(RuntimeState::Cancelling)?;
                }
                // A completed pre-barrier effect remains attributed evidence; it is
                // not an observation that the cancelling worker resumed.
                if !(self.binding.state == RuntimeState::Cancelling
                    && next == RuntimeState::Completed)
                {
                    self.binding.transition(next)?;
                }
            }
            Message::RuntimeClosed(_) => {
                if correlation != self.close_id || correlation.is_none() {
                    return Err(invalid("Runtime closed has no current close correlation"));
                }
                if self.binding.state == RuntimeState::Running {
                    self.binding.transition(RuntimeState::Cancelling)?;
                }
                if self.binding.state == RuntimeState::Cancelling {
                    self.binding.transition(RuntimeState::Cancelled)?;
                }
                self.binding.transition(RuntimeState::Closed)?;
            }
            _ => {
                return Err(invalid(
                    "Supervisor or host payload on authenticated runtime output",
                ));
            }
        }
        self.seen.insert(envelope.message_id, digest);
        Ok(())
    }
}
impl Runtime for SimulatedRuntime {
    fn binding(&self) -> &RuntimeBinding {
        &self.binding
    }
    fn lease(&self) -> &Lease {
        &self.lease
    }
    fn send(&mut self, frame: &[u8]) -> ProofResult<()> {
        if self.lease.state != LeaseState::Active {
            return Err(invalid("Terminal runtime lease cannot send work"));
        }
        let envelope = decode_frame(
            frame,
            self.frame_limit,
            ChannelRole::Runtime,
            Direction::HostToPeer,
        )?;
        if !matches!(envelope.message(), Message::ToolResult(_))
            && envelope.correlation_id.is_some()
        {
            return Err(invalid(
                "Host lifecycle request cannot borrow another call correlation",
            ));
        }
        match envelope.message() {
            Message::RuntimeStart(start) => {
                if self.start_id.is_some()
                    || start.binding_id != self.authority.binding_id()
                    || start.context_refs != [self.authority.investigation_id()]
                    || start.tool_ids != self.authority.allowed_tools()
                {
                    return Err(invalid(
                        "Runtime start differs from its actual opaque host binding and scoped context",
                    ));
                }
                self.start_id = Some(envelope.message_id);
            }
            Message::ToolResult(result) => {
                if self.binding.state != RuntimeState::Running
                    || envelope.correlation_id != self.request_id
                    || self.request_id.is_none()
                    || self.reply_id.is_some()
                    || Some(result.call_id) != self.call_id
                {
                    return Err(invalid(
                        "Tool result is not the pending binding-local request/call",
                    ));
                }
                self.reply_id = Some(envelope.message_id);
            }
            Message::RuntimeCancel(cancel) => {
                if cancel.control_revision <= self.lease.control_revision {
                    return Err(invalid(
                        "Runtime cancellation requires a newer host barrier revision",
                    ));
                }
                self.binding.transition(RuntimeState::Cancelling)?;
                self.cancel_id = Some(envelope.message_id);
            }
            Message::RuntimeClose(_) => {
                if self.close_id.is_some()
                    || !matches!(
                        self.binding.state,
                        RuntimeState::Running
                            | RuntimeState::Cancelling
                            | RuntimeState::Cancelled
                            | RuntimeState::Completed
                            | RuntimeState::Failed
                    )
                {
                    return Err(invalid("Runtime close is not permitted in this lifecycle"));
                }
                self.close_id = Some(envelope.message_id);
            }
            _ => return Err(invalid("Unreviewed runtime host operation")),
        }
        self.guest.send_runtime(frame)
    }
    fn poll(&mut self) -> ProofResult<Option<Vec<u8>>> {
        if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let frame: Vec<u8> = self.pending.drain(..=end).collect();
            self.accept_runtime(&frame)?;
            return Ok(Some(frame));
        }
        if let Some(frame) = self.guest.poll()? {
            if self.supervisor.len() >= 1024 {
                return Err(invalid("Supervisor lifecycle retention exhausted"));
            }
            if frame["kind"] == "output" {
                let bytes = STANDARD
                    .decode(
                        frame["payload"]["bytes_base64"]
                            .as_str()
                            .ok_or_else(|| invalid("Supervisor output missing bytes"))?,
                    )
                    .map_err(|_| invalid("Invalid supervisor output bytes"))?;
                if bytes.len()
                    > self
                        .output_limit
                        .saturating_sub(self.stdout.len() + self.stderr.len())
                {
                    return Err(invalid("Runtime output exceeds cumulative cap"));
                }
                if frame["payload"]["stream"] == "stdout" {
                    self.stdout.extend_from_slice(&bytes);
                    self.pending.extend_from_slice(&bytes);
                } else {
                    self.stderr.extend_from_slice(&bytes);
                }
            }
            if frame["kind"] == "terminated" {
                self.terminated = true;
            }
            self.supervisor.push(frame);
        }
        if self.pending.len() > self.frame_limit {
            return Err(invalid("Runtime output has an oversized partial frame"));
        }
        Ok(None)
    }
    fn refresh(&mut self, revision: WireInt) -> ProofResult<()> {
        if self.lease.state != LeaseState::Active || revision != self.lease.control_revision {
            return Err(invalid("Revoked or old runtime lease cannot refresh"));
        }
        self.guest.refresh(self.lease.lease_id, revision)
    }
    fn contain(&mut self, revision: WireInt) -> ProofResult<RuntimeContainment> {
        self.lease.state = LeaseState::Revoked;
        let started = std::time::Instant::now();
        let mut control_error = None;
        if !self.terminated {
            control_error = self
                .guest
                .cancel(
                    self.lease.lease_id,
                    revision,
                    "containment after durable host barrier",
                )
                .err();
            while !self.terminated
                && control_error.is_none()
                && started.elapsed() < Duration::from_millis(1500)
            {
                if let Err(error) = self.poll() {
                    control_error = Some(error);
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let result = self.guest.terminate(self.lease.lease_id, revision)?;
        if !result.empty_cgroup && !result.vm_force_stopped {
            return Err(invalid(
                "Runtime containment has no observed empty cgroup or owned VM stop",
            ));
        }
        self.terminated = true;
        if matches!(
            self.binding.state,
            RuntimeState::Created
                | RuntimeState::Running
                | RuntimeState::WaitingApproval
                | RuntimeState::Paused
        ) {
            self.binding.transition(RuntimeState::Cancelling)?;
        }
        if self.binding.state == RuntimeState::Cancelling {
            self.binding.transition(RuntimeState::Cancelled)?;
        }
        if self.binding.state != RuntimeState::Closed {
            self.binding.transition(RuntimeState::Closed)?;
        }
        Ok(RuntimeContainment {
            invocation_id: result.invocation_id,
            empty_cgroup: result.empty_cgroup,
            vm_force_stopped: result.vm_force_stopped,
            observed_vm_status: result.observed_vm_status,
            elapsed_us: result.elapsed_us,
            control_error,
        })
    }
}
fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}
