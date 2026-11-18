//! Reusable trusted fixtures over the same authoritative registry/admission core.
//! Neither consumer approves requests or imports authority from wire metadata.
use std::sync::Arc;

use super::admission::TrustedBinding;
use super::profile::LoadedProfile;
use super::registry::Registry;
use crate::domain::runtime::RuntimeCapability;
use crate::domain::values::EntityId;
use crate::protocol::codec::{ChannelRole, Direction, decode_frame};
use crate::protocol::engine::{RuntimeBroker, RuntimeIngress, RuntimeIngressKind, encode_envelope};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use crate::protocol::messages::{BudgetSummary, Message, RuntimeStarted, ToolRequest, ToolResult};

pub struct HarnessConsumer {
    binding: Arc<TrustedBinding>,
    registry: Arc<Registry>,
}

impl HarnessConsumer {
    pub fn new(binding: Arc<TrustedBinding>, registry: Arc<Registry>) -> Self {
        Self { binding, registry }
    }
    pub fn binding(&self) -> &Arc<TrustedBinding> {
        &self.binding
    }
    pub fn call(&self, request: &ToolRequest<'_>) -> ProofResult<ToolResult> {
        self.registry.execute(&self.binding, request)
    }
}

pub struct SimulatedRuntimeConsumer {
    broker: RuntimeBroker,
    frame_limit: usize,
    start_frame: Arc<Vec<u8>>,
    last_request: Option<Arc<Vec<u8>>>,
    last_reply: Option<Arc<Vec<u8>>>,
}

impl SimulatedRuntimeConsumer {
    pub fn new(
        binding: Arc<TrustedBinding>,
        registry: Arc<Registry>,
        profile: &LoadedProfile,
        context_refs: Vec<EntityId>,
        budget_summary: BudgetSummary,
    ) -> ProofResult<Self> {
        let frame_limit = usize::try_from(profile.config().protocol.message_limit_bytes.get())
            .map_err(|_| {
                ProofError::new(
                    ErrorCode::BudgetExhausted,
                    "Runtime frame limit is not representable",
                )
            })?;
        let mut broker = RuntimeBroker::new(binding, registry, profile)?;
        let start_frame = broker.start(context_refs, budget_summary)?;
        let start = decode_frame(
            &start_frame,
            frame_limit,
            ChannelRole::Runtime,
            Direction::HostToPeer,
        )?;
        let started = RuntimeStarted {
            capabilities: vec![
                RuntimeCapability::BrokeredCalls,
                RuntimeCapability::Events,
                RuntimeCapability::Results,
                RuntimeCapability::Usage,
                RuntimeCapability::Cancellation,
                RuntimeCapability::Closure,
            ],
        };
        let wire = encode_envelope(
            EntityId::new(),
            "started",
            Some(start.message_id),
            &started,
            frame_limit,
        )?;
        if !matches!(broker.receive(&wire)?.kind, RuntimeIngressKind::Started(_)) {
            return Err(invalid());
        }
        Ok(Self {
            broker,
            frame_limit,
            start_frame,
            last_request: None,
            last_reply: None,
        })
    }

    pub fn binding(&self) -> &Arc<TrustedBinding> {
        self.broker.binding()
    }
    pub fn start_frame(&self) -> &[u8] {
        &self.start_frame
    }
    pub fn last_request_frame(&self) -> Option<&[u8]> {
        self.last_request.as_deref().map(Vec::as_slice)
    }
    pub fn last_reply_frame(&self) -> Option<&[u8]> {
        self.last_reply.as_deref().map(Vec::as_slice)
    }

    /// Raw ingress remains typed and untrusted, including duplicate event/result delivery.
    pub fn receive(&mut self, frame: &[u8]) -> ProofResult<RuntimeIngress> {
        self.broker.receive(frame)
    }

    pub fn call(&mut self, request: &ToolRequest<'_>) -> ProofResult<ToolResult> {
        let message_id = EntityId::new();
        let wire = Arc::new(encode_envelope(
            message_id,
            "tool_request",
            None,
            request,
            self.frame_limit,
        )?);
        self.last_request = Some(Arc::clone(&wire));
        self.last_reply = None;
        let ingress = self.broker.receive(&wire)?;
        let RuntimeIngressKind::ToolReply(reply) = ingress.kind else {
            return Err(invalid());
        };
        self.last_reply = Some(Arc::clone(&reply));
        let envelope = decode_frame(
            &reply,
            self.frame_limit,
            ChannelRole::Runtime,
            Direction::HostToPeer,
        )?;
        if envelope.correlation_id != Some(message_id) {
            return Err(invalid());
        }
        let Message::ToolResult(result) = envelope.into_message() else {
            return Err(invalid());
        };
        if result.call_id != request.call_id {
            return Err(invalid());
        }
        Ok(result)
    }
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Simulated runtime received an unexpected wire reply",
    )
}
