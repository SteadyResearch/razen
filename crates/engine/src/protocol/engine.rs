//! One authenticated runtime channel. Wire metadata is never admission authority.
use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;

use super::codec::{ChannelRole, Direction, PROTOCOL, decode_frame, encode_frame};
use super::error::{ErrorCode, ProofError, ProofResult};
use super::messages::{
    BudgetSummary, MAX_REFERENCES, Message, RuntimeCancel, RuntimeClose, RuntimeEvent,
    RuntimeResult, RuntimeStart, RuntimeStarted, RuntimeSteer,
};
use crate::application::admission::TrustedBinding;
use crate::application::profile::LoadedProfile;
use crate::application::registry::Registry;
use crate::domain::runtime::RuntimeCapability;
use crate::domain::values::{ContractVersion, Digest, EntityId};

#[derive(Debug)]
pub struct RuntimeIngress {
    pub message_id: EntityId,
    pub correlation_id: Option<EntityId>,
    pub duplicate: bool,
    pub kind: RuntimeIngressKind,
}

/// Events/results are untrusted proposals for the caller, not canonical writes.
#[derive(Debug)]
pub enum RuntimeIngressKind {
    Started(RuntimeStarted),
    ToolReply(Arc<Vec<u8>>),
    Event(RuntimeEvent),
    Result(RuntimeResult),
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Fresh,
    Starting,
    Running,
    Cancelling,
    Finished,
    Closing,
    Closed,
}

enum SeenMessage {
    Host,
    Peer { digest: Digest, delivery: Delivery },
}

enum Delivery {
    Typed,
    Reply(Arc<Vec<u8>>),
    Failed(ProofError),
}

pub struct RuntimeBroker {
    binding: Arc<TrustedBinding>,
    registry: Arc<Registry>,
    lifecycle: Lifecycle,
    native_steering: bool,
    frame_limit: usize,
    id_capacity: usize,
    reply_capacity: usize,
    reply_count: usize,
    known: BTreeMap<EntityId, SeenMessage>,
}

impl RuntimeBroker {
    pub fn new(
        binding: Arc<TrustedBinding>,
        registry: Arc<Registry>,
        profile: &LoadedProfile,
    ) -> ProofResult<Self> {
        let protocol = &profile.config().protocol;
        let reply_capacity =
            usize::try_from(protocol.admission_queue_capacity.get()).map_err(|_| capacity())?;
        let event_capacity =
            usize::try_from(protocol.event_queue_capacity.get()).map_err(|_| capacity())?;
        Ok(Self {
            binding,
            registry,
            lifecycle: Lifecycle::Fresh,
            native_steering: false,
            frame_limit: usize::try_from(protocol.message_limit_bytes.get())
                .map_err(|_| capacity())?,
            id_capacity: event_capacity
                .checked_add(reply_capacity)
                .ok_or_else(capacity)?,
            reply_capacity,
            reply_count: 0,
            known: BTreeMap::new(),
        })
    }

    pub fn binding(&self) -> &Arc<TrustedBinding> {
        &self.binding
    }

    pub fn start(
        &mut self,
        context_refs: Vec<EntityId>,
        budget_summary: BudgetSummary,
    ) -> ProofResult<Arc<Vec<u8>>> {
        if self.lifecycle != Lifecycle::Fresh {
            return Err(lifecycle());
        }
        if context_refs.len() > MAX_REFERENCES
            || self.binding.allowed_tools().len() > MAX_REFERENCES
            || !budget_summary
                .consumed
                .checked_add(budget_summary.reserved)
                .is_ok_and(|total| total <= budget_summary.limit)
        {
            return Err(invalid());
        }
        let payload = RuntimeStart {
            binding_id: self.binding.binding_id(),
            contract_version: ContractVersion::V0_1_0,
            context_refs,
            tool_ids: self.binding.allowed_tools().to_vec(),
            budget_summary,
        };
        let frame = self.send("start", &payload)?;
        self.lifecycle = Lifecycle::Starting;
        Ok(frame)
    }

    pub fn receive(&mut self, frame: &[u8]) -> ProofResult<RuntimeIngress> {
        let envelope = decode_frame(
            frame,
            self.frame_limit,
            ChannelRole::Runtime,
            Direction::PeerToHost,
        )?;
        let message_id = envelope.message_id;
        let correlation_id = envelope.correlation_id;
        let digest = Digest::of(frame);
        let duplicate = match self.known.get(&message_id) {
            Some(SeenMessage::Host) => return Err(invalid()),
            Some(SeenMessage::Peer {
                digest: previous,
                delivery,
            }) => {
                if *previous != digest {
                    return Err(invalid());
                }
                match delivery {
                    Delivery::Reply(reply) => {
                        return Ok(RuntimeIngress {
                            message_id,
                            correlation_id,
                            duplicate: true,
                            kind: RuntimeIngressKind::ToolReply(Arc::clone(reply)),
                        });
                    }
                    Delivery::Failed(error) => return Err(error.clone()),
                    Delivery::Typed => true,
                }
            }
            None => false,
        };
        if !duplicate {
            if correlation_id.is_some_and(|id| !self.known.contains_key(&id)) {
                return Err(invalid());
            }
            self.ensure_room(1)?;
        }
        let message = envelope.into_message();
        let kind = match message {
            Message::RuntimeStarted(started) => {
                if !duplicate {
                    if self.lifecycle != Lifecycle::Starting {
                        return Err(lifecycle());
                    }
                    self.native_steering = started
                        .capabilities
                        .contains(&RuntimeCapability::NativeSteering);
                    self.lifecycle = Lifecycle::Running;
                }
                RuntimeIngressKind::Started(started)
            }
            Message::ToolRequest(request) => {
                if self.lifecycle != Lifecycle::Running {
                    return Err(lifecycle());
                }
                self.ensure_room(2)?;
                if self.reply_count >= self.reply_capacity {
                    return Err(capacity());
                }
                // Exclusive &mut access reserves these two slots until dispatch returns.
                // Retain errors too: an uncertain effect must not be redispatched.
                let reply_id = loop {
                    let id = self.fresh_id();
                    if id != message_id {
                        break id;
                    }
                };
                self.reply_count += 1;
                let executed = self
                    .registry
                    .execute(&self.binding, &request)
                    .and_then(|result| {
                        encode_envelope(
                            reply_id,
                            "tool_result",
                            Some(message_id),
                            &result,
                            self.frame_limit,
                        )
                    });
                let delivery = match executed {
                    Ok(reply) => Delivery::Reply(Arc::new(reply)),
                    Err(error) => Delivery::Failed(error),
                };
                let outcome = match &delivery {
                    Delivery::Reply(bytes) => Ok(RuntimeIngress {
                        message_id,
                        correlation_id,
                        duplicate: false,
                        kind: RuntimeIngressKind::ToolReply(Arc::clone(bytes)),
                    }),
                    Delivery::Failed(error) => Err(error.clone()),
                    Delivery::Typed => unreachable!("tool execution always has a reply or error"),
                };
                if matches!(&delivery, Delivery::Reply(_)) {
                    self.known.insert(reply_id, SeenMessage::Host);
                }
                self.known
                    .insert(message_id, SeenMessage::Peer { digest, delivery });
                return outcome;
            }
            Message::RuntimeEvent(event) => {
                if !duplicate
                    && matches!(
                        self.lifecycle,
                        Lifecycle::Fresh | Lifecycle::Starting | Lifecycle::Closed
                    )
                {
                    return Err(lifecycle());
                }
                RuntimeIngressKind::Event(event)
            }
            Message::RuntimeResult(result) => {
                if !duplicate {
                    if !matches!(
                        self.lifecycle,
                        Lifecycle::Running | Lifecycle::Cancelling | Lifecycle::Closing
                    ) {
                        return Err(lifecycle());
                    }
                    if self.lifecycle != Lifecycle::Closing {
                        self.lifecycle = Lifecycle::Finished;
                    }
                }
                RuntimeIngressKind::Result(result)
            }
            Message::RuntimeClosed(_) => {
                if !duplicate {
                    if self.lifecycle != Lifecycle::Closing {
                        return Err(lifecycle());
                    }
                    self.lifecycle = Lifecycle::Closed;
                }
                RuntimeIngressKind::Closed
            }
            _ => return Err(invalid()),
        };
        if !duplicate {
            self.known.insert(
                message_id,
                SeenMessage::Peer {
                    digest,
                    delivery: Delivery::Typed,
                },
            );
        }
        Ok(RuntimeIngress {
            message_id,
            correlation_id,
            duplicate,
            kind,
        })
    }

    pub fn steer(&mut self, payload: RuntimeSteer) -> ProofResult<Arc<Vec<u8>>> {
        if self.lifecycle != Lifecycle::Running || !self.native_steering {
            return Err(lifecycle());
        }
        self.send("steer", &payload)
    }

    pub fn cancel(&mut self, payload: RuntimeCancel<'_>) -> ProofResult<Arc<Vec<u8>>> {
        if self.lifecycle != Lifecycle::Running {
            return Err(lifecycle());
        }
        validate_reason(&payload.reason)?;
        let frame = self.send("cancel", &payload)?;
        self.lifecycle = Lifecycle::Cancelling;
        Ok(frame)
    }

    pub fn close(&mut self, payload: RuntimeClose<'_>) -> ProofResult<Arc<Vec<u8>>> {
        if !matches!(
            self.lifecycle,
            Lifecycle::Running | Lifecycle::Cancelling | Lifecycle::Finished
        ) {
            return Err(lifecycle());
        }
        validate_reason(&payload.reason)?;
        let frame = self.send("close", &payload)?;
        self.lifecycle = Lifecycle::Closing;
        Ok(frame)
    }

    fn send<T: Serialize>(&mut self, kind: &str, payload: &T) -> ProofResult<Arc<Vec<u8>>> {
        self.ensure_room(1)?;
        let id = self.fresh_id();
        let frame = encode_envelope(id, kind, None, payload, self.frame_limit)?;
        self.known.insert(id, SeenMessage::Host);
        Ok(Arc::new(frame))
    }

    fn fresh_id(&self) -> EntityId {
        loop {
            let id = EntityId::new();
            if !self.known.contains_key(&id) {
                return id;
            }
        }
    }

    fn ensure_room(&self, additional: usize) -> ProofResult<()> {
        if additional > self.id_capacity.saturating_sub(self.known.len()) {
            return Err(capacity());
        }
        Ok(())
    }
}

pub(crate) fn encode_envelope<T: Serialize>(
    message_id: EntityId,
    kind: &str,
    correlation_id: Option<EntityId>,
    payload: &T,
    limit: usize,
) -> ProofResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Outbound<'a, T> {
        protocol: &'static str,
        message_id: EntityId,
        kind: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<EntityId>,
        payload: &'a T,
    }
    encode_frame(
        &Outbound {
            protocol: PROTOCOL,
            message_id,
            kind,
            correlation_id,
            payload,
        },
        limit,
    )
}

fn validate_reason(reason: &str) -> ProofResult<()> {
    if reason.is_empty() || reason.len() > 256 {
        return Err(invalid());
    }
    Ok(())
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Invalid runtime message or binding-local correlation",
    )
}
fn lifecycle() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Runtime message is not permitted in this lifecycle",
    )
}
fn capacity() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Runtime message retention capacity is exhausted",
    )
}
