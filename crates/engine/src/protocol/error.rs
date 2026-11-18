use std::borrow::Cow;
use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::domain::values::{EntityId, ValueError, non_null_optional};

pub type ProofResult<T> = Result<T, ProofError>;
const MAX_MESSAGE_BYTES: usize = 256;
const MAX_DIAGNOSTIC_REFS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    UnsupportedVersion,
    UnknownTool,
    PermissionDenied,
    OutOfScope,
    ApprovalRequired,
    BudgetExhausted,
    StaleSnapshot,
    UnsupportedProtocol,
    Timeout,
    Cancelled,
    PluginTrap,
    OutputInvalid,
    ProviderUnavailable,
    OutcomeUnknown,
    IntegrityError,
    IsolationUnavailable,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownTool => "unknown_tool",
            Self::PermissionDenied => "permission_denied",
            Self::OutOfScope => "out_of_scope",
            Self::ApprovalRequired => "approval_required",
            Self::BudgetExhausted => "budget_exhausted",
            Self::StaleSnapshot => "stale_snapshot",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::PluginTrap => "plugin_trap",
            Self::OutputInvalid => "output_invalid",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::IntegrityError => "integrity_error",
            Self::IsolationUnavailable => "isolation_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retryability {
    SafeRead,
    Reconcile,
    Never,
}

/// Host-only native SQLite context; never accepted from or serialized to peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFault {
    pub primary_code: i32,
    pub extended_code: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "WireError")]
pub struct ProofError {
    pub code: ErrorCode,
    pub message: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<EntityId>,
    pub retryability: Retryability,
    pub diagnostic_refs: Vec<EntityId>,
    #[serde(skip)]
    storage_fault: Option<StorageFault>,
}

impl ProofError {
    pub fn new(code: ErrorCode, message: &'static str) -> Self {
        let message = if message.len() <= MAX_MESSAGE_BYTES {
            message
        } else {
            "Error detail exceeds the permitted diagnostic length"
        };
        Self {
            code,
            message: Cow::Borrowed(message),
            invocation_id: None,
            retryability: if code == ErrorCode::OutcomeUnknown {
                Retryability::Reconcile
            } else {
                Retryability::Never
            },
            diagnostic_refs: Vec::new(),
            storage_fault: None,
        }
    }

    pub fn with_invocation(mut self, invocation_id: EntityId) -> Self {
        self.invocation_id = Some(invocation_id);
        self
    }

    pub fn for_safe_read(mut self) -> Self {
        if self.code != ErrorCode::OutcomeUnknown {
            self.retryability = Retryability::SafeRead;
        }
        self
    }

    pub fn storage_fault(&self) -> Option<StorageFault> {
        self.storage_fault
    }

    pub(crate) fn with_storage_fault(mut self, extended_code: i32) -> Self {
        self.storage_fault = Some(StorageFault {
            primary_code: extended_code & 0xff,
            extended_code,
        });
        self
    }
}

// Equality is the canonical wire contract, not transient native diagnostic context.
impl PartialEq for ProofError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.message == other.message
            && self.invocation_id == other.invocation_id
            && self.retryability == other.retryability
            && self.diagnostic_refs == other.diagnostic_refs
    }
}
impl Eq for ProofError {}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ProofError {}

impl From<ValueError> for ProofError {
    fn from(error: ValueError) -> Self {
        let code = if error == ValueError::InvalidVersion {
            ErrorCode::UnsupportedVersion
        } else {
            ErrorCode::InvalidInput
        };
        Self::new(code, error.message())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: ErrorCode,
    #[serde(deserialize_with = "bounded_message")]
    message: Cow<'static, str>,
    #[serde(default, deserialize_with = "non_null_optional")]
    invocation_id: Option<EntityId>,
    retryability: Retryability,
    #[serde(deserialize_with = "bounded_refs")]
    diagnostic_refs: Vec<EntityId>,
}

impl TryFrom<WireError> for ProofError {
    type Error = &'static str;

    fn try_from(wire: WireError) -> Result<Self, Self::Error> {
        if wire.code == ErrorCode::OutcomeUnknown && wire.retryability != Retryability::Reconcile {
            return Err("Unknown effects require read-only reconciliation");
        }
        Ok(Self {
            code: wire.code,
            message: wire.message,
            invocation_id: wire.invocation_id,
            retryability: wire.retryability,
            diagnostic_refs: wire.diagnostic_refs,
            storage_fault: None,
        })
    }
}

fn bounded_message<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Cow<'static, str>, D::Error> {
    struct MessageVisitor;
    impl Visitor<'_> for MessageVisitor {
        type Value = Cow<'static, str>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded redacted error message")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > MAX_MESSAGE_BYTES {
                return Err(E::custom("Error message exceeds its byte limit"));
            }
            Ok(Cow::Owned(value.to_owned()))
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
            if value.len() > MAX_MESSAGE_BYTES {
                return Err(E::custom("Error message exceeds its byte limit"));
            }
            Ok(Cow::Owned(value))
        }
    }
    deserializer.deserialize_str(MessageVisitor)
}

fn bounded_refs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<EntityId>, D::Error> {
    struct ReferenceVisitor;
    impl<'de> Visitor<'de> for ReferenceVisitor {
        type Value = Vec<EntityId>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 32 diagnostic references")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut references =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_DIAGNOSTIC_REFS));
            while let Some(reference) = sequence.next_element()? {
                if references.len() == MAX_DIAGNOSTIC_REFS {
                    return Err(de::Error::custom("Too many diagnostic references"));
                }
                references.push(reference);
            }
            Ok(references)
        }
    }
    deserializer.deserialize_seq(ReferenceVisitor)
}
