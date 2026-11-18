//! Dedicated, explicitly prepared Linux/VZ proof boundary; never a native fallback.
pub mod attestation;
pub mod lifecycle;
pub mod preflight;
pub mod proofs;
pub mod transport;

use crate::protocol::error::{ErrorCode, ProofError};
pub(crate) fn unavailable(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::IsolationUnavailable, message)
}
pub(crate) fn integrity(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::IntegrityError, message)
}
