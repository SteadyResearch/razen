//! Executed observations. The orchestrator supplies measured usage and immutable evidence.
use std::path::PathBuf;

use crate::domain::proofs::Assertions;
use crate::domain::values::CatalogId;

#[derive(Debug)]
pub struct CaseObservation {
    pub case_id: CatalogId,
    pub observed: Assertions,
    pub report: serde_json::Value,
    /// Actual files beneath the owned run, never arbitrary host filesystem paths.
    pub attachment_paths: Vec<PathBuf>,
}

pub mod components;
pub mod contracts;
pub mod exit;
pub mod recovery;
pub mod runtime;
pub mod transport;
