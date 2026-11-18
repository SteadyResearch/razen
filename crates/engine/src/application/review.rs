//! A private owner's explicit decision is an audit record, not cryptographic human attestation.
//! Caller first verifies the immutable packet, resolves required evidence, and supplies its actual manifest hash.
use crate::{
    adapters::workspace::OwnedDirectory,
    application::{
        harness::{CommandStatus, ReviewStatus},
        inventory::InventoryEvaluation,
        profile::LoadedProfile,
    },
    domain::{
        decisions::{
            DecisionEvidence, DecisionRecord, DecisionStatus, nonzero, validate_reference,
        },
        evidence::EvidenceRef,
        proofs::{IsolationStatus, Run},
        values::{AuditTime, Digest},
    },
    protocol::error::{ErrorCode, ProofError, ProofResult},
};
use rustix::fs::{self, AtFlags};
use std::{io::Read, path::Path};
pub struct ReviewContext<'a> {
    pub run: &'a Run,
    pub manifest_sha256: Digest,
    pub profile: &'a LoadedProfile,
    pub gate: &'a InventoryEvaluation<'a>,
    pub required_evidence: &'a [EvidenceRef],
    pub now: AuditTime,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewAssessment {
    pub review_status: ReviewStatus,
    pub r0_exit_ready: bool,
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Maintainer review context, ownership, or decision is invalid",
    )
}
pub fn assess(
    context: &ReviewContext<'_>,
    decision: Option<&DecisionRecord>,
) -> ProofResult<ReviewAssessment> {
    context.run.validate()?;
    crate::application::inventory::validate_environment(context.run, context.profile)?;
    context.gate.counts.validate()?;
    if !nonzero(context.manifest_sha256)
        || context.run.profile_sha256 != context.profile.sha256()
        || context.run.profile_id != context.profile.config().profile_id
        || context.gate.run_id != context.run.run_id
        || context.gate.profile_sha256 != context.run.profile_sha256
        || context.gate.counts.total.get() != 35
        || (context.required_evidence.is_empty()
            && context.gate.full_status == CommandStatus::Passed)
        || context.required_evidence.len() > 63
    {
        return Err(integrity());
    }
    for (index, reference) in context.required_evidence.iter().enumerate() {
        validate_reference(reference)?;
        if context.required_evidence[..index].contains(reference) {
            return Err(integrity());
        }
    }
    let mut result = ReviewAssessment {
        review_status: ReviewStatus::Unreviewed,
        r0_exit_ready: false,
    };
    let Some(decision) = decision else {
        return Ok(result);
    };
    decision.validate()?;
    let Some(finished) = context.run.finished_at else {
        return Ok(result);
    };
    if decision.decision_id.as_str() != "EXIT-REVIEW"
        || decision.reviewed_at < finished
        || decision.reviewed_at > context.now
        || !decision
            .evidence_refs
            .contains(&DecisionEvidence::RunManifest {
                run_id: context.run.run_id,
                sha256: context.manifest_sha256,
            })
        || decision.evidence_refs.len() != context.required_evidence.len() + 1
        || context.required_evidence.iter().any(|reference| {
            !decision
                .evidence_refs
                .contains(&DecisionEvidence::Evidence {
                    reference: *reference,
                })
        })
    {
        return Ok(result);
    }
    result.review_status = match decision.status {
        DecisionStatus::Approved => ReviewStatus::Approved,
        DecisionStatus::Rejected => ReviewStatus::Rejected,
        DecisionStatus::Recorded | DecisionStatus::Pending | DecisionStatus::Blocked => {
            ReviewStatus::Unreviewed
        }
    };
    result.r0_exit_ready = result.review_status == ReviewStatus::Approved
        && context.gate.full_status == CommandStatus::Passed
        && context.gate.counts.passed.get() == 35
        && context.run.environment.isolation_status == IsolationStatus::Prepared;
    Ok(result)
}
/// No creation, rewrite, automatic reviewer, manifest mutation, or proof rerun.
pub fn read_and_assess(
    workspace: &OwnedDirectory,
    context: &ReviewContext<'_>,
) -> ProofResult<ReviewAssessment> {
    if workspace.run_id() != context.run.run_id {
        return Err(integrity());
    }
    let exists = {
        let root = workspace.lock_directory()?;
        match fs::statat(&root, "review.json", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(_) => return Err(integrity()),
        }
    };
    if !exists {
        return assess(context, None);
    }
    let path = Path::new("review.json");
    let mut file = workspace.open_readonly(path)?;
    let before = file.metadata().map_err(|_| integrity())?;
    if before.len() > 256 * 1024 {
        return Err(integrity());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| integrity())?;
    let after = file.metadata().map_err(|_| integrity())?;
    let named = workspace
        .open_readonly(path)?
        .metadata()
        .map_err(|_| integrity())?;
    if bytes.len() as u64 != before.len()
        || !crate::adapters::native_files::same_file(&before, &after)
        || !crate::adapters::native_files::same_file(&before, &named)
    {
        return Err(integrity());
    }
    let decision = serde_json::from_slice::<DecisionRecord>(&bytes).map_err(|_| integrity())?;
    assess(context, Some(&decision))
}
