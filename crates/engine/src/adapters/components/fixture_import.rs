//! Trusted CMP fixture controller: a real foreign owned project and admitted import.
use crate::application::{
    admission::PreparedCall, effect_meter::EffectMeter, proof_host::ProofHost,
};
use crate::domain::{
    evidence::{RedactionStatus, Snapshot},
    execution::{ControlMode, ControlState},
    values::{CatalogId, ContractVersion, Digest, EntityId, WireInt},
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignFixture {
    pub snapshot: Snapshot,
    pub import_invocation_id: EntityId,
}
pub(crate) fn import(host: &ProofHost, source: &Snapshot) -> ProofResult<ForeignFixture> {
    let mut project = host.project.clone();
    project.project_id = EntityId::new();
    project.scope_policy_id = EntityId::new();
    project.revision = WireInt::ZERO;
    let mut scope = host.scope.clone();
    scope.project_id = project.project_id;
    scope.scope_policy_id = project.scope_policy_id;
    scope.revision = WireInt::ZERO;
    scope.allowed_destinations.clear();
    scope.exclusions.clear();
    host.ledger.transaction(|tx| {
        tx.insert_project(&project)?;
        tx.insert_scope(&scope)
    })?;
    let mut identity = host.identity.clone();
    identity.identity_id = EntityId::new();
    identity.project_id = project.project_id;
    identity.secret_ref_names.clear();
    host.ledger.insert_identity(&identity)?;
    let mut session = host.session.clone();
    session.session_id = EntityId::new();
    session.investigation_id = EntityId::new();
    session.control_revision = WireInt::ZERO;
    session.branch_refs.clear();
    session.evidence_refs.clear();
    let invocation_id = EntityId::new();
    let instruction = host.evidence.write_artifact(
        project.project_id,
        CatalogId::parse("proof-instruction")?,
        invocation_id,
        b"Import only the owned public foreign-project snapshot fixture.",
        RedactionStatus::Original,
    )?;
    let metadata = serde_json::to_vec(&serde_json::json!({"source_snapshot_id":source.snapshot_id,"source_sha256":source.sha256,"project_id":project.project_id})).map_err(|_| invalid())?;
    let input = host.evidence.write_artifact(
        project.project_id,
        CatalogId::parse("fixture-import-input")?,
        invocation_id,
        &metadata,
        RedactionStatus::Original,
    )?;
    host.ledger.insert_control(
        &ControlState {
            investigation_id: session.investigation_id,
            revision: WireInt::ZERO,
            mode: ControlMode::Running,
            admission_open: true,
            instruction_ref: instruction.artifact_id,
        },
        project.project_id,
        scope.revision,
    )?;
    host.ledger.insert_session(&session, project.project_id)?;
    host.control.register_existing(session.investigation_id)?;
    let tool = host
        .ledger
        .read_tool(&CatalogId::parse("proof.fixture.import")?)?;
    let mut spec = host.local_spec();
    spec.project_id = project.project_id;
    spec.identity_id = identity.identity_id;
    spec.session_id = session.session_id;
    spec.investigation_id = session.investigation_id;
    spec.allowed_tools = vec![tool.descriptor.tool_id.clone()];
    spec.permissions = tool.descriptor.permissions.clone();
    let binding = host.admission.bind(spec)?;
    let call = PreparedCall {
        invocation_id,
        call_id: EntityId::new(),
        tool_id: tool.descriptor.tool_id,
        tool_version: ContractVersion::V0_1_0,
        input_ref: input.artifact_id,
        input_sha256: input.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: tool.descriptor.limits,
    };
    host.approve(&binding, &call)?;
    host.admission.reserve(&binding, &call)?;
    let permit = host.admission.begin_effect(&binding, invocation_id)?;
    let mut meter = EffectMeter::start();
    meter.dispatched = true;
    let imported = (|| {
        host.admission.recheck_effect(&binding, &permit)?;
        let reader = host.evidence.snapshot_reader(
            source.project_id,
            source.snapshot_id,
            source.revision,
        )?;
        if source.length_bytes.get() > 65536 {
            return Err(invalid());
        }
        let bytes = reader.read(WireInt::ZERO, source.length_bytes)?;
        meter.add_bytes(bytes.len())?;
        meter.write_pending = true;
        let body = host.evidence.write_artifact(
            project.project_id,
            CatalogId::parse("foreign-fixture-body")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(bytes.len())?;
        let snapshot = Snapshot {
            snapshot_id: EntityId::new(),
            project_id: project.project_id,
            revision: WireInt::ZERO,
            sha256: Digest::of(&bytes),
            length_bytes: source.length_bytes,
            body_ref: body.artifact_id,
            representation: source.representation,
            headers: source.headers.clone(),
            truncated: false,
            derived_from: None,
        };
        meter.write_pending = true;
        host.evidence.install_snapshot(snapshot.clone())?;
        let output = host.evidence.write_artifact(
            project.project_id,
            CatalogId::parse("fixture-import-result")?,
            invocation_id,
            &metadata,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(metadata.len())?;
        Ok((snapshot, output.artifact_id))
    })();
    let usage = meter.usage()?;
    match imported {
        Ok((snapshot, output)) => {
            host.admission
                .complete(&binding, permit, usage, Some(output))?;
            Ok(ForeignFixture {
                snapshot,
                import_invocation_id: invocation_id,
            })
        }
        Err(cause) => {
            let terminal = if cause.code == ErrorCode::OutputInvalid && meter.write_pending {
                host.admission.outcome_unknown(
                    &binding,
                    permit,
                    usage,
                    ProofError::new(
                        ErrorCode::OutcomeUnknown,
                        "Foreign fixture persistence requires reconciliation",
                    ),
                )?
            } else {
                host.admission.fail(&binding, permit, usage, cause)?
            };
            Err(terminal.error.ok_or_else(|| {
                ProofError::new(
                    ErrorCode::IntegrityError,
                    "Foreign fixture terminal state is missing its attributed error",
                )
            })?)
        }
    }
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Foreign component fixture import does not match its bounded public source",
    )
}
