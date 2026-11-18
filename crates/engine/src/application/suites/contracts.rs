//! Executed shared-contract checks. Schema examples never become operational outcomes.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::CaseObservation;
use crate::adapters::workspace::OwnedDirectory;
use crate::application::consumers::{HarnessConsumer, SimulatedRuntimeConsumer};
use crate::application::parser_fuzz::{FuzzReport, run_contracts, run_framing};
use crate::application::profile::LoadedProfile;
use crate::application::proof_host::ProofHost;
use crate::application::registry::Registry;
use crate::domain::evidence::{EvidenceRef, Snapshot};
use crate::domain::knowledge::{
    MemoryItem, MemoryLevel, PromotionReview, prefilter_memory, validate_example_links,
};
use crate::domain::proofs::{Assertions, CheckName};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt,
};
use crate::protocol::codec::{ChannelRole, Direction, decode_frame};
use crate::protocol::contracts::{CanonicalFixtures, ContractRecord, parse_document};
use crate::protocol::engine::{RuntimeIngressKind, encode_envelope};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use crate::protocol::messages::{BudgetSummary, Message, ToolRequest, ToolResult};

pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    let (observed, report, attachment_paths) = match case_id.as_str() {
        "CON-01" => round_trips(host)?,
        "CON-02" => parser_campaigns(host, profile, repo_root)?,
        "CON-03" => rejected_references(host)?,
        "CON-04" => consumers(host, profile)?,
        "CON-05" => knowledge(host, profile, repo_root)?,
        _ => {
            return Err(ProofError::new(
                ErrorCode::InvalidInput,
                "Unknown shared-contract case",
            ));
        }
    };
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report,
        attachment_paths,
    })
}

type Observation = (Assertions, Value, Vec<PathBuf>);

fn observation(
    checks: impl IntoIterator<Item = (CheckName, bool)>,
    report: Value,
) -> ProofResult<Observation> {
    Ok((Assertions::new(checks)?, report, Vec::new()))
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Executed contract observation did not satisfy its invariant",
    )
}

fn encode(value: &impl Serialize) -> ProofResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> ProofResult<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

fn expected_error<T>(result: ProofResult<T>, code: ErrorCode) -> ProofResult<ProofError> {
    match result {
        Err(error) if error.code == code => Ok(error),
        Err(error) => Err(error),
        Ok(_) => Err(invalid()),
    }
}

fn wire(value: u64) -> ProofResult<WireInt> {
    Ok(WireInt::new(value)?)
}

fn snapshot(host: &ProofHost) -> ProofResult<Arc<Snapshot>> {
    host.evidence
        .snapshots()?
        .into_iter()
        .find(|value| value.project_id == host.project.project_id)
        .ok_or_else(invalid)
}

fn round_trips(host: &ProofHost) -> ProofResult<Observation> {
    let examples = host.registry.contract_examples();
    let mut round_trips = Vec::with_capacity(examples.records().len());
    let mut stable = true;
    let mut resolved = Vec::new();
    let (mut snapshots, mut artifacts) = (0, 0);
    for original in examples.records() {
        let bytes = encode(original)?;
        let first = parse_document(&bytes, examples.context())?;
        let restored = parse_document(&encode(&first)?, examples.context())?;
        let equal = original == &first && first == restored;
        stable &= equal && original.schema_version == ContractVersion::V0_1_0;
        let value: Value = decode(&bytes)?;
        round_trips.push(json!({"type": value["record"]["type"], "schema_version": restored.schema_version,
            "serialized_sha256": Digest::of(&bytes), "equal": equal, "classification": "schema_example"}));
        let ContractRecord::EvidenceRef(reference) = &original.record else {
            continue;
        };
        match *reference {
            EvidenceRef::Snapshot {
                snapshot_id,
                revision,
                sha256,
                ..
            } => {
                let reader = host.evidence.snapshot_reader(
                    host.project.project_id,
                    snapshot_id,
                    revision,
                )?;
                let canonical =
                    host.evidence
                        .snapshot(host.project.project_id, snapshot_id, revision)?;
                let body = reader.read(WireInt::ZERO, canonical.length_bytes)?;
                reference.validate_snapshot(
                    host.project.project_id,
                    revision,
                    &canonical,
                    &body,
                )?;
                snapshots += 1;
                resolved.push(json!({"kind": "snapshot", "snapshot_id": snapshot_id, "project_id": canonical.project_id,
                    "revision": revision, "reference": reference, "expected_sha256": sha256,
                    "observed_sha256": Digest::of(&body), "length_bytes": body.len()}));
            }
            EvidenceRef::Artifact {
                artifact_id,
                sha256,
                ..
            } => {
                let canonical = host
                    .evidence
                    .artifact(host.project.project_id, artifact_id)?;
                let body =
                    host.evidence
                        .read_artifact(host.project.project_id, artifact_id, 1_048_576)?;
                reference.validate_artifact(host.project.project_id, &canonical, &body)?;
                artifacts += 1;
                resolved.push(json!({"kind": "artifact", "artifact_id": artifact_id, "project_id": canonical.project_id,
                    "reference": reference, "expected_sha256": sha256, "observed_sha256": Digest::of(&body),
                    "length_bytes": body.len()}));
            }
        }
    }
    observation(
        [
            (CheckName::RoundTrip, !round_trips.is_empty() && stable),
            (CheckName::StableReferences, stable && !resolved.is_empty()),
            (CheckName::EvidenceVariants, snapshots > 0 && artifacts > 0),
        ],
        json!({"round_trips": round_trips, "resolved_evidence": resolved,
            "scope": "Schema examples round-trip; only imported public bytes resolve as current evidence"}),
    )
}

fn complete(report: &FuzzReport, profile: &LoadedProfile) -> bool {
    let limits = &profile.config().parser_fuzz;
    report.executed_inputs == limits.max_inputs.get()
        && report.max_inputs == limits.max_inputs.get()
        && report.seed == limits.seed.get()
        && report.mutation_version == limits.mutation_version
        && report.max_input_bytes == limits.max_input_bytes.get()
        && report.deadline_ms == limits.deadline_ms.get()
        && report.profile_sha256 == profile.sha256()
        && report.elapsed_us <= limits.deadline_ms.get() * 1000
        && report.counterexamples == 0
        && report.valid_round_trips > 0
        && report.explicit_rejections > 0
        && report.valid_round_trips + report.explicit_rejections == report.executed_inputs
}

fn parser_campaigns(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
) -> ProofResult<Observation> {
    let examples = host.registry.contract_examples();
    let project = examples
        .records()
        .iter()
        .find(|document| matches!(document.record, ContractRecord::FixtureProject(_)))
        .ok_or_else(invalid)?;
    let valid = String::from_utf8(encode(project)?).map_err(|_| invalid())?;
    let mut invalid_number = serde_json::to_value(project).map_err(|_| invalid())?;
    invalid_number["record"]["fields"]["revision"] = json!(-1);
    let mut negatives = Vec::new();
    for (name, bytes, code) in [
        ("malformed", b"{".to_vec(), ErrorCode::InvalidInput),
        (
            "version",
            valid.replace("0.1.0", "0.2.0").into_bytes(),
            ErrorCode::InvalidInput,
        ),
        (
            "unknown_field",
            valid.replacen("{", "{\"unknown\":true,", 1).into_bytes(),
            ErrorCode::InvalidInput,
        ),
        (
            "duplicate_field",
            valid
                .replacen("{", "{\"schema_version\":\"0.1.0\",", 1)
                .into_bytes(),
            ErrorCode::InvalidInput,
        ),
        (
            "malformed_id",
            valid
                .replace(&host.project.project_id.to_string(), "not-a-uuid")
                .into_bytes(),
            ErrorCode::InvalidInput,
        ),
        ("numeric", encode(&invalid_number)?, ErrorCode::InvalidInput),
        (
            "document_bound",
            vec![b' '; 1_048_577],
            ErrorCode::BudgetExhausted,
        ),
    ] {
        let error = expected_error(parse_document(&bytes, examples.context()), code)?;
        negatives.push(json!({"input": name, "input_sha256": Digest::of(&bytes), "length_bytes": bytes.len(), "error": error}));
    }
    let range = br#"{"schema_version":"0.1.0","record":{"type":"evidence_ref","fields":{"artifact_id":"00000000-0000-4000-8000-00000000000b","sha256":"dcce14860cca030bfc9ecbf85fcce43ca1f766030bd654487efeca7c7f75b681","range_start":4,"range_end":3}}}"#;
    let error = expected_error(
        parse_document(range, examples.context()),
        ErrorCode::InvalidInput,
    )?;
    negatives.push(
        json!({"input": "reversed_range", "input_sha256": Digest::of(range), "error": error}),
    );
    let frame = vec![b' '; profile.config().parser_fuzz.max_input_bytes.get() as usize + 1];
    let error = expected_error(
        decode_frame(
            &frame,
            frame.len() - 1,
            ChannelRole::Runtime,
            Direction::PeerToHost,
        ),
        ErrorCode::BudgetExhausted,
    )?;
    negatives
        .push(json!({"input": "oversized_frame", "length_bytes": frame.len(), "error": error}));
    let relative = PathBuf::from(format!("contract-campaigns-{}", EntityId::new()));
    let evidence =
        OwnedDirectory::create(host.workspace.path(), &relative, host.workspace.run_id())?;
    let corpus = repo_root.join("fixtures/scenarios/parser-corpus");
    let framing = run_framing(profile, &corpus, &evidence)?;
    let typed = run_contracts(profile, &corpus, &evidence, examples.context())?;
    let manifest = std::fs::read(corpus.join("manifest.json")).map_err(|_| {
        ProofError::new(
            ErrorCode::IntegrityError,
            "Parser corpus manifest is unavailable",
        )
    })?;
    if Digest::of(&manifest) != framing.corpus_sha256
        || framing.corpus_sha256 != typed.corpus_sha256
    {
        return Err(ProofError::new(
            ErrorCode::IntegrityError,
            "Parser corpus changed during the executed campaigns",
        ));
    }
    evidence.write_new(Path::new("corpus-manifest.json"), &manifest)?;
    let framing_complete = complete(&framing, profile);
    let typed_complete = complete(&typed, profile);
    let replayable = framing.replay_checks > 0 && typed.replay_checks > 0;
    let attachments = [
        "framing-fuzz.json",
        "framing-seed-replays.json",
        "contracts-fuzz.json",
        "contracts-seed-replays.json",
        "corpus-manifest.json",
    ]
    .into_iter()
    .map(|name| relative.join(name))
    .collect();
    Ok((
        Assertions::new([
            (CheckName::InvalidRejected, negatives.len() == 9),
            (CheckName::FramingFuzz, framing_complete),
            (CheckName::TypedFuzz, typed_complete),
            (
                CheckName::CompleteBudget,
                framing_complete && typed_complete,
            ),
            (CheckName::Replayable, replayable),
        ])?,
        json!({"rejections": negatives, "framing": framing, "contracts": typed,
            "corpus_manifest": "fixtures/scenarios/parser-corpus/manifest.json"}),
        attachments,
    ))
}

fn rejected_references(host: &ProofHost) -> ProofResult<Observation> {
    let base = snapshot(host)?;
    let reader =
        host.evidence
            .snapshot_reader(host.project.project_id, base.snapshot_id, base.revision)?;
    let bytes = reader.read(WireInt::ZERO, base.length_bytes)?;
    let artifact = host
        .evidence
        .artifact(host.project.project_id, base.body_ref)?;
    let original_artifact =
        host.evidence
            .read_artifact(host.project.project_id, artifact.artifact_id, 1_048_576)?;
    let patch = host
        .registry
        .contract_examples()
        .records()
        .iter()
        .find_map(|document| match &document.record {
            ContractRecord::Patch(patch) if patch.base_snapshot_id == base.snapshot_id => {
                Some(patch)
            }
            _ => None,
        })
        .ok_or_else(invalid)?;
    let accepted = patch.apply(
        host.project.project_id,
        base.revision,
        &base,
        &bytes,
        EntityId::new(),
        EntityId::new(),
    )?;
    let permitted_revision = accepted.snapshot.revision;
    let mut stale = patch.clone();
    stale.base_revision = base.revision.checked_add(wire(1)?)?;
    let stale_error = expected_error(
        stale.apply(
            host.project.project_id,
            base.revision,
            &base,
            &bytes,
            EntityId::new(),
            EntityId::new(),
        ),
        ErrorCode::StaleSnapshot,
    )?;
    let mut mismatch = patch.clone();
    mismatch.base_sha256 = Digest::of(b"not the owned snapshot bytes");
    let hash_error = expected_error(
        mismatch.apply(
            host.project.project_id,
            base.revision,
            &base,
            &bytes,
            EntityId::new(),
            EntityId::new(),
        ),
        ErrorCode::IntegrityError,
    )?;
    let foreign = EntityId::new();
    let foreign_error = expected_error(
        host.evidence
            .read_artifact(foreign, artifact.artifact_id, 1_048_576),
        ErrorCode::PermissionDenied,
    )?;
    let identity_error = expected_error(
        host.identity.validate_project(foreign),
        ErrorCode::PermissionDenied,
    )?;
    let mut foreign_project = host.project.clone();
    foreign_project.project_id = foreign;
    foreign_project.scope_policy_id = EntityId::new();
    let mut foreign_scope = host.scope.clone();
    foreign_scope.scope_policy_id = foreign_project.scope_policy_id;
    foreign_scope.project_id = foreign_project.project_id;
    let mut foreign_identity = host.identity.clone();
    foreign_identity.identity_id = EntityId::new();
    foreign_identity.project_id = foreign;
    host.ledger.transaction(|tx| {
        tx.insert_project(&foreign_project)?;
        tx.insert_scope(&foreign_scope)?;
        tx.insert_identity(&foreign_identity)
    })?;
    let mut spec = host.local_spec();
    spec.identity_id = foreign_identity.identity_id;
    let binding_error = expected_error(host.admission.bind(spec), ErrorCode::PermissionDenied)?;
    let permitted_binding = host.bind_local()?;
    let permitted_session = host.admission.session(&permitted_binding)?;
    let after = reader.read(WireInt::ZERO, base.length_bytes)?;
    let artifact_after =
        host.evidence
            .read_artifact(host.project.project_id, artifact.artifact_id, 1_048_576)?;
    let unchanged = bytes == after
        && original_artifact == artifact_after
        && Digest::of(&after) == base.sha256
        && Digest::of(&artifact_after) == artifact.sha256
        && host
            .evidence
            .snapshot(host.project.project_id, base.snapshot_id, base.revision)?
            .as_ref()
            == base.as_ref();
    observation(
        [
            (
                CheckName::StaleRejected,
                stale_error.code == ErrorCode::StaleSnapshot
                    && hash_error.code == ErrorCode::IntegrityError,
            ),
            (
                CheckName::ForeignRejected,
                foreign_error.code == ErrorCode::PermissionDenied
                    && identity_error.code == ErrorCode::PermissionDenied
                    && binding_error.code == ErrorCode::PermissionDenied
                    && permitted_session.project_id == host.project.project_id,
            ),
            (CheckName::OriginalUnchanged, unchanged),
        ],
        json!({"snapshot_id": base.snapshot_id, "artifact_id": artifact.artifact_id, "permitted_patch_revision": permitted_revision,
            "foreign_project_id": foreign_project.project_id, "foreign_identity_id": foreign_identity.identity_id,
            "original_sha256": Digest::of(&bytes), "after_sha256": Digest::of(&after),
            "rejections": {"stale_patch": {"error": stale_error}, "hash_mismatch": {"error": hash_error},
                "foreign_evidence": {"error": foreign_error}, "unauthorized_identity": {"error": identity_error},
                "unauthorized_binding": {"error": binding_error}}}),
    )
}

fn request<'a>(
    call_id: EntityId,
    tool: &str,
    input: &'a RawValue,
    revision: WireInt,
) -> ProofResult<ToolRequest<'a>> {
    Ok(ToolRequest {
        call_id,
        tool_id: CatalogId::parse(tool)?,
        tool_version: ContractVersion::V0_1_0,
        input,
        source_control_revision: revision,
    })
}

fn raw(value: Value) -> ProofResult<Box<RawValue>> {
    RawValue::from_string(value.to_string()).map_err(|_| invalid())
}

fn success(host: &ProofHost, result: &ToolResult) -> ProofResult<()> {
    if result.state != InvocationState::Completed || result.error.is_some() {
        return Err(invalid());
    }
    let stored = host.ledger.read_invocation(result.invocation_id)?;
    stored.invocation.validate(Some(&stored.history))?;
    if stored.invocation.state != result.state
        || stored.invocation.output_ref != result.output_ref
        || stored.invocation.usage != result.usage
        || stored.reserved_units != WireInt::ZERO
    {
        return Err(invalid());
    }
    let artifact = host.evidence.artifact(
        host.project.project_id,
        result.output_ref.ok_or_else(invalid)?,
    )?;
    if artifact.origin_invocation_id != result.invocation_id {
        return Err(invalid());
    }
    host.evidence
        .verify_artifact(host.project.project_id, artifact.artifact_id)
}

fn denied_result(
    host: &ProofHost,
    result: &ToolResult,
    expected: ErrorCode,
) -> ProofResult<ProofError> {
    let error = result.error.as_ref().ok_or_else(invalid)?;
    let stored = host.ledger.read_invocation(result.invocation_id)?;
    if error.code != expected
        || result.output_ref.is_some()
        || result.state == InvocationState::Completed
        || stored.invocation.error.as_ref() != Some(error)
        || stored.reserved_units != WireInt::ZERO
    {
        return Err(invalid());
    }
    stored.invocation.validate(Some(&stored.history))?;
    Ok(error.clone())
}

fn snapshot_input(base: &Snapshot, max_bytes: u64) -> ProofResult<Box<RawValue>> {
    raw(
        json!({"snapshot_id": base.snapshot_id, "revision": base.revision, "offset": 0, "max_bytes": max_bytes}),
    )
}

fn consumers(host: &ProofHost, profile: &LoadedProfile) -> ProofResult<Observation> {
    let base = snapshot(host)?;
    let harness = HarnessConsumer::new(host.bind_local()?, Arc::clone(&host.registry));
    let budget = host.ledger.read_budget(host.budget_id)?;
    let mut runtime = SimulatedRuntimeConsumer::new(
        host.bind_local()?,
        Arc::clone(&host.registry),
        profile,
        vec![base.body_ref],
        BudgetSummary {
            limit: budget.limit,
            consumed: budget.consumed,
            reserved: budget.reserved,
        },
    )?;
    let input = snapshot_input(&base, 4)?;
    let call_id = EntityId::new();
    let harness_request = request(
        call_id,
        "traffic.snapshot.read",
        &input,
        harness.binding().control_revision(),
    )?;
    let reviewed = host.registry.prepare(harness.binding(), &harness_request)?;
    let harness_grant = host.approve(harness.binding(), reviewed.call())?;
    let completed = harness.call(&harness_request)?;
    success(host, &completed)?;
    let before_duplicate = host.ledger.read_budget(host.budget_id)?;
    let duplicate = harness.call(&harness_request)?;
    let after_duplicate = host.ledger.read_budget(host.budget_id)?;
    let replayed = same_result(&completed, &duplicate) && before_duplicate == after_duplicate;
    let runtime_request = request(
        call_id,
        "traffic.snapshot.read",
        &input,
        runtime.binding().control_revision(),
    )?;
    let prepared = host.registry.prepare(runtime.binding(), &runtime_request)?;
    host.approve(runtime.binding(), prepared.call())?;
    let runtime_completed = runtime.call(&runtime_request)?;
    success(host, &runtime_completed)?;
    let runtime_before = host.ledger.read_budget(host.budget_id)?;
    let runtime_duplicate = runtime.call(&runtime_request)?;
    let runtime_after = host.ledger.read_budget(host.budget_id)?;
    let (wire_isolated, wire_observations) =
        runtime_wire_checks(host, profile, &mut runtime, &runtime_request)?;
    let distinct = completed.invocation_id != runtime_completed.invocation_id
        && host
            .ledger
            .read_invocation(completed.invocation_id)?
            .invocation
            .actor_ref
            == harness.binding().actor_ref()
        && host
            .ledger
            .read_invocation(runtime_completed.invocation_id)?
            .invocation
            .actor_ref
            == runtime.binding().actor_ref();
    let mut denials = Vec::new();
    let denial_budget = host.ledger.read_budget(host.budget_id)?;
    let proposals_before = host.evidence.proposals(host.project.project_id)?;
    for (tool, body, code) in [
        (
            "traffic.snapshot.read",
            json!({"snapshot_id": base.snapshot_id, "revision": base.revision, "offset": -1, "max_bytes": 4}),
            ErrorCode::InvalidInput,
        ),
        (
            "traffic.snapshot.read",
            json!({"snapshot_id": base.snapshot_id, "revision": base.revision, "offset": 0, "max_bytes": 4, "grant_id": harness_grant}),
            ErrorCode::InvalidInput,
        ),
        (
            "context.read",
            json!({"kind": "investigation", "record_id": EntityId::new()}),
            ErrorCode::PermissionDenied,
        ),
        (
            "context.read",
            json!({"kind": "canonical_grants", "record_id": host.session.session_id}),
            ErrorCode::InvalidInput,
        ),
    ] {
        let input = raw(body)?;
        let id = EntityId::new();
        let direct = harness.call(&request(
            id,
            tool,
            &input,
            harness.binding().control_revision(),
        )?)?;
        let wire = runtime.call(&request(
            id,
            tool,
            &input,
            runtime.binding().control_revision(),
        )?)?;
        let direct_error = denied_result(host, &direct, code)?;
        let runtime_error = denied_result(host, &wire, code)?;
        denials.push(json!({"tool": tool, "harness_invocation_id": direct.invocation_id,
            "runtime_invocation_id": wire.invocation_id, "harness_error": direct_error, "runtime_error": runtime_error}));
    }
    let no_effects = denial_budget == host.ledger.read_budget(host.budget_id)?
        && proposals_before == host.evidence.proposals(host.project.project_id)?;
    // Revoke the exact chosen live grant after preparation, before admission.
    let revoked_input = snapshot_input(&base, 5)?;
    let revoked_request = request(
        EntityId::new(),
        "traffic.snapshot.read",
        &revoked_input,
        harness.binding().control_revision(),
    )?;
    let prepared = host.registry.prepare(harness.binding(), &revoked_request)?;
    let revoked_grant_id = host.approve(harness.binding(), prepared.call())?;
    host.ledger.revoke_grant(revoked_grant_id)?;
    let revoked_before = host.ledger.read_budget(host.budget_id)?;
    let revoked_result = host
        .registry
        .execute_prepared(harness.binding(), prepared)?;
    let revocation_error = denied_result(host, &revoked_result, ErrorCode::ApprovalRequired)?;
    let revoked_without_effect = revoked_before == host.ledger.read_budget(host.budget_id)?;
    let parent_before = host.ledger.read_budget(host.budget_id)?;
    let child = host.ledger.transaction(|tx| {
        tx.allocate_child(
            host.budget_id,
            EntityId::new(),
            wire(8)?,
            parent_before.revision,
        )
    })?;
    let parent_after = host.ledger.read_budget(host.budget_id)?;
    let mut child_spec = host.local_spec();
    child_spec.budget_id = child.budget_id;
    let child_binding = Arc::new(host.admission.bind_child(
        harness.binding(),
        child_spec.clone(),
        host.scope.clone(),
    )?);
    let mut scope = serde_json::to_value(&host.scope).map_err(|_| invalid())?;
    let destination = scope["allowed_destinations"]
        .as_array_mut()
        .and_then(|rules| rules.first_mut())
        .ok_or_else(invalid)?;
    destination["host"] = json!("unauthorized.example.invalid");
    let scope = serde_json::from_value(scope).map_err(|_| invalid())?;
    let scope_error = expected_error(
        host.admission
            .bind_child(harness.binding(), child_spec.clone(), scope),
        ErrorCode::PermissionDenied,
    )?;
    let mut tools = child_spec.clone();
    tools
        .allowed_tools
        .push(CatalogId::parse("proof.fixture.import")?);
    let tools_error = expected_error(
        host.admission
            .bind_child(harness.binding(), tools, host.scope.clone()),
        ErrorCode::PermissionDenied,
    )?;
    let mut identity = child_spec.clone();
    identity.identity_id = EntityId::new();
    let identity_error = expected_error(
        host.admission
            .bind_child(harness.binding(), identity, host.scope.clone()),
        ErrorCode::PermissionDenied,
    )?;
    let mut permissions = child_spec.clone();
    permissions
        .permissions
        .push(CatalogId::parse("fixture.ungranted")?);
    let permissions_error = expected_error(
        host.admission
            .bind_child(harness.binding(), permissions, host.scope.clone()),
        ErrorCode::PermissionDenied,
    )?;
    let root_child_error =
        expected_error(host.admission.bind(child_spec), ErrorCode::PermissionDenied)?;
    let overdraw = expected_error(
        host.ledger
            .transaction(|tx| tx.reserve_budget(child.budget_id, wire(9)?, child.revision)),
        ErrorCode::BudgetExhausted,
    )?;
    let sibling = expected_error(
        host.ledger.transaction(|tx| {
            tx.allocate_child(
                host.budget_id,
                EntityId::new(),
                parent_after.limit,
                parent_after.revision,
            )
        }),
        ErrorCode::BudgetExhausted,
    )?;
    let child_consumer = HarnessConsumer::new(child_binding, Arc::clone(&host.registry));
    let child_request = request(
        EntityId::new(),
        "traffic.snapshot.read",
        &input,
        child_consumer.binding().control_revision(),
    )?;
    let prepared = host
        .registry
        .prepare(child_consumer.binding(), &child_request)?;
    host.approve(child_consumer.binding(), prepared.call())?;
    let child_result = child_consumer.call(&child_request)?;
    success(host, &child_result)?;
    let parent_final = host.ledger.read_budget(host.budget_id)?;
    let child_final = host.ledger.read_budget(child.budget_id)?;
    let escrow = parent_after.reserved == parent_before.reserved.checked_add(child.limit)?
        && parent_after.consumed == parent_before.consumed
        && child_final.consumed == child_result.usage.units
        && parent_final.consumed == parent_before.consumed.checked_add(child_final.consumed)?
        && parent_final.reserved == parent_after.reserved.checked_sub(child_final.consumed)?;
    observation(
        [
            (
                CheckName::ConsumerEquivalence,
                no_effects
                    && distinct
                    && replayed
                    && wire_isolated
                    && same_result(&runtime_completed, &runtime_duplicate)
                    && runtime_before == runtime_after,
            ),
            (
                CheckName::RevocationEnforced,
                revoked_without_effect && host.ledger.read_grant(revoked_grant_id)?.revoked,
            ),
            (
                CheckName::ChildScopeBounded,
                child_final.parent_budget_id == Some(host.budget_id)
                    && scope_error.code == tools_error.code
                    && tools_error.code == identity_error.code
                    && permissions_error.code == ErrorCode::PermissionDenied
                    && root_child_error.code == ErrorCode::PermissionDenied,
            ),
            (
                CheckName::AggregateQuota,
                escrow
                    && overdraw.code == ErrorCode::BudgetExhausted
                    && sibling.code == ErrorCode::BudgetExhausted,
            ),
        ],
        json!({"consumer_denials": denials, "completed_invocation_id": completed.invocation_id,
            "runtime_wire_observations": wire_observations,
            "runtime_completed_invocation_id": runtime_completed.invocation_id, "duplicate_invocation_id": duplicate.invocation_id,
            "harness_binding_id": harness.binding().binding_id(), "runtime_binding_id": runtime.binding().binding_id(),
            "consumed_before_duplicate": before_duplicate.consumed, "consumed_after_duplicate": after_duplicate.consumed,
            "revoked_grant_id": revoked_grant_id, "revocation_error": revocation_error,
            "parent_budget_id": host.budget_id, "child_budget_id": child.budget_id,
            "parent_before": parent_before, "parent_escrowed": parent_after, "parent_after": parent_final,
            "child_after": child_final, "child_invocation_id": child_result.invocation_id,
            "child_rejections": {"scope": scope_error, "tools": tools_error, "identity": identity_error,
                "permissions": permissions_error,
                "root_rebind": root_child_error, "overdraw": overdraw, "sibling_allocation": sibling}}),
    )
}

fn knowledge(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
) -> ProofResult<Observation> {
    let examples = host.registry.contract_examples();
    let (mut assets, mut investigation, mut workflow, mut trace, mut example_session) =
        (None, None, None, None, None);
    let mut memories = Vec::new();
    for document in examples.records() {
        match &document.record {
            ContractRecord::AssetGraph(value) => assets = Some(value),
            ContractRecord::InvestigationGraph(value) => investigation = Some(value),
            ContractRecord::WorkflowDefinition(value) => workflow = Some(value),
            ContractRecord::Trace(value) => trace = Some(value),
            ContractRecord::InvestigationSession(value) => example_session = Some(value),
            ContractRecord::MemoryItem(value) => memories.push(value.clone()),
            _ => {}
        }
    }
    let (assets, investigation, workflow, trace, example_session) = (
        assets.ok_or_else(invalid)?,
        investigation.ok_or_else(invalid)?,
        workflow.ok_or_else(invalid)?,
        trace.ok_or_else(invalid)?,
        example_session.ok_or_else(invalid)?,
    );
    validate_example_links(assets, investigation, workflow, trace, example_session)?;
    let mut foreign_trace = trace.clone();
    foreign_trace.session_id = EntityId::new();
    let graph_error = expected_error(
        validate_example_links(
            assets,
            investigation,
            workflow,
            &foreign_trace,
            example_session,
        ),
        ErrorCode::PermissionDenied,
    )?;
    let binding = host.bind_local()?;
    let canonical = host.admission.session(&binding)?;
    canonical
        .session
        .authorize_access(binding.user_id(), binding.session_id())?;
    let foreign_owner = expected_error(
        canonical
            .session
            .authorize_access(EntityId::new(), binding.session_id()),
        ErrorCode::PermissionDenied,
    )?;
    let foreign_session = expected_error(
        canonical
            .session
            .authorize_access(binding.user_id(), EntityId::new()),
        ErrorCode::PermissionDenied,
    )?;
    let now = AuditTime::now();
    let user = prefilter_memory(&memories, binding.user_id(), MemoryLevel::User, None, now)?;
    let session = prefilter_memory(
        &memories,
        binding.user_id(),
        MemoryLevel::Session,
        Some(binding.session_id()),
        now,
    )?;
    let source = (*session.first().ok_or_else(invalid)?).clone();
    let candidate = (*user.first().ok_or_else(invalid)?).clone();
    let source_bytes =
        host.evidence
            .read_artifact(host.project.project_id, source.content_ref, 1_048_576)?;
    let generalized_bytes =
        host.evidence
            .read_artifact(host.project.project_id, candidate.content_ref, 1_048_576)?;
    if source_bytes == generalized_bytes || generalized_bytes.is_empty() {
        return Err(invalid());
    }
    // Trusted harness review of these selected public generalized fixture bytes,
    // not an approval inferred from a runtime-supplied promotion request.
    let review = PromotionReview {
        source_memory_id: source.memory_id,
        reviewer_user_id: binding.user_id(),
        reviewed_at: now,
        generalized_content_ref: candidate.content_ref,
        confidential_data_removed: !generalized_bytes
            .windows(source_bytes.len().max(1))
            .any(|window| window == source_bytes),
        conflicts_checked: candidate.kind == source.kind,
        explicit_user_decision: false,
    };
    let promoted = source.promote(
        candidate.clone(),
        &review,
        binding.user_id(),
        binding.session_id(),
        now,
    )?;
    let mut unreviewed = review.clone();
    unreviewed.confidential_data_removed = false;
    let unreviewed_error = expected_error(
        source.promote(
            candidate.clone(),
            &unreviewed,
            binding.user_id(),
            binding.session_id(),
            now,
        ),
        ErrorCode::PermissionDenied,
    )?;
    let mut raw_candidate = candidate.clone();
    raw_candidate.content_ref = source.content_ref;
    let raw_error = expected_error(
        source.promote(
            raw_candidate,
            &review,
            binding.user_id(),
            binding.session_id(),
            now,
        ),
        ErrorCode::PermissionDenied,
    )?;
    let mut third = serde_json::to_value(&source).map_err(|_| invalid())?;
    third["level"] = json!("project");
    let third_document = encode(
        &json!({"schema_version": "0.1.0", "record": {"type": "memory_item", "fields": third}}),
    )?;
    let third_error = expected_error(
        parse_document(&third_document, examples.context()),
        ErrorCode::InvalidInput,
    )?;
    // Add excluded memory metadata whose content does not exist. A successful real
    // provider read establishes that excluded content was not even resolved.
    let bytes =
        std::fs::read(repo_root.join("fixtures/scenarios/contracts.json")).map_err(|_| {
            ProofError::new(
                ErrorCode::IntegrityError,
                "Reviewed contract fixture source is unavailable",
            )
        })?;
    let mut pack: Value = decode(&bytes)?;
    let mut excluded = Vec::new();
    for (field, value) in [
        ("user_id", json!(EntityId::new())),
        ("session_id", json!(EntityId::new())),
        ("status", json!("retired")),
        ("valid_until", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut item = serde_json::to_value(&source).map_err(|_| invalid())?;
        let id = EntityId::new();
        let content = EntityId::new();
        item["memory_id"] = json!(id);
        item["content_ref"] = json!(content);
        item[field] = value;
        expected_error(
            host.evidence.artifact(host.project.project_id, content),
            ErrorCode::PermissionDenied,
        )?;
        excluded.push((id, content));
        pack["records"].as_array_mut().ok_or_else(invalid)?.push(
            json!({"schema_version": "0.1.0", "record": {"type": "memory_item", "fields": item}}),
        );
    }
    let registry = Arc::new(Registry::new(
        Arc::clone(&host.admission),
        Arc::clone(&host.evidence),
        CanonicalFixtures::from_bytes(&encode(&pack)?)?,
        profile,
    )?);
    let consumer = HarnessConsumer::new(binding, Arc::clone(&registry));
    let input =
        raw(json!({"kind": "memory_examples", "record_id": consumer.binding().session_id()}))?;
    let call = request(
        EntityId::new(),
        "context.read",
        &input,
        consumer.binding().control_revision(),
    )?;
    let prepared = registry.prepare(consumer.binding(), &call)?;
    host.approve(consumer.binding(), prepared.call())?;
    let result = consumer.call(&call)?;
    success(host, &result)?;
    let output: Value = decode(&host.evidence.read_artifact(
        host.project.project_id,
        result.output_ref.ok_or_else(invalid)?,
        1_048_576,
    )?)?;
    let context_id: EntityId =
        serde_json::from_value(output["record_ref"].clone()).map_err(|_| invalid())?;
    let context_bytes =
        host.evidence
            .read_artifact(host.project.project_id, context_id, 1_048_576)?;
    let context: Value = decode(&context_bytes)?;
    let retrieved = context["memory_examples"].as_array().ok_or_else(invalid)?;
    let selected: Vec<MemoryItem> = retrieved
        .iter()
        .map(|item| serde_json::from_value(item["record"].clone()).map_err(|_| invalid()))
        .collect::<ProofResult<_>>()?;
    let filtered = selected.iter().all(|item| {
        item.authorize_access(
            consumer.binding().user_id(),
            item.level,
            if item.level == MemoryLevel::Session {
                Some(consumer.binding().session_id())
            } else {
                None
            },
            now,
        )
        .is_ok()
    }) && selected.len() == user.len() + session.len()
        && excluded.iter().all(|(id, content)| {
            !selected
                .iter()
                .any(|item| item.memory_id == *id || item.content_ref == *content)
        });
    let two_levels = selected.iter().any(|item| item.level == MemoryLevel::User)
        && selected
            .iter()
            .any(|item| item.level == MemoryLevel::Session);
    let mut levels = Vec::with_capacity(2);
    if selected.iter().any(|item| item.level == MemoryLevel::User) {
        levels.push(MemoryLevel::User);
    }
    if selected
        .iter()
        .any(|item| item.level == MemoryLevel::Session)
    {
        levels.push(MemoryLevel::Session);
    }
    let canonical_input =
        raw(json!({"kind": "investigation", "record_id": canonical.session.investigation_id}))?;
    let canonical_call = request(
        EntityId::new(),
        "context.read",
        &canonical_input,
        consumer.binding().control_revision(),
    )?;
    let prepared = registry.prepare(consumer.binding(), &canonical_call)?;
    host.approve(consumer.binding(), prepared.call())?;
    let canonical_result = consumer.call(&canonical_call)?;
    success(host, &canonical_result)?;
    let canonical_output: Value = decode(&host.evidence.read_artifact(
        host.project.project_id,
        canonical_result.output_ref.ok_or_else(invalid)?,
        1_048_576,
    )?)?;
    let canonical_context_id: EntityId =
        serde_json::from_value(canonical_output["record_ref"].clone()).map_err(|_| invalid())?;
    let canonical_context: Value = decode(&host.evidence.read_artifact(
        host.project.project_id,
        canonical_context_id,
        1_048_576,
    )?)?;
    let current_session = serde_json::to_value(&canonical.session).map_err(|_| invalid())?;
    let ids = [
        assets.graph_id,
        investigation.graph_id,
        workflow.workflow_id,
        trace.trace_id,
    ];
    let distinct_ids = ids
        .iter()
        .enumerate()
        .all(|(index, id)| !ids[..index].contains(id));
    observation(
        [
            (
                CheckName::GraphsDistinct,
                distinct_ids
                    && assets.project_id == investigation.project_id
                    && workflow.workflow_id == trace.workflow_id
                    && graph_error.code == ErrorCode::PermissionDenied,
            ),
            (
                CheckName::OwnershipFiltered,
                filtered && canonical_context["record"] == current_session,
            ),
            (CheckName::TwoMemoryLevels, two_levels),
            (
                CheckName::PromotionBounded,
                promoted.content_ref != source.content_ref
                    && promoted.promotion_source_id == Some(source.memory_id)
                    && promoted.valid_until <= source.valid_until,
            ),
        ],
        json!({"structures": {"asset_graph": assets, "investigation_graph": investigation, "execution_dag": workflow, "execution_trace": trace},
            "structures_classification": "Linked concrete schema examples; not execution results or authority",
            "canonical_session": canonical.session, "context_invocation_id": result.invocation_id,
            "context_artifact_id": context_id, "context_sha256": Digest::of(&context_bytes),
            "canonical_context_artifact_id": canonical_context_id, "canonical_context_invocation_id": canonical_result.invocation_id,
            "memory_levels": levels, "selected_memory": selected, "excluded_missing_content": excluded,
            "promotion": {"source": source, "promoted": promoted, "generalized_sha256": Digest::of(&generalized_bytes)},
            "rejections": {"foreign_owner": foreign_owner, "foreign_session": foreign_session,
                "third_level": third_error, "unreviewed_promotion": unreviewed_error,
                "raw_evidence_promotion": raw_error, "cross_session_trace": graph_error}}),
    )
}

fn runtime_wire_checks(
    host: &ProofHost,
    profile: &LoadedProfile,
    runtime: &mut SimulatedRuntimeConsumer,
    request: &ToolRequest<'_>,
) -> ProofResult<(bool, Value)> {
    let frame = runtime.last_request_frame().ok_or_else(invalid)?.to_vec();
    let original_reply = runtime.last_reply_frame().ok_or_else(invalid)?.to_vec();
    let before = host.ledger.read_budget(host.budget_id)?;
    let replay = runtime.receive(&frame)?;
    let duplicate = replay.duplicate;
    let RuntimeIngressKind::ToolReply(reply) = replay.kind else {
        return Err(invalid());
    };
    let unchanged = before == host.ledger.read_budget(host.budget_id)? && *reply == original_reply;
    let budget = host.ledger.read_budget(host.budget_id)?;
    let mut other = SimulatedRuntimeConsumer::new(
        host.bind_local()?,
        Arc::clone(&host.registry),
        profile,
        Vec::new(),
        BudgetSummary {
            limit: budget.limit,
            consumed: budget.consumed,
            reserved: budget.reserved,
        },
    )?;
    let reviewed = host.registry.prepare(other.binding(), request)?;
    host.approve(other.binding(), reviewed.call())?;
    let first = other.receive(&frame)?;
    let not_duplicate = !first.duplicate;
    let RuntimeIngressKind::ToolReply(other_reply) = first.kind else {
        return Err(invalid());
    };
    let limit = profile.config().protocol.message_limit_bytes.get() as usize;
    let original = decode_frame(
        &original_reply,
        limit,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )?;
    let cross = decode_frame(
        &other_reply,
        limit,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )?;
    let Message::ToolResult(original_result) = original.into_message() else {
        return Err(invalid());
    };
    let Message::ToolResult(other_result) = cross.into_message() else {
        return Err(invalid());
    };
    success(host, &other_result)?;
    let foreign_start = decode_frame(
        other.start_frame(),
        limit,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )?;
    let foreign_correlation = foreign_start.message_id;
    let bad_event = encode_envelope(
        EntityId::new(),
        "event",
        Some(foreign_correlation),
        &json!({"event_type": "fixture.progress", "source_control_revision": runtime.binding().control_revision(),
            "sequence": 0, "data_refs": []}),
        limit,
    )?;
    let correlation_error = expected_error(runtime.receive(&bad_event), ErrorCode::InvalidInput)?;
    let inbound = decode_frame(&frame, limit, ChannelRole::Runtime, Direction::PeerToHost)?;
    let different_binding = runtime.binding().binding_id() != other.binding().binding_id()
        && original_result.invocation_id != other_result.invocation_id
        && host
            .ledger
            .read_invocation(other_result.invocation_id)?
            .invocation
            .actor_ref
            == other.binding().actor_ref();
    Ok((
        duplicate && unchanged && not_duplicate && different_binding,
        json!({"sender_message_id": inbound.message_id, "sender_call_id": request.call_id,
            "first_binding_id": runtime.binding().binding_id(), "other_binding_id": other.binding().binding_id(),
            "first_invocation_id": original_result.invocation_id, "other_invocation_id": other_result.invocation_id,
            "before_replay_budget": before, "after_replay_budget": budget, "cross_binding_correlation_error": correlation_error}),
    ))
}

fn same_result(first: &ToolResult, second: &ToolResult) -> bool {
    first.call_id == second.call_id
        && first.invocation_id == second.invocation_id
        && first.state == second.state
        && first.output_ref == second.output_ref
        && first.error == second.error
        && first.usage == second.usage
}
