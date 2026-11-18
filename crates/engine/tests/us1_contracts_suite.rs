use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::parser_fuzz::{FuzzReport, FuzzTarget};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::application::suites::{CaseObservation, contracts};
use razen_engine::domain::knowledge::{
    AssetGraph, InvestigationGraph, MemoryItem, MemoryLevel, Trace, WorkflowDefinition,
    validate_example_links,
};
use razen_engine::domain::proofs::CheckName;
use razen_engine::domain::values::{CatalogId, Digest, EntityId, InvocationState};
use razen_engine::protocol::contracts::CanonicalFixtures;
use razen_engine::protocol::error::ErrorCode;
use serde_json::Value;

#[path = "support/private_root.rs"]
mod private_root;

struct Fixture {
    host: ProofHost,
    profile: LoadedProfile,
    repository: PathBuf,
    _root: private_root::PrivateRoot,
}

impl Fixture {
    fn new() -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let bytes = std::fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let root = private_root::PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::of(b"contract-suite integration-test provider"),
        )
        .unwrap();
        Self {
            host,
            profile,
            repository,
            _root: root,
        }
    }

    fn execute(&self, case: &str) -> CaseObservation {
        let id = CatalogId::parse(case).unwrap();
        let observation =
            contracts::execute(&self.host, &self.profile, &self.repository, &id).unwrap();
        assert_eq!(observation.case_id, id);
        assert!(observation.report.is_object());
        for path in &observation.attachment_paths {
            assert!(!path.is_absolute());
            assert!(
                path.components()
                    .all(|part| matches!(part, Component::Normal(_)))
            );
            assert!(self.host.workspace.path().join(path).is_file());
        }
        observation
    }

    fn evidence_bytes(&self) -> Vec<(EntityId, Digest, Vec<u8>)> {
        self.host
            .evidence
            .artifacts()
            .unwrap()
            .into_iter()
            .map(|artifact| {
                let bytes = self
                    .host
                    .evidence
                    .read_artifact(
                        self.host.project.project_id,
                        artifact.artifact_id,
                        2_097_152,
                    )
                    .unwrap();
                (artifact.artifact_id, artifact.sha256, bytes)
            })
            .collect()
    }
}

fn checks(observation: &CaseObservation, expected: &[CheckName]) {
    assert_eq!(observation.observed.iter().count(), expected.len());
    for check in expected {
        assert_eq!(
            observation.observed.get(*check),
            Some(true),
            "{check:?}: {}",
            observation.report
        );
    }
}

fn entity(value: &Value) -> EntityId {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn con01_round_trips_every_typed_example_and_resolves_both_live_evidence_variants() {
    let fixture = Fixture::new();
    let before = fixture.evidence_bytes();
    let observation = fixture.execute("CON-01");
    checks(
        &observation,
        &[
            CheckName::RoundTrip,
            CheckName::StableReferences,
            CheckName::EvidenceVariants,
        ],
    );
    assert_eq!(
        observation.report["round_trips"].as_array().unwrap().len(),
        fixture.host.registry.contract_examples().records().len()
    );
    let references = observation.report["resolved_evidence"].as_array().unwrap();
    assert!(
        references
            .iter()
            .any(|reference| reference["kind"] == "snapshot")
    );
    assert!(
        references
            .iter()
            .any(|reference| reference["kind"] == "artifact")
    );
    for reference in references {
        assert_eq!(
            entity(&reference["project_id"]),
            fixture.host.project.project_id
        );
        assert_eq!(reference["expected_sha256"], reference["observed_sha256"]);
        assert!(reference["length_bytes"].as_u64().unwrap() > 0);
    }
    assert_eq!(fixture.evidence_bytes(), before);
}

#[test]
fn con02_runs_and_persists_both_full_campaigns_with_actual_seed_replays_and_provenance() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CON-02");
    checks(
        &observation,
        &[
            CheckName::InvalidRejected,
            CheckName::FramingFuzz,
            CheckName::TypedFuzz,
            CheckName::CompleteBudget,
            CheckName::Replayable,
        ],
    );
    let corpus_digest = Digest::of(
        &std::fs::read(
            fixture
                .repository
                .join("fixtures/scenarios/parser-corpus/manifest.json"),
        )
        .unwrap(),
    );
    let manifest_path = observation
        .attachment_paths
        .iter()
        .find(|path| path.file_name().unwrap() == "corpus-manifest.json")
        .unwrap();
    assert_eq!(
        Digest::of(&std::fs::read(fixture.host.workspace.path().join(manifest_path)).unwrap()),
        corpus_digest
    );
    assert_eq!(
        observation.report["corpus_manifest"],
        "fixtures/scenarios/parser-corpus/manifest.json"
    );
    let numeric = observation.report["rejections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rejection| rejection["input"] == "numeric")
        .unwrap();
    assert_eq!(numeric["error"]["code"], "invalid_input");
    for (target, report_name, replay_name) in [
        (
            FuzzTarget::Framing,
            "framing-fuzz.json",
            "framing-seed-replays.json",
        ),
        (
            FuzzTarget::Contracts,
            "contracts-fuzz.json",
            "contracts-seed-replays.json",
        ),
    ] {
        let path = observation
            .attachment_paths
            .iter()
            .find(|path| path.file_name().unwrap() == report_name)
            .unwrap();
        let report: FuzzReport = serde_json::from_slice(
            &std::fs::read(fixture.host.workspace.path().join(path)).unwrap(),
        )
        .unwrap();
        assert_eq!(report.target, target);
        assert_eq!(report.executed_inputs, 10_000);
        assert_eq!(report.max_inputs, 10_000);
        assert_eq!(report.seed, 5489);
        assert_eq!(report.mutation_version.to_string(), "0.1.0");
        assert_eq!(report.max_input_bytes, 65_536);
        assert_eq!(report.deadline_ms, 30_000);
        assert!(report.elapsed_us > 0 && report.elapsed_us <= 30_000_000);
        assert_eq!(report.profile_sha256, fixture.profile.sha256());
        assert_eq!(report.corpus_sha256, corpus_digest);
        assert!(report.valid_round_trips > 0);
        assert!(report.explicit_rejections > 0);
        assert!(report.replay_checks > 0);
        assert_eq!(report.counterexamples, 0);
        assert_eq!(
            report.valid_round_trips + report.explicit_rejections,
            report.executed_inputs
        );
        let replay_path = observation
            .attachment_paths
            .iter()
            .find(|path| path.file_name().unwrap() == replay_name)
            .unwrap();
        let replays: Value = serde_json::from_slice(
            &std::fs::read(fixture.host.workspace.path().join(replay_path)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            replays.as_array().unwrap().len() as u64,
            report.replay_checks
        );
        for replay in replays.as_array().unwrap() {
            assert_eq!(replay["original"], "rejected");
            assert_eq!(replay["replay"], "rejected");
            assert!(replay["input_sha256"].as_str().is_some());
        }
    }
}

#[test]
fn con02_missing_corpus_is_an_explicit_error_not_a_generated_passing_observation() {
    let fixture = Fixture::new();
    let error = contracts::execute(
        &fixture.host,
        &fixture.profile,
        fixture._root.path(),
        &CatalogId::parse("CON-02").unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::IntegrityError);
}

#[test]
fn con03_rejects_stale_hash_foreign_and_identity_access_without_changing_original_bytes() {
    let fixture = Fixture::new();
    let before = fixture.evidence_bytes();
    let observation = fixture.execute("CON-03");
    checks(
        &observation,
        &[
            CheckName::StaleRejected,
            CheckName::ForeignRejected,
            CheckName::OriginalUnchanged,
        ],
    );
    for (name, code) in [
        ("stale_patch", "stale_snapshot"),
        ("hash_mismatch", "integrity_error"),
        ("foreign_evidence", "permission_denied"),
        ("unauthorized_identity", "permission_denied"),
        ("unauthorized_binding", "permission_denied"),
    ] {
        assert_eq!(
            observation.report["rejections"][name]["error"]["code"],
            code
        );
    }
    assert_eq!(fixture.evidence_bytes(), before);
    let foreign_project = fixture
        .host
        .ledger
        .read_project(entity(&observation.report["foreign_project_id"]))
        .unwrap();
    let foreign_scope = fixture
        .host
        .ledger
        .read_scope(foreign_project.scope_policy_id)
        .unwrap();
    let foreign_identity = fixture
        .host
        .ledger
        .read_identity(entity(&observation.report["foreign_identity_id"]))
        .unwrap();
    assert_eq!(foreign_scope.project_id, foreign_project.project_id);
    assert_eq!(foreign_identity.project_id, foreign_project.project_id);
    assert_ne!(foreign_project.project_id, fixture.host.project.project_id);
    fixture.host.admission.check_integrity().unwrap();
    let permitted = fixture.host.bind_local().unwrap();
    assert_eq!(
        fixture
            .host
            .admission
            .session(&permitted)
            .unwrap()
            .project_id,
        fixture.host.project.project_id
    );
    for (id, digest, bytes) in before {
        fixture
            .host
            .evidence
            .verify_artifact(fixture.host.project.project_id, id)
            .unwrap();
        assert_eq!(Digest::of(&bytes), digest);
    }
}

#[test]
fn con04_real_consumers_record_authoritative_denials_revocation_and_escrow_without_duplicate_charge()
 {
    let fixture = Fixture::new();
    let observation = fixture.execute("CON-04");
    checks(
        &observation,
        &[
            CheckName::ConsumerEquivalence,
            CheckName::RevocationEnforced,
            CheckName::ChildScopeBounded,
            CheckName::AggregateQuota,
        ],
    );
    let denials = observation.report["consumer_denials"].as_array().unwrap();
    assert!(!denials.is_empty());
    for denial in denials {
        assert_eq!(
            denial["harness_error"]["code"],
            denial["runtime_error"]["code"]
        );
        assert!(denial["harness_error"]["code"].as_str().is_some());
    }
    let completed_id = entity(&observation.report["completed_invocation_id"]);
    let completed = fixture.host.ledger.read_invocation(completed_id).unwrap();
    assert_eq!(completed.invocation.state, InvocationState::Completed);
    assert_eq!(
        entity(&observation.report["duplicate_invocation_id"]),
        completed_id
    );
    assert_eq!(
        observation.report["consumed_before_duplicate"],
        observation.report["consumed_after_duplicate"]
    );
    let revoked = fixture
        .host
        .ledger
        .read_grant(entity(&observation.report["revoked_grant_id"]))
        .unwrap();
    let wire = &observation.report["runtime_wire_observations"];
    assert_ne!(wire["first_binding_id"], wire["other_binding_id"]);
    assert_ne!(wire["first_invocation_id"], wire["other_invocation_id"]);
    assert_eq!(wire["before_replay_budget"], wire["after_replay_budget"]);
    assert_eq!(
        wire["cross_binding_correlation_error"]["code"],
        "invalid_input"
    );
    let other_invocation = fixture
        .host
        .ledger
        .read_invocation(entity(&wire["other_invocation_id"]))
        .unwrap();
    assert_eq!(
        other_invocation.invocation.actor_ref,
        entity(&wire["other_binding_id"])
    );
    assert_eq!(
        other_invocation.invocation.state,
        InvocationState::Completed
    );
    assert!(revoked.revoked);
    let parent = fixture
        .host
        .ledger
        .read_budget(entity(&observation.report["parent_budget_id"]))
        .unwrap();
    let child = fixture
        .host
        .ledger
        .read_budget(entity(&observation.report["child_budget_id"]))
        .unwrap();
    assert_eq!(parent.budget_id, fixture.host.budget_id);
    assert_eq!(child.parent_budget_id, Some(parent.budget_id));
    assert!(child.limit.get() > 0);
    assert!(parent.reserved.get() + child.consumed.get() >= child.limit.get());
    assert_eq!(
        observation.report["revocation_error"]["code"],
        "approval_required"
    );
}

#[test]
fn con05_links_four_distinct_structures_and_filters_real_context_before_bounded_promotion() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CON-05");
    checks(
        &observation,
        &[
            CheckName::GraphsDistinct,
            CheckName::OwnershipFiltered,
            CheckName::TwoMemoryLevels,
            CheckName::PromotionBounded,
        ],
    );
    let structures = observation.report["structures"].as_object().unwrap();
    assert_eq!(structures.len(), 4);
    for name in [
        "asset_graph",
        "investigation_graph",
        "execution_dag",
        "execution_trace",
    ] {
        assert!(structures[name].is_object());
    }
    let assets: AssetGraph = serde_json::from_value(structures["asset_graph"].clone()).unwrap();
    let investigation: InvestigationGraph =
        serde_json::from_value(structures["investigation_graph"].clone()).unwrap();
    let workflow: WorkflowDefinition =
        serde_json::from_value(structures["execution_dag"].clone()).unwrap();
    let trace: Trace = serde_json::from_value(structures["execution_trace"].clone()).unwrap();
    validate_example_links(
        &assets,
        &investigation,
        &workflow,
        &trace,
        &fixture.host.session,
    )
    .unwrap();
    let ids = [
        assets.graph_id,
        investigation.graph_id,
        workflow.workflow_id,
        trace.trace_id,
    ];
    assert!(
        ids.iter()
            .enumerate()
            .all(|(index, id)| !ids[..index].contains(id))
    );
    let context = fixture
        .host
        .evidence
        .read_artifact(
            fixture.host.project.project_id,
            entity(&observation.report["context_artifact_id"]),
            2_097_152,
        )
        .unwrap();
    let context: Value = serde_json::from_slice(&context).unwrap();
    let items: Vec<MemoryItem> = context["memory_examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| serde_json::from_value(item["record"].clone()).unwrap())
        .collect();
    assert!(items.iter().any(|item| item.level == MemoryLevel::User));
    assert!(items.iter().any(|item| item.level == MemoryLevel::Session));
    for item in &items {
        assert_eq!(item.user_id, fixture.host.project.user_id);
        if item.level == MemoryLevel::Session {
            assert_eq!(item.session_id, Some(fixture.host.session.session_id));
        }
    }
    let canonical_bytes = fixture
        .host
        .evidence
        .read_artifact(
            fixture.host.project.project_id,
            entity(&observation.report["canonical_context_artifact_id"]),
            2_097_152,
        )
        .unwrap();
    let canonical: Value = serde_json::from_slice(&canonical_bytes).unwrap();
    assert_eq!(
        canonical["record"],
        serde_json::to_value(&fixture.host.session).unwrap()
    );
    assert_eq!(
        observation.report["memory_levels"],
        serde_json::json!(["user", "session"])
    );
    for (name, code) in [
        ("foreign_owner", "permission_denied"),
        ("foreign_session", "permission_denied"),
        ("third_level", "invalid_input"),
        ("unreviewed_promotion", "permission_denied"),
        ("raw_evidence_promotion", "permission_denied"),
    ] {
        assert_eq!(observation.report["rejections"][name]["code"], code);
    }
    let session = fixture
        .host
        .ledger
        .read_session(fixture.host.session.session_id)
        .unwrap();
    assert_eq!(session.session.user_id, fixture.host.project.user_id);
    assert_eq!(session.session.session_id, fixture.host.session.session_id);
}

#[test]
fn unknown_contract_case_fails_without_touching_authority_budget_or_evidence() {
    let fixture = Fixture::new();
    let before = fixture.evidence_bytes();
    let budget = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let error = contracts::execute(
        &fixture.host,
        &fixture.profile,
        &fixture.repository,
        &CatalogId::parse("CON-99").unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        budget
    );
    assert_eq!(fixture.evidence_bytes(), before);
}
