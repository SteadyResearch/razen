use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use razen_engine::adapters::evidence_store::EvidenceStore;
use razen_engine::adapters::ledger::{Ledger, StoredInvocation};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::case_execution::execute;
use razen_engine::application::parser_fuzz::{FuzzReport, FuzzTarget};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::domain::evidence::{Artifact, EvidenceRef};
use razen_engine::domain::proofs::{CaseStatus, CheckName, ProofCase, ProofResult};
use razen_engine::domain::values::{CatalogId, Digest, EntityId, InvocationState, WireInt};
use razen_engine::protocol::contracts::CanonicalFixtures;
use razen_engine::protocol::error::ErrorCode;
use serde_json::Value;

#[path = "support/private_root.rs"]
mod private_root;

const TOOL: &str = "proof.case.execute";

struct Fixture {
    host: ProofHost,
    profile: LoadedProfile,
    repository: PathBuf,
    manifest_sha256: Digest,
    _root: private_root::PrivateRoot,
}

impl Fixture {
    fn new() -> Self {
        Self::with_examples(|_| {})
    }

    fn with_examples(change: impl FnOnce(&mut Value)) -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let source = fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let mut examples: Value = serde_json::from_slice(&source).unwrap();
        change(&mut examples);
        let bytes = serde_json::to_vec(&examples).unwrap();
        let root = private_root::PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        // Deliberate test-provider identity, not operational executable provenance.
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::of(b"case publication behavior-test provider"),
        )
        .unwrap();
        let manifest_sha256 =
            Digest::of(&fs::read(repository.join("fixtures/scenarios/manifest.json")).unwrap());
        Self {
            host,
            profile,
            repository,
            manifest_sha256,
            _root: root,
        }
    }

    fn case(&self, id: &str) -> ProofCase {
        let manifest: Value = serde_json::from_slice(
            &fs::read(self.repository.join("fixtures/scenarios/manifest.json")).unwrap(),
        )
        .unwrap();
        serde_json::from_value(
            manifest["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["case_id"] == id)
                .unwrap()
                .clone(),
        )
        .unwrap()
    }

    fn execute(&self, id: &str) -> ProofResult {
        execute(
            &self.host,
            &self.profile,
            &self.repository,
            &self.case(id),
            self.manifest_sha256,
        )
        .unwrap()
    }

    fn calls(&self) -> Vec<StoredInvocation> {
        self.host
            .ledger
            .invocations()
            .unwrap()
            .into_iter()
            .filter(|stored| stored.invocation.tool_id.as_str() == TOOL)
            .collect()
    }

    fn bytes(&self, id: EntityId) -> Vec<u8> {
        self.host
            .evidence
            .read_artifact(
                self.host.project.project_id,
                id,
                self.profile
                    .config()
                    .protocol
                    .invocation_output_limit_bytes
                    .get() as usize,
            )
            .unwrap()
    }

    fn report(&self, stored: &StoredInvocation) -> Value {
        serde_json::from_slice(&self.bytes(stored.invocation.output_ref.unwrap())).unwrap()
    }

    fn published(&self, invocation_id: EntityId) -> Vec<Arc<Artifact>> {
        self.host
            .evidence
            .artifacts()
            .unwrap()
            .into_iter()
            .filter(|artifact| artifact.origin_invocation_id == invocation_id)
            .collect()
    }

    fn durable_state(&self) -> Value {
        serde_json::json!({
            "invocations": self.host.ledger.invocations().unwrap().into_iter().map(|stored| stored.invocation).collect::<Vec<_>>(),
            "artifacts": self.host.evidence.artifacts().unwrap().iter().map(AsRef::as_ref).collect::<Vec<_>>(),
            "grants": self.host.ledger.grants().unwrap(),
            "budget": self.host.ledger.read_budget(self.host.budget_id).unwrap(),
            "checkpoint": self.host.ledger.latest_checkpoint().unwrap(),
            "events": self.host.ledger.outbox(256).unwrap(),
        })
    }
}

fn catalog(value: &str) -> CatalogId {
    CatalogId::parse(value).unwrap()
}
fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}

fn assert_publication(fixture: &Fixture, result: &ProofResult, stored: &StoredInvocation) {
    result.validate().unwrap();
    let invocation = &stored.invocation;
    invocation.validate(Some(&stored.history)).unwrap();
    assert_eq!(stored.history.last(), invocation);
    assert_eq!(invocation.state, InvocationState::Completed);
    assert_eq!(
        stored.history.event_sequence().get(),
        4,
        "proposed, reserved, sending, completed are durable facts"
    );
    assert_eq!(invocation.run_id, fixture.host.workspace.run_id());
    assert_eq!(result.run_id, invocation.run_id);
    assert_eq!(invocation.project_id, fixture.host.project.project_id);
    assert_eq!(
        invocation.investigation_id,
        fixture.host.session.investigation_id
    );
    assert_eq!(invocation.session_id, fixture.host.session.session_id);
    assert_eq!(invocation.identity_id, fixture.host.identity.identity_id);
    assert_eq!(invocation.budget_id, fixture.host.budget_id);
    assert_eq!(invocation.provider_digest, fixture.host.provider_digest);
    assert_ne!(
        invocation.invocation_id,
        fixture.host.bootstrap_invocation_id
    );
    assert_eq!(stored.reserved_units, WireInt::ZERO);
    assert_eq!(invocation.usage, result.usage);
    assert_eq!(result.elapsed_us, result.usage.elapsed_us);
    assert_eq!(result.usage.units.get(), 1);
    assert!(result.usage.cpu_us.get() > 0);
    assert!(result.usage.elapsed_us.get() > 0);
    assert!(result.usage.bytes.get() > 0);
    assert!(result.usage.bytes <= stored.requested.bytes);
    assert!(result.usage.cpu_us <= stored.requested.cpu_us);
    assert!(result.usage.elapsed_us <= stored.requested.elapsed_us);
    assert_eq!(
        stored.requested.bytes,
        fixture
            .profile
            .config()
            .protocol
            .invocation_output_limit_bytes
    );

    let input = fixture
        .host
        .evidence
        .artifact(invocation.project_id, invocation.input_ref)
        .unwrap();
    assert_eq!(input.origin_invocation_id, invocation.invocation_id);
    let bytes = fixture.bytes(input.artifact_id);
    assert_eq!(Digest::of(&bytes), invocation.input_sha256);
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        document["case_id"],
        serde_json::to_value(&result.case_id).unwrap()
    );
    assert_eq!(
        document["profile_sha256"],
        serde_json::to_value(fixture.profile.sha256()).unwrap()
    );
    assert_eq!(
        document["fixture_manifest_sha256"],
        serde_json::to_value(fixture.manifest_sha256).unwrap()
    );
    for (field, value) in [
        ("invocation_id", invocation.invocation_id),
        ("actor_ref", invocation.actor_ref),
        ("user_id", fixture.host.project.user_id),
        ("project_id", invocation.project_id),
        ("investigation_id", invocation.investigation_id),
        ("session_id", invocation.session_id),
        ("identity_id", invocation.identity_id),
        ("budget_id", invocation.budget_id),
    ] {
        assert_eq!(
            document[field],
            serde_json::to_value(value).unwrap(),
            "canonical attribution: {field}"
        );
    }
    let grant = fixture
        .host
        .ledger
        .read_grant(invocation.grant_id.unwrap())
        .unwrap();
    assert_eq!(grant.tool_id, invocation.tool_id);
    assert_eq!(grant.tool_version, invocation.tool_version);
    assert_eq!(grant.project_id, invocation.project_id);
    assert_eq!(grant.identity_id, invocation.identity_id);
    assert_eq!(grant.provider_digest, invocation.provider_digest);
    assert_eq!(grant.scope_revision, invocation.scope_revision);
    assert_eq!(grant.bounded_input_sha256, invocation.input_sha256);
    assert_eq!(grant.limits, stored.requested);
    assert!(!grant.revoked);

    let mut refs = BTreeSet::new();
    for reference in &result.evidence_refs {
        let EvidenceRef::Artifact {
            artifact_id,
            sha256,
            ..
        } = reference
        else {
            panic!("Case publication is immutable artifact evidence")
        };
        assert!(refs.insert(*artifact_id));
        let artifact = fixture
            .host
            .evidence
            .artifact(invocation.project_id, *artifact_id)
            .unwrap();
        assert_eq!(artifact.origin_invocation_id, invocation.invocation_id);
        assert_eq!(*sha256, artifact.sha256);
        let body = fixture.bytes(*artifact_id);
        reference
            .validate_artifact(invocation.project_id, &artifact, &body)
            .unwrap();
        let wire = serde_json::to_value(reference).unwrap();
        assert!(wire.get("revision").is_none());
        assert_eq!(
            serde_json::from_value::<EvidenceRef>(wire).unwrap(),
            *reference
        );
    }
    assert!(
        refs.contains(&invocation.output_ref.unwrap()),
        "output_ref names the published report, not an unrelated UUID"
    );
    let exposed: u64 = fixture
        .published(invocation.invocation_id)
        .iter()
        .filter(|artifact| artifact.artifact_id != invocation.input_ref)
        .map(|artifact| artifact.length_bytes.get())
        .sum();
    assert_eq!(
        result.usage.bytes.get(),
        exposed,
        "every exposed output byte, excluding pre-admission input, is charged"
    );
}

#[test]
fn con01_publishes_real_report_current_grant_actor_and_per_case_origin_with_measured_usage() {
    let fixture = Fixture::new();
    let before = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let result = fixture.execute("CON-01");
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(result.status, CaseStatus::Passed);
    assert!(result.error.is_none());
    assert_eq!(result.observed.get(CheckName::RoundTrip), Some(true));
    assert_eq!(result.observed.get(CheckName::EvidenceVariants), Some(true));
    assert_publication(&fixture, &result, &calls[0]);
    let report = fixture.report(&calls[0]);
    assert_eq!(
        report["round_trips"].as_array().unwrap().len(),
        fixture.host.registry.contract_examples().records().len()
    );
    for resolved in report["resolved_evidence"].as_array().unwrap() {
        assert_eq!(resolved["expected_sha256"], resolved["observed_sha256"]);
        assert!(resolved["length_bytes"].as_u64().unwrap() > 0);
    }
    let after = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    assert_eq!(
        after.consumed.get() - before.consumed.get(),
        result.usage.units.get()
    );
    assert_eq!(after.reserved, before.reserved);
    let events = fixture.host.ledger.outbox(256).unwrap();
    let origins: Vec<_> = events
        .iter()
        .filter(|event| event.aggregate_id == calls[0].invocation.invocation_id)
        .collect();
    assert_eq!(origins.len(), 4);
    for (index, event) in origins.iter().enumerate() {
        assert_eq!(event.aggregate_sequence.get(), index as u64 + 1);
        assert_eq!(event.project_id, fixture.host.project.project_id);
        assert_eq!(
            event.control_revision,
            Some(calls[0].invocation.control_revision)
        );
    }
    let checkpoint = fixture.host.ledger.latest_checkpoint().unwrap().unwrap();
    let current = fixture
        .host
        .ledger
        .read_control(fixture.host.session.investigation_id)
        .unwrap();
    assert!(
        checkpoint
            .invocation_refs
            .contains(&calls[0].invocation.invocation_id)
    );
    assert!(checkpoint.budget_refs.contains(&fixture.host.budget_id));
    assert_eq!(checkpoint.control_revision, current.revision);
    assert_eq!(checkpoint.scope_revision, fixture.host.scope.revision);
}

#[test]
fn false_observed_evidence_variant_fails_proof_without_falsifying_provider_completion() {
    let fixture = Fixture::with_examples(|pack| {
        pack["records"].as_array_mut().unwrap().retain(|document| {
            !(document["record"]["type"] == "evidence_ref"
                && document["record"]["fields"].get("artifact_id").is_some())
        });
    });
    let result = fixture.execute("CON-01");
    assert_eq!(result.status, CaseStatus::Failed);
    assert_eq!(result.observed.get(CheckName::RoundTrip), Some(true));
    assert_eq!(
        result.observed.get(CheckName::EvidenceVariants),
        Some(false)
    );
    assert_eq!(result.expected.get(CheckName::EvidenceVariants), Some(true));
    assert_eq!(
        result.error.as_ref().unwrap().code,
        ErrorCode::OutputInvalid
    );
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].invocation.error.is_none(),
        "the provider successfully executed a failing proof"
    );
    assert_publication(&fixture, &result, &calls[0]);
    let report = fixture.report(&calls[0]);
    assert!(
        report["resolved_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["kind"] == "snapshot")
    );
}

#[test]
fn both_full_parser_campaigns_keep_owned_replay_sources_and_publish_exact_attachment_bytes() {
    let fixture = Fixture::new();
    let result = fixture.execute("CON-02");
    assert_eq!(result.status, CaseStatus::Passed);
    assert_eq!(result.observed.get(CheckName::CompleteBudget), Some(true));
    assert_eq!(result.observed.get(CheckName::Replayable), Some(true));
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_publication(&fixture, &result, call);
    let parser_us = fixture.profile.config().parser_fuzz.deadline_ms.get() * 1000;
    assert!(
        call.requested.elapsed_us.get() > 2 * parser_us,
        "two complete target deadlines plus finite completion overhead"
    );
    assert!(call.requested.cpu_us.get() >= 2 * parser_us);
    let report = fixture.report(call);
    assert_eq!(
        report["corpus_manifest"],
        "fixtures/scenarios/parser-corpus/manifest.json"
    );
    let sources: Vec<_> = fs::read_dir(fixture.host.workspace.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("contract-campaigns-")
        })
        .collect();
    assert_eq!(sources.len(), 1);
    let published = fixture.published(call.invocation.invocation_id);
    let referenced: BTreeSet<_> = result
        .evidence_refs
        .iter()
        .map(|reference| match reference {
            EvidenceRef::Artifact { artifact_id, .. } => *artifact_id,
            _ => panic!("Parser attachment refs must be artifacts"),
        })
        .collect();
    for name in [
        "framing-fuzz.json",
        "contracts-fuzz.json",
        "framing-seed-replays.json",
        "contracts-seed-replays.json",
        "corpus-manifest.json",
    ] {
        let source = fs::read(sources[0].join(name)).unwrap();
        let artifact = published
            .iter()
            .find(|artifact| {
                artifact.artifact_id != call.invocation.input_ref
                    && artifact.sha256 == Digest::of(&source)
                    && artifact.length_bytes.get() == source.len() as u64
            })
            .unwrap();
        assert!(
            referenced.contains(&artifact.artifact_id),
            "every actual replay attachment remains referenced: {name}"
        );
        assert_eq!(fixture.bytes(artifact.artifact_id), source);
        if name == "framing-fuzz.json" || name == "contracts-fuzz.json" {
            let fuzz: FuzzReport = serde_json::from_slice(&source).unwrap();
            assert_eq!(
                fuzz.target,
                if name == "framing-fuzz.json" {
                    FuzzTarget::Framing
                } else {
                    FuzzTarget::Contracts
                }
            );
            assert_eq!(fuzz.executed_inputs, 10_000);
            assert_eq!(fuzz.max_inputs, 10_000);
            assert_eq!(fuzz.deadline_ms, 30_000);
            assert_eq!(fuzz.profile_sha256, fixture.profile.sha256());
            assert_eq!(fuzz.counterexamples, 0);
            assert!(fuzz.replay_checks > 0);
        }
    }
    assert_eq!(
        fs::read(sources[0].join("corpus-manifest.json")).unwrap(),
        fs::read(
            fixture
                .repository
                .join("fixtures/scenarios/parser-corpus/manifest.json")
        )
        .unwrap()
    );
}

#[test]
fn invalid_inventory_cannot_register_grants_or_mutate_run_state() {
    let fixture = Fixture::new();
    for mutation in ["unknown", "expected", "fixture"] {
        let mut case = fixture.case("CON-01");
        match mutation {
            "unknown" => case.case_id = catalog("CON-99"),
            "expected" => {
                case.expected =
                    razen_engine::domain::proofs::Assertions::new([(CheckName::RoundTrip, true)])
                        .unwrap()
            }
            _ => case.fixture_refs = vec!["../private-host-file".to_owned()],
        }
        let before = fixture.durable_state();
        let error = execute(
            &fixture.host,
            &fixture.profile,
            &fixture.repository,
            &case,
            fixture.manifest_sha256,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(fixture.durable_state(), before);
    }
}

#[test]
fn repeated_real_cases_reuse_immutable_provider_but_never_reuse_actor_input_or_approval_authority()
{
    let fixture = Fixture::new();
    let first = fixture.execute("CON-01");
    let registered = fixture.host.ledger.read_tool(&catalog(TOOL)).unwrap();
    let first_call = fixture.calls().pop().unwrap();
    fixture
        .host
        .ledger
        .revoke_grant(first_call.invocation.grant_id.unwrap())
        .unwrap();
    let second = fixture.execute("CON-01");
    assert_eq!(
        fixture.host.ledger.read_tool(&catalog(TOOL)).unwrap(),
        registered
    );
    let calls = fixture.calls();
    assert_eq!(calls.len(), 2);
    let second_call = calls
        .iter()
        .find(|stored| stored.invocation.invocation_id != first_call.invocation.invocation_id)
        .unwrap();
    assert_ne!(
        first_call.invocation.actor_ref,
        second_call.invocation.actor_ref
    );
    assert_ne!(
        first_call.invocation.input_ref,
        second_call.invocation.input_ref
    );
    assert_ne!(
        first_call.invocation.input_sha256,
        second_call.invocation.input_sha256
    );
    assert_ne!(
        first_call.invocation.grant_id,
        second_call.invocation.grant_id
    );
    assert_ne!(
        first_call.invocation.output_ref,
        second_call.invocation.output_ref
    );
    assert_eq!(first.status, CaseStatus::Passed);
    assert_publication(&fixture, &second, second_call);
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap()
            .consumed
            .get(),
        3
    );
    let binding = fixture.host.bind_local().unwrap();
    assert!(
        !binding.allowed_tools().contains(&catalog(TOOL)),
        "internal case approval is never guest authority"
    );
    assert!(!binding.permissions().contains(&catalog(TOOL)));
}

#[test]
fn conflicting_existing_tool_cannot_be_upserted_or_advertised_as_the_case_provider() {
    for conflict in ["provider", "contract", "limits"] {
        let fixture = Fixture::new();
        let mut existing = fixture
            .host
            .ledger
            .read_tool(&catalog("traffic.snapshot.read"))
            .unwrap();
        existing.descriptor.tool_id = catalog(TOOL);
        match conflict {
            "provider" => existing.provider_digest = Digest::of(b"foreign reviewed provider"),
            "contract" => existing.descriptor.output_contract = catalog("foreign.case.output"),
            _ => existing.descriptor.limits.bytes = wire(1),
        }
        fixture.host.ledger.insert_tool(&existing).unwrap();
        let before = fixture.durable_state();
        let error = execute(
            &fixture.host,
            &fixture.profile,
            &fixture.repository,
            &fixture.case("CON-01"),
            fixture.manifest_sha256,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::IntegrityError);
        assert_eq!(
            fixture.host.ledger.read_tool(&catalog(TOOL)).unwrap(),
            existing
        );
        assert_eq!(fixture.durable_state(), before);
        assert_eq!(
            fixture.host.admission.check_integrity().unwrap_err().code,
            ErrorCode::IntegrityError
        );
    }
}

#[test]
fn exhausted_shared_root_leaves_a_durable_denial_and_does_not_execute_the_suite_or_create_a_fresh_balance()
 {
    let fixture = Fixture::new();
    let budget = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let remaining = budget.limit.checked_sub(budget.consumed).unwrap();
    fixture
        .host
        .ledger
        .transaction(|tx| {
            tx.reserve_budget(budget.budget_id, remaining, budget.revision)?;
            let reserved = tx.read_budget(budget.budget_id)?;
            tx.settle_budget(budget.budget_id, remaining, remaining, reserved.revision)
        })
        .unwrap();
    let exhausted = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let error = execute(
        &fixture.host,
        &fixture.profile,
        &fixture.repository,
        &fixture.case("CON-02"),
        fixture.manifest_sha256,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    let denied = &calls[0];
    assert_eq!(denied.invocation.state, InvocationState::Rejected);
    assert_eq!(denied.invocation.budget_id, fixture.host.budget_id);
    assert_eq!(denied.invocation.usage.units, WireInt::ZERO);
    assert!(denied.invocation.output_ref.is_none());
    assert_eq!(denied.reserved_units, WireInt::ZERO);
    denied.invocation.validate(Some(&denied.history)).unwrap();
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        exhausted
    );
    assert!(
        !fs::read_dir(fixture.host.workspace.path())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("contract-campaigns-"))
    );
    fixture.host.admission.check_integrity().unwrap();
}

#[test]
fn real_known_suite_error_settles_actual_usage_without_claiming_a_passing_proof() {
    let fixture = Fixture::new();
    fixture
        .host
        .workspace
        .write_new(
            Path::new("invalid-reviewed-source/fixtures/scenarios/contracts.json"),
            b"{",
        )
        .unwrap();
    let before = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let error = execute(
        &fixture.host,
        &fixture.profile,
        &fixture
            .host
            .workspace
            .path()
            .join("invalid-reviewed-source"),
        &fixture.case("CON-05"),
        fixture.manifest_sha256,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputInvalid);
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    let failed = &calls[0];
    assert_eq!(failed.invocation.state, InvocationState::Failed);
    assert_eq!(
        failed.invocation.error.as_ref().unwrap().code,
        ErrorCode::OutputInvalid
    );
    assert_eq!(failed.invocation.usage.units.get(), 1);
    assert!(failed.invocation.usage.cpu_us.get() > 0);
    assert!(failed.invocation.usage.elapsed_us.get() > 0);
    assert_eq!(failed.reserved_units, WireInt::ZERO);
    failed.invocation.validate(Some(&failed.history)).unwrap();
    let after = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    assert_eq!(after.consumed.get(), before.consumed.get() + 1);
    assert_eq!(after.reserved, before.reserved);
    fixture.host.admission.check_integrity().unwrap();
}

#[test]
fn real_missing_corpus_keeps_last_durable_sending_full_hold_and_common_integrity_latch() {
    let fixture = Fixture::new();
    let before = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let error = execute(
        &fixture.host,
        &fixture.profile,
        fixture._root.path(),
        &fixture.case("CON-02"),
        fixture.manifest_sha256,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert_integrity_hold(&fixture, &before);
}

fn assert_integrity_hold(fixture: &Fixture, before: &razen_engine::domain::authority::Budget) {
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    let sending = &calls[0];
    assert_eq!(sending.invocation.state, InvocationState::Sending);
    assert_eq!(sending.history.last(), &sending.invocation);
    assert_eq!(sending.history.event_sequence().get(), 3);
    assert!(sending.invocation.output_ref.is_none());
    assert!(
        sending.invocation.error.is_none(),
        "fatal integrity loss cannot fabricate a durable terminal failure"
    );
    assert_eq!(sending.reserved_units, sending.requested.units);
    let after = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    assert_eq!(after.consumed, before.consumed);
    assert_eq!(
        after.reserved,
        before
            .reserved
            .checked_add(sending.requested.units)
            .unwrap()
    );
    assert_eq!(
        fixture.host.admission.check_integrity().unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        fixture.host.bind_local().err().unwrap().code,
        ErrorCode::IntegrityError
    );
    let invocation_count = fixture.host.ledger.invocations().unwrap().len();
    let error = execute(
        &fixture.host,
        &fixture.profile,
        &fixture.repository,
        &fixture.case("CON-01"),
        fixture.manifest_sha256,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert_eq!(
        fixture.host.ledger.invocations().unwrap().len(),
        invocation_count
    );
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        after
    );
}

#[test]
fn changed_or_symlinked_actual_evidence_never_becomes_a_success_report_or_external_file_read() {
    for substitution in ["changed", "symlink"] {
        let fixture = Fixture::new();
        let snapshot = fixture.host.evidence.snapshots().unwrap().pop().unwrap();
        let artifact = fixture
            .host
            .evidence
            .artifact(fixture.host.project.project_id, snapshot.body_ref)
            .unwrap();
        let path = fixture.host.workspace.path().join(&artifact.relative_path);
        let external = fixture._root.path().join("not-owned-evidence");
        let secret = b"private bytes must not be exposed as proof evidence";
        fs::write(&external, secret).unwrap();
        if substitution == "changed" {
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            fs::write(&path, bytes).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
            symlink(&external, &path).unwrap();
        }
        let before = fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap();
        let error = execute(
            &fixture.host,
            &fixture.profile,
            &fixture.repository,
            &fixture.case("CON-01"),
            fixture.manifest_sha256,
        )
        .unwrap_err();
        if substitution == "changed" {
            assert_eq!(error.code, ErrorCode::IntegrityError);
            assert_integrity_hold(&fixture, &before);
        } else {
            // The descriptor-safe workspace rejects O_NOFOLLOW open failures as
            // OutputInvalid. No write was pending, so this read failure is known.
            assert_eq!(error.code, ErrorCode::OutputInvalid);
            let calls = fixture.calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].invocation.state, InvocationState::Failed);
            assert_eq!(calls[0].reserved_units, WireInt::ZERO);
            assert_eq!(calls[0].invocation.usage.units.get(), 1);
            fixture.host.admission.check_integrity().unwrap();
        }
        assert_eq!(fs::read(&external).unwrap(), secret);
        let calls = fixture.calls();
        for artifact in fixture.published(calls[0].invocation.invocation_id) {
            assert!(
                !fixture
                    .bytes(artifact.artifact_id)
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
    }
}

#[test]
fn published_refs_reject_hash_range_revision_and_later_body_tampering() {
    let fixture = Fixture::new();
    let result = fixture.execute("CON-01");
    let calls = fixture.calls();
    let id = calls[0].invocation.output_ref.unwrap();
    let artifact = fixture
        .host
        .evidence
        .artifact(fixture.host.project.project_id, id)
        .unwrap();
    let bytes = fixture.bytes(id);
    let reference = result
        .evidence_refs
        .iter()
        .find(|reference| {
            matches!(reference,
        EvidenceRef::Artifact { artifact_id, .. } if *artifact_id == id)
        })
        .unwrap();
    let mut wire = serde_json::to_value(reference).unwrap();
    wire["revision"] = serde_json::json!(0);
    assert!(serde_json::from_value::<EvidenceRef>(wire).is_err());
    let wrong = EvidenceRef::Artifact {
        artifact_id: id,
        sha256: Digest::of(b"not the report"),
        range: None,
    };
    assert_eq!(
        wrong
            .validate_artifact(fixture.host.project.project_id, &artifact, &bytes)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    let outside = EvidenceRef::Artifact {
        artifact_id: id,
        sha256: artifact.sha256,
        range: Some(
            razen_engine::domain::evidence::EvidenceRange::new(
                WireInt::ZERO,
                wire_int_after(artifact.length_bytes),
            )
            .unwrap(),
        ),
    };
    assert_eq!(
        outside
            .validate_artifact(fixture.host.project.project_id, &artifact, &bytes)
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    let path = fixture.host.workspace.path().join(&artifact.relative_path);
    let mut altered = bytes;
    altered[0] ^= 1;
    fs::write(path, altered).unwrap();
    assert_eq!(
        fixture
            .host
            .evidence
            .verify_artifact(fixture.host.project.project_id, id)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        fixture
            .host
            .ledger
            .read_invocation(calls[0].invocation.invocation_id)
            .unwrap()
            .invocation,
        calls[0].invocation,
        "later corruption does not rewrite historical completion into fake failure"
    );
}

fn wire_int_after(value: WireInt) -> WireInt {
    value.checked_add(wire(1)).unwrap()
}

#[test]
fn report_grant_history_origins_and_shared_consumption_survive_real_close_and_reopen() {
    let fixture = Fixture::new();
    let result = fixture.execute("CON-01");
    let call = fixture.calls().pop().unwrap();
    let report = fixture.bytes(call.invocation.output_ref.unwrap());
    let artifacts = fixture.published(call.invocation.invocation_id);
    let Fixture {
        host,
        profile,
        _root,
        ..
    } = fixture;
    let workspace = Arc::clone(&host.workspace);
    let project = host.project.project_id;
    let budget_id = host.budget_id;
    let before = host.ledger.read_budget(budget_id).unwrap();
    drop(host);
    let ledger = Ledger::open(&workspace, &profile).unwrap();
    let reopened = ledger
        .read_invocation(call.invocation.invocation_id)
        .unwrap();
    assert_eq!(reopened.invocation, call.invocation);
    assert_eq!(reopened.requested, call.requested);
    reopened
        .invocation
        .validate(Some(&reopened.history))
        .unwrap();
    assert_eq!(ledger.read_budget(budget_id).unwrap(), before);
    assert_eq!(
        ledger
            .read_grant(call.invocation.grant_id.unwrap())
            .unwrap()
            .bounded_input_sha256,
        call.invocation.input_sha256
    );
    let evidence = EvidenceStore::open(workspace).unwrap();
    assert_eq!(
        evidence
            .read_artifact(project, call.invocation.output_ref.unwrap(), 2_097_152)
            .unwrap(),
        report
    );
    for artifact in artifacts {
        assert_eq!(
            artifact.origin_invocation_id,
            reopened.invocation.invocation_id
        );
        evidence
            .verify_artifact(project, artifact.artifact_id)
            .unwrap();
    }
    assert_eq!(result.status, CaseStatus::Passed);
    drop(evidence);
    drop(ledger);
    drop(_root);
}

#[test]
fn remaining_completed_contract_cases_publish_real_observations_and_charge_one_shared_root() {
    for id in ["CON-03", "CON-04", "CON-05"] {
        let fixture = Fixture::new();
        let result = fixture.execute(id);
        assert_eq!(
            result.status,
            CaseStatus::Passed,
            "{id}: {:?}",
            result.error
        );
        let calls = fixture.calls();
        assert_eq!(calls.len(), 1);
        assert_publication(&fixture, &result, &calls[0]);
        assert_eq!(result.observed, fixture.case(id).expected);
        let all = fixture.host.ledger.invocations().unwrap();
        let consumed: u64 = all
            .iter()
            .map(|stored| stored.invocation.usage.units.get())
            .sum();
        let root = fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap();
        assert_eq!(
            root.consumed.get(),
            consumed,
            "nested case consumers and the case execution share aggregate consumption"
        );
        assert!(root.consumed <= root.limit);
        assert!(
            all.iter()
                .filter(|stored| stored.invocation.tool_id.as_str() == TOOL)
                .all(|stored| stored.invocation.budget_id == fixture.host.budget_id)
        );
    }
}

#[test]
fn transport_case_uses_real_admitted_suite_and_publishes_canonical_report() {
    let fixture = Fixture::new();
    let result = fixture.execute("NET-01");
    assert_eq!(result.status, CaseStatus::Passed, "{:?}", result.error);
    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    assert_publication(&fixture, &result, &calls[0]);
    assert_eq!(result.observed, fixture.case("NET-01").expected);
}
