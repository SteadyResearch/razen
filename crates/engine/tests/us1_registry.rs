use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use razen_engine::adapters::evidence_store::EvidenceStore;
use razen_engine::adapters::ledger::{Ledger, RegisteredTool};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::admission::{BindingSpec, HostAdmission, TrustedBinding};
use razen_engine::application::control::{
    ControlAction, ControlClient, ControlCommand, ControlServer, ControlService,
};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::registry::{PreparedInvocation, Registry};
use razen_engine::domain::authority::{ApprovalGrant, Budget, FixtureProject, IdentityProfile};
use razen_engine::domain::evidence::{
    EvidenceRange, EvidenceRef, ObservationStatus, RedactionStatus, Snapshot,
};
use razen_engine::domain::execution::ControlState;
use razen_engine::domain::knowledge::{AssetGraph, InvestigationSession};
use razen_engine::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt,
};
use razen_engine::protocol::contracts::{CanonicalFixtures, ContractRecord};
use razen_engine::protocol::error::ErrorCode;
use razen_engine::protocol::messages::{ToolRequest, ToolResult};
use serde_json::value::RawValue;
use serde_json::{Value, json};

fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}
fn catalog(value: &str) -> CatalogId {
    CatalogId::parse(value).unwrap()
}
fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/scenarios/contracts.json")
}
fn fixtures() -> CanonicalFixtures {
    CanonicalFixtures::load(&fixture_path()).unwrap()
}

struct Run {
    workspace: Arc<OwnedDirectory>,
    profile: LoadedProfile,
}

impl Run {
    fn new() -> Self {
        let run_id = EntityId::new();
        // A short, private, marked path also permits the genuine Unix control socket.
        let workspace = Arc::new(
            OwnedDirectory::create(
                Path::new("/private/tmp"),
                Path::new(&format!("rz-reg-{run_id}")),
                run_id,
            )
            .unwrap(),
        );
        let profile = LoadedProfile::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        Self { workspace, profile }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(self.workspace.path());
        if !std::thread::panicking() {
            result.expect("remove only this test's owned run");
        }
    }
}

struct Host {
    registry: Registry,
    admission: Arc<HostAdmission>,
    evidence: Arc<EvidenceStore>,
    control: Arc<ControlService>,
    ledger: Arc<Ledger>,
    project: FixtureProject,
    identity: IdentityProfile,
    session: InvestigationSession,
    snapshot: Snapshot,
    graph: AssetGraph,
    budget: EntityId,
    provider: Digest,
    tools: Vec<RegisteredTool>,
}

impl Host {
    fn new(run: &Run, fixtures: CanonicalFixtures) -> Self {
        let project = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::FixtureProject(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        let scope = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::ScopePolicy(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        let identity = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::IdentityProfile(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        let mut session = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::InvestigationSession(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        session.control_revision = WireInt::ZERO;
        session.goal = "Canonical ledger session, not the fixture's stale session copy".into();
        let snapshot = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::Snapshot(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        let graph = fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::AssetGraph(v) => Some(v.clone()),
                _ => None,
            })
            .unwrap();
        let ledger = Arc::new(Ledger::create(&run.workspace, &run.profile).unwrap());
        ledger
            .transaction(|tx| {
                tx.insert_project(&project)?;
                tx.insert_scope(&scope)
            })
            .unwrap();
        ledger.insert_identity(&identity).unwrap();
        let provider = Digest::of(b"trusted local registry provider binding for this test run");
        let tools = Registry::builtin_tools(provider, &run.profile).unwrap();
        for tool in &tools {
            ledger.insert_tool(tool).unwrap();
        }
        let state: ControlState = serde_json::from_value(json!({
            "investigation_id": session.investigation_id, "revision": 0,
            "mode": "running", "admission_open": true, "instruction_ref": EntityId::new()
        }))
        .unwrap();
        ledger
            .insert_control(&state, project.project_id, scope.revision)
            .unwrap();
        ledger.insert_session(&session, project.project_id).unwrap();
        let budget = EntityId::new();
        ledger
            .insert_budget(&Budget {
                budget_id: budget,
                parent_budget_id: None,
                limit: wire(1_000_000),
                consumed: WireInt::ZERO,
                reserved: WireInt::ZERO,
                revision: WireInt::ZERO,
            })
            .unwrap();
        let evidence = Arc::new(EvidenceStore::open(Arc::clone(&run.workspace)).unwrap());
        evidence
            .import_fixtures(&fixtures, EntityId::new())
            .unwrap();
        let control = Arc::new(
            ControlService::new(Arc::clone(&ledger), &run.profile, session.investigation_id)
                .unwrap(),
        );
        let admission = Arc::new(HostAdmission::new(
            Arc::clone(&ledger),
            Arc::clone(&control),
        ));
        let registry = Registry::new(
            Arc::clone(&admission),
            Arc::clone(&evidence),
            fixtures,
            &run.profile,
        )
        .unwrap();
        Self {
            registry,
            admission,
            evidence,
            control,
            ledger,
            project,
            identity,
            session,
            snapshot,
            graph,
            budget,
            provider,
            tools,
        }
    }

    fn bind(&self) -> Arc<TrustedBinding> {
        self.bind_session(&self.session)
    }

    fn bind_session(&self, session: &InvestigationSession) -> Arc<TrustedBinding> {
        self.admission
            .bind(BindingSpec {
                user_id: self.project.user_id,
                project_id: self.project.project_id,
                investigation_id: session.investigation_id,
                session_id: session.session_id,
                identity_id: self.identity.identity_id,
                budget_id: self.budget,
                provider_digest: self.provider,
                allowed_tools: self
                    .tools
                    .iter()
                    .map(|t| t.descriptor.tool_id.clone())
                    .collect(),
                permissions: self
                    .tools
                    .iter()
                    .flat_map(|t| t.descriptor.permissions.iter().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
            .map(Arc::new)
            .unwrap()
    }

    fn snapshot_input(&self, offset: u64, count: u64) -> Value {
        json!({"snapshot_id": self.snapshot.snapshot_id, "revision": self.snapshot.revision,
            "offset": offset, "max_bytes": count})
    }

    fn proposal_input(&self) -> Value {
        json!({"rule_id": "rule:public-binary", "title": "Actual public binary observation",
            "snapshot_id": self.snapshot.snapshot_id, "revision": self.snapshot.revision,
            "range_start": 1, "range_end": self.snapshot.length_bytes})
    }

    fn prepare(
        &self,
        binding: &Arc<TrustedBinding>,
        call_id: EntityId,
        tool: &str,
        input: &Value,
    ) -> PreparedInvocation {
        let raw = RawValue::from_string(input.to_string()).unwrap();
        self.registry
            .prepare(
                binding,
                &request(call_id, tool, &raw, binding.control_revision()),
            )
            .unwrap()
    }

    fn approve(&self, binding: &TrustedBinding, prepared: &PreparedInvocation) -> EntityId {
        let call = prepared.call();
        let grant_id = EntityId::new();
        self.ledger
            .insert_grant(&ApprovalGrant {
                grant_id,
                project_id: binding.project_id(),
                identity_id: binding.identity_id(),
                tool_id: call.tool_id.clone(),
                tool_version: call.tool_version,
                provider_digest: binding.provider_digest(),
                scope_revision: binding.scope_revision(),
                bounded_input_sha256: call.input_sha256,
                limits: call.requested,
                expires_at: AuditTime::now()
                    .checked_add(Duration::from_secs(60))
                    .unwrap(),
                revoked: false,
            })
            .unwrap();
        grant_id
    }

    fn success(&self, binding: &Arc<TrustedBinding>, tool: &str, input: &Value) -> ToolResult {
        let prepared = self.prepare(binding, EntityId::new(), tool, input);
        self.approve(binding, &prepared);
        let result = self.registry.execute_prepared(binding, prepared).unwrap();
        self.assert_success(binding, &result);
        result
    }

    fn assert_success(&self, binding: &TrustedBinding, result: &ToolResult) {
        assert_eq!(result.state, InvocationState::Completed);
        assert!(result.error.is_none());
        let stored = self.ledger.read_invocation(result.invocation_id).unwrap();
        assert_eq!(stored.invocation.state, result.state);
        assert_eq!(stored.invocation.output_ref, result.output_ref);
        assert_eq!(stored.invocation.usage, result.usage);
        assert_eq!(stored.invocation.actor_ref, binding.actor_ref());
        assert_eq!(stored.invocation.session_id, binding.session_id());
        assert_eq!(stored.invocation.provider_digest, self.provider);
        assert_eq!(stored.reserved_units, WireInt::ZERO);
        stored.invocation.validate(Some(&stored.history)).unwrap();
        let artifact = self
            .evidence
            .artifact(binding.project_id(), result.output_ref.unwrap())
            .unwrap();
        assert_eq!(artifact.origin_invocation_id, result.invocation_id);
        self.evidence
            .verify_artifact(binding.project_id(), artifact.artifact_id)
            .unwrap();
    }

    fn output(&self, result: &ToolResult) -> Value {
        serde_json::from_slice(
            &self
                .evidence
                .read_artifact(
                    self.project.project_id,
                    result.output_ref.unwrap(),
                    2_097_152,
                )
                .unwrap(),
        )
        .unwrap()
    }

    fn assert_denial(&self, binding: &TrustedBinding, result: &ToolResult, code: ErrorCode) {
        let error = result
            .error
            .as_ref()
            .expect("business denial is explicit, never empty success");
        assert_eq!(error.code, code);
        assert_eq!(error.invocation_id, Some(result.invocation_id));
        assert!(result.output_ref.is_none());
        assert_ne!(result.state, InvocationState::Completed);
        let stored = self.ledger.read_invocation(result.invocation_id).unwrap();
        assert_eq!(stored.invocation.actor_ref, binding.actor_ref());
        assert_eq!(stored.invocation.state, result.state);
        assert_eq!(stored.invocation.error, result.error);
        assert_eq!(stored.reserved_units, WireInt::ZERO);
        assert_eq!(stored.invocation.usage, result.usage);
        stored.invocation.validate(Some(&stored.history)).unwrap();
    }

    fn execute_raw(&self, binding: &Arc<TrustedBinding>, tool: &str, input: &str) -> ToolResult {
        let raw = RawValue::from_string(input.to_owned()).unwrap();
        self.registry
            .execute(
                binding,
                &request(EntityId::new(), tool, &raw, binding.control_revision()),
            )
            .unwrap()
    }
}

fn request<'a>(
    call_id: EntityId,
    tool: &str,
    input: &'a RawValue,
    revision: WireInt,
) -> ToolRequest<'a> {
    ToolRequest {
        call_id,
        tool_id: catalog(tool),
        tool_version: ContractVersion::V0_1_0,
        input,
        source_control_revision: revision,
    }
}

fn exact_keys(value: &Value, expected: &[&str]) {
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(keys, expected);
}

fn contains_value(tree: &Value, value: &Value) -> bool {
    tree == value
        || match tree {
            Value::Array(items) => items.iter().any(|item| contains_value(item, value)),
            Value::Object(items) => items.values().any(|item| contains_value(item, value)),
            _ => false,
        }
}

fn assert_no_authority_context(tree: &Value) {
    match tree {
        Value::Array(values) => values.iter().for_each(assert_no_authority_context),
        Value::Object(values) => {
            for (key, value) in values {
                assert!(
                    ![
                        "grant_id",
                        "secret_ref_names",
                        "credentials",
                        "conversation",
                        "runtime_state"
                    ]
                    .contains(&key.as_str())
                );
                assert_no_authority_context(value);
            }
        }
        _ => {}
    }
}

#[test]
fn builtin_catalog_advertises_only_three_real_local_providers_with_exact_versions() {
    let run = Run::new();
    let digest = Digest::of(b"trusted reviewed local provider");
    let tools = Registry::builtin_tools(digest, &run.profile).unwrap();
    let mut ids: Vec<_> = tools
        .iter()
        .map(|t| t.descriptor.tool_id.to_string())
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            "context.read",
            "observation.propose",
            "traffic.snapshot.read"
        ]
    );
    for tool in tools {
        assert_eq!(tool.provider_digest, digest);
        assert_eq!(tool.descriptor.version, ContractVersion::V0_1_0);
        assert!(!tool.descriptor.permissions.is_empty());
        assert!(tool.descriptor.limits.units > WireInt::ZERO);
    }
}

#[test]
fn snapshot_provider_returns_actual_public_binary_ranges_eof_and_immutable_results_after_reopen() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let public = fixtures().body(host.snapshot.body_ref).unwrap().to_vec();
    assert!(public.contains(&0) && public.contains(&0xff));
    let original = host
        .evidence
        .artifact(host.project.project_id, host.snapshot.body_ref)
        .unwrap();
    assert_eq!(
        fs::read(run.workspace.path().join(&original.relative_path)).unwrap(),
        public
    );
    let before = host.ledger.read_budget(host.budget).unwrap();
    let mut charged = 0;
    let mut outputs = Vec::new();
    for (offset, count) in [(0, 7), (7, 65_536), (public.len() as u64, 16)] {
        let started = Instant::now();
        let result = host.success(
            &binding,
            "traffic.snapshot.read",
            &host.snapshot_input(offset, count),
        );
        assert!(result.usage.elapsed_us.get() > 0);
        assert!(result.usage.elapsed_us.get() <= started.elapsed().as_micros() as u64);
        let output = host.output(&result);
        exact_keys(&output, &["snapshot_ref", "offset", "bytes_base64", "eof"]);
        assert_eq!(output["offset"], offset);
        let reference: EvidenceRef =
            serde_json::from_value(output["snapshot_ref"].clone()).unwrap();
        host.evidence
            .snapshot_reader(
                host.project.project_id,
                host.snapshot.snapshot_id,
                host.snapshot.revision,
            )
            .unwrap()
            .validate_reference(&reference)
            .unwrap();
        let bytes = STANDARD
            .decode(output["bytes_base64"].as_str().unwrap())
            .unwrap();
        let end = public.len().min(offset as usize + count as usize);
        assert_eq!(bytes, public[offset as usize..end]);
        assert_eq!(output["eof"], end == public.len());
        assert!(result.usage.bytes.get() >= bytes.len() as u64);
        charged += result.usage.units.get();
        outputs.push((result.output_ref.unwrap(), output));
    }
    let after = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(after.consumed.get() - before.consumed.get(), charged);
    assert_eq!(after.reserved, WireInt::ZERO);
    let project = host.project.project_id;
    drop(host);
    let reopened = EvidenceStore::open(Arc::clone(&run.workspace)).unwrap();
    for (id, output) in outputs {
        assert_eq!(
            serde_json::from_slice::<Value>(
                &reopened.read_artifact(project, id, 2_097_152).unwrap()
            )
            .unwrap(),
            output
        );
    }
}

#[test]
fn prepared_input_is_canonical_host_owned_evidence_and_never_the_callers_claimed_digest() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let input = host.snapshot_input(0, 16);
    let prepared = host.prepare(&binding, EntityId::new(), "traffic.snapshot.read", &input);
    let call = prepared.call();
    let artifact = host
        .evidence
        .artifact(binding.project_id(), call.input_ref)
        .unwrap();
    let bytes = host
        .evidence
        .read_artifact(binding.project_id(), call.input_ref, 65_536)
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), input);
    assert_eq!(Digest::of(&bytes), call.input_sha256);
    assert_eq!(artifact.sha256, call.input_sha256);
    assert_eq!(artifact.origin_invocation_id, call.invocation_id);
    let proposal = host.ledger.read_invocation(call.invocation_id).unwrap();
    assert_eq!(proposal.invocation.state, InvocationState::Proposed);
    assert!(proposal.invocation.grant_id.is_none());
    assert_eq!(proposal.reserved_units, WireInt::ZERO);
    assert_eq!(proposal.invocation.input_ref, artifact.artifact_id);
    host.approve(&binding, &prepared);
    let result = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_success(&binding, &result);
}

#[test]
fn observation_provider_persists_only_host_generated_proposals_with_verified_binary_evidence() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let input = host.proposal_input();
    let result = host.success(&binding, "observation.propose", &input);
    let output = host.output(&result);
    exact_keys(&output, &["proposal_id", "status"]);
    assert_eq!(output["status"], "proposed");
    let proposal_id: EntityId = serde_json::from_value(output["proposal_id"].clone()).unwrap();
    assert_ne!(proposal_id, result.invocation_id);
    let proposal = host
        .evidence
        .proposal(host.project.project_id, proposal_id)
        .unwrap();
    assert_eq!(proposal.actor_ref, binding.actor_ref());
    assert_eq!(proposal.status, ObservationStatus::Proposed);
    assert_eq!(proposal.title, input["title"].as_str().unwrap());
    assert_eq!(proposal.rule_id, catalog("rule:public-binary"));
    assert_eq!(
        proposal.evidence_refs,
        vec![EvidenceRef::Snapshot {
            snapshot_id: host.snapshot.snapshot_id,
            revision: host.snapshot.revision,
            sha256: host.snapshot.sha256,
            range: Some(EvidenceRange::new(wire(1), host.snapshot.length_bytes).unwrap()),
        }]
    );
    let reader = host
        .evidence
        .snapshot_reader(
            host.project.project_id,
            host.snapshot.snapshot_id,
            host.snapshot.revision,
        )
        .unwrap();
    reader
        .validate_reference(&proposal.evidence_refs[0])
        .unwrap();
    assert_eq!(
        host.evidence.proposals(host.project.project_id).unwrap(),
        vec![Arc::clone(&proposal)]
    );
    assert!(
        host.evidence.record_proposal((*proposal).clone()).is_err(),
        "proposal IDs are immutable, not upserts"
    );
    let project = host.project.project_id;
    drop(reader);
    drop(host);
    let reopened = EvidenceStore::open(Arc::clone(&run.workspace)).unwrap();
    assert_eq!(reopened.proposals(project).unwrap(), vec![proposal]);
}

#[test]
fn context_provider_stores_owned_artifacts_and_reads_canonical_session_not_fixture_authority() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let mut saved_contexts = Vec::new();
    for (kind, id, expected) in [
        (
            "investigation",
            host.session.investigation_id,
            json!(host.session),
        ),
        ("asset_examples", host.graph.graph_id, json!(host.graph)),
    ] {
        let result = host.success(
            &binding,
            "context.read",
            &json!({"kind": kind, "record_id": id}),
        );
        let output = host.output(&result);
        exact_keys(&output, &["record_ref", "schema_version"]);
        assert_eq!(output["schema_version"], "0.1.0");
        let record_ref: EntityId = serde_json::from_value(output["record_ref"].clone()).unwrap();
        assert_ne!(record_ref, result.output_ref.unwrap());
        let artifact = host
            .evidence
            .artifact(host.project.project_id, record_ref)
            .unwrap();
        assert_eq!(artifact.origin_invocation_id, result.invocation_id);
        let bytes = host
            .evidence
            .read_artifact(host.project.project_id, record_ref, 2_097_152)
            .unwrap();
        let context: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            contains_value(&context, &expected),
            "context must contain the actual canonical typed record"
        );
        assert_no_authority_context(&context);
        assert!(host.evidence.artifact(EntityId::new(), record_ref).is_err());
        saved_contexts.push((record_ref, bytes));
    }
    // The store has one writer; restart only after releasing that writer.
    drop(host);
    let reopened = EvidenceStore::open(Arc::clone(&run.workspace)).unwrap();
    for (record_ref, bytes) in saved_contexts {
        assert_eq!(
            reopened
                .read_artifact(binding.project_id(), record_ref, 2_097_152)
                .unwrap(),
            bytes
        );
    }
}

#[test]
fn memory_context_filters_owner_session_status_and_expiry_before_touching_content() {
    let run = Run::new();
    let mut pack: Value = serde_json::from_slice(&fs::read(fixture_path()).unwrap()).unwrap();
    let memory = pack["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| {
            d["record"]["type"] == "memory_item" && d["record"]["fields"]["level"] == "session"
        })
        .unwrap()
        .clone();
    let user_memory = pack["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["record"]["type"] == "memory_item" && d["record"]["fields"]["level"] == "user")
        .unwrap()
        .clone();
    let mut excluded_artifact = pack["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| {
            d["record"]["type"] == "artifact" && d["record"]["fields"]["kind"] == "fixture-body"
        })
        .unwrap()
        .clone();
    let excluded_content = EntityId::new();
    excluded_artifact["record"]["fields"]["artifact_id"] = json!(excluded_content);
    excluded_artifact["record"]["fields"]["relative_path"] = json!("evidence/excluded-public.bin");
    // The excluded file starts with precisely the same actual public bytes/hash/length.
    let source_id = pack["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| {
            d["record"]["type"] == "artifact" && d["record"]["fields"]["kind"] == "fixture-body"
        })
        .unwrap()["record"]["fields"]["artifact_id"]
        .clone();
    let mut body = pack["bodies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["body_id"] == source_id)
        .unwrap()
        .clone();
    body["body_id"] = json!(excluded_content);
    pack["bodies"].as_array_mut().unwrap().push(body);
    pack["records"]
        .as_array_mut()
        .unwrap()
        .push(excluded_artifact);
    let mut excluded_ids = Vec::new();
    for (field, value) in [
        ("user_id", json!(EntityId::new())),
        ("session_id", json!(EntityId::new())),
        ("status", json!("retired")),
        ("status", json!("proposed")),
        ("valid_until", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut excluded = memory.clone();
        let id = EntityId::new();
        excluded["record"]["fields"]["memory_id"] = json!(id);
        excluded["record"]["fields"]["content_ref"] = json!(excluded_content);
        excluded["record"]["fields"][field] = value;
        pack["records"].as_array_mut().unwrap().push(excluded);
        excluded_ids.push(id);
    }
    let host = Host::new(
        &run,
        CanonicalFixtures::from_bytes(&serde_json::to_vec(&pack).unwrap()).unwrap(),
    );
    let binding = host.bind();
    let artifact = host
        .evidence
        .artifact(host.project.project_id, excluded_content)
        .unwrap();
    let path = run.workspace.path().join(&artifact.relative_path);
    assert_eq!(Digest::of(&fs::read(&path).unwrap()), artifact.sha256);
    fs::write(&path, b"public fixture deliberately corrupted after import").unwrap();
    assert_eq!(
        host.evidence
            .verify_artifact(host.project.project_id, excluded_content)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    let result = host.success(
        &binding,
        "context.read",
        &json!({"kind": "memory_examples", "record_id": binding.session_id()}),
    );
    let output = host.output(&result);
    exact_keys(&output, &["record_ref", "schema_version"]);
    let record_ref: EntityId = serde_json::from_value(output["record_ref"].clone()).unwrap();
    let bytes = host
        .evidence
        .read_artifact(host.project.project_id, record_ref, 2_097_152)
        .unwrap();
    let context: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(contains_value(
        &context,
        &memory["record"]["fields"]["memory_id"]
    ));
    assert!(contains_value(
        &context,
        &user_memory["record"]["fields"]["memory_id"]
    ));
    for id in excluded_ids {
        assert!(!contains_value(&context, &json!(id)));
    }
    assert!(!contains_value(&context, &json!(excluded_content)));
    assert_no_authority_context(&context);
}

#[test]
fn two_trusted_bindings_receive_equivalent_strict_input_denials_without_secret_body_publication() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    assert_ne!(bindings[0].binding_id(), bindings[1].binding_id());
    for binding in &bindings {
        host.success(binding, "traffic.snapshot.read", &host.snapshot_input(0, 4));
    }
    let budget = host.ledger.read_budget(host.budget).unwrap();
    let sentinel = "synthetic-untrusted-secret-body-never-persist-me";
    let mut unknown = host.snapshot_input(0, 4);
    unknown["secret"] = json!(sentinel);
    let mut guest_grant = host.snapshot_input(0, 4);
    guest_grant["grant_id"] = json!(EntityId::new());
    let mut forged_digest = host.snapshot_input(0, 4);
    forged_digest["input_sha256"] = json!(Digest::of(b"caller claim"));
    let mut missing = host.snapshot_input(0, 4);
    missing.as_object_mut().unwrap().remove("revision");
    let duplicate = format!(
        "{{\"snapshot_id\":\"{}\",\"revision\":1,\"offset\":0,\"offset\":1,\"max_bytes\":4}}",
        host.snapshot.snapshot_id
    );
    let mut long_title = host.proposal_input();
    long_title["title"] = json!("é".repeat(129));
    let mut reversed = host.proposal_input();
    reversed["range_start"] = json!(4);
    reversed["range_end"] = json!(3);
    let mut oversized_rule = host.proposal_input();
    oversized_rule["rule_id"] = json!("x".repeat(129));
    let cases = vec![
        ("traffic.snapshot.read", unknown.to_string()),
        ("traffic.snapshot.read", guest_grant.to_string()),
        ("traffic.snapshot.read", forged_digest.to_string()),
        ("traffic.snapshot.read", missing.to_string()),
        ("traffic.snapshot.read", duplicate),
        ("traffic.snapshot.read", json!({"snapshot_id": host.snapshot.snapshot_id, "revision": 1, "offset": -1, "max_bytes": 4}).to_string()),
        ("traffic.snapshot.read", json!({"snapshot_id": host.snapshot.snapshot_id, "revision": 1, "offset": 0.5, "max_bytes": 4}).to_string()),
        ("observation.propose", long_title.to_string()),
        ("observation.propose", reversed.to_string()),
        ("observation.propose", oversized_rule.to_string()),
        ("context.read", json!({"kind": "canonical_grants", "record_id": host.session.session_id}).to_string()),
        ("context.read", json!({"kind": "investigation", "record_id": host.session.investigation_id, "path": sentinel}).to_string()),
    ];
    for (tool, input) in cases {
        let mut invocation_ids = Vec::new();
        for binding in &bindings {
            let result = host.execute_raw(binding, tool, &input);
            host.assert_denial(binding, &result, ErrorCode::InvalidInput);
            assert_eq!(result.state, InvocationState::Rejected);
            let stored = host.ledger.read_invocation(result.invocation_id).unwrap();
            assert!(stored.invocation.grant_id.is_none());
            let bytes = host
                .evidence
                .read_artifact(host.project.project_id, stored.invocation.input_ref, 65_536)
                .unwrap();
            assert!(
                bytes.len() <= 1024,
                "rejected bodies are reduced to bounded safe metadata"
            );
            let metadata: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(contains_value(
                &metadata,
                &json!(Digest::of(input.as_bytes()))
            ));
            assert!(contains_value(&metadata, &json!("invalid_input")));
            assert_eq!(
                host.evidence
                    .artifact(host.project.project_id, stored.invocation.input_ref)
                    .unwrap()
                    .origin_invocation_id,
                result.invocation_id
            );
            assert!(!String::from_utf8_lossy(&bytes).contains(sentinel));
            assert!(!serde_json::to_string(&result).unwrap().contains(sentinel));
            invocation_ids.push(result.invocation_id);
        }
        assert_ne!(invocation_ids[0], invocation_ids[1]);
    }
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    // Safe rejection metadata, outbox, and stored errors must not retain the rejected secret body.
    for artifact in host.evidence.artifacts().unwrap() {
        let bytes = host
            .evidence
            .read_artifact(artifact.project_id, artifact.artifact_id, 2_097_152)
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(sentinel));
    }
    assert!(
        !serde_json::to_string(&host.ledger.outbox(256).unwrap())
            .unwrap()
            .contains(sentinel)
    );
}

#[test]
fn request_envelope_rejects_unknown_fields_duplicates_and_unsupported_versions_before_preparation()
{
    let call_id = EntityId::new();
    let base = json!({"call_id": call_id, "tool_id": "context.read", "tool_version": "0.1.0",
        "input": {"kind": "investigation", "record_id": EntityId::new()}, "source_control_revision": 0});
    let valid = base.to_string();
    assert!(serde_json::from_str::<ToolRequest<'_>>(&valid).is_ok());
    for (field, value) in [
        ("tool_version", json!("0.2.0")),
        ("schema_version", json!("0.1.0")),
        ("grant_id", json!(EntityId::new())),
        ("provider_digest", json!(Digest::of(b"peer"))),
    ] {
        let mut invalid = base.clone();
        invalid[field] = value;
        assert!(serde_json::from_str::<ToolRequest<'_>>(&invalid.to_string()).is_err());
    }
    let duplicate = valid.replacen(
        "\"call_id\":",
        &format!("\"call_id\":\"{call_id}\",\"call_id\":"),
        1,
    );
    assert!(serde_json::from_str::<ToolRequest<'_>>(&duplicate).is_err());
}

#[test]
fn actual_existing_foreign_and_stale_snapshots_and_out_of_bounds_reads_never_become_empty_success()
{
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    host.success(
        &bindings[0],
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let public = fixtures().body(host.snapshot.body_ref).unwrap().to_vec();
    let foreign_project = EntityId::new();
    let foreign_artifact = host
        .evidence
        .write_artifact(
            foreign_project,
            catalog("public-binary"),
            EntityId::new(),
            &public,
            RedactionStatus::Original,
        )
        .unwrap();
    let mut foreign = host.snapshot.clone();
    foreign.project_id = foreign_project;
    foreign.snapshot_id = EntityId::new();
    foreign.body_ref = foreign_artifact.artifact_id;
    host.evidence.install_snapshot(foreign.clone()).unwrap();
    assert_eq!(
        host.evidence
            .snapshot_reader(foreign_project, foreign.snapshot_id, foreign.revision)
            .unwrap()
            .read(WireInt::ZERO, wire(65_536))
            .unwrap(),
        public
    );
    let budget = host.ledger.read_budget(host.budget).unwrap();
    for binding in &bindings {
        let mut input = host.snapshot_input(0, 4);
        input["snapshot_id"] = json!(foreign.snapshot_id);
        let result = host.execute_raw(binding, "traffic.snapshot.read", &input.to_string());
        host.assert_denial(binding, &result, ErrorCode::PermissionDenied);
        input = host.snapshot_input(0, 4);
        input["revision"] = json!(host.snapshot.revision.get() + 1);
        let result = host.execute_raw(binding, "traffic.snapshot.read", &input.to_string());
        host.assert_denial(binding, &result, ErrorCode::StaleSnapshot);
        for input in [
            host.snapshot_input(public.len() as u64 + 1, 4),
            host.snapshot_input(0, 65_537),
        ] {
            let result = host.execute_raw(binding, "traffic.snapshot.read", &input.to_string());
            host.assert_denial(binding, &result, ErrorCode::InvalidInput);
        }
        let mut proposal = host.proposal_input();
        proposal["range_end"] = json!(public.len() + 1);
        let result = host.execute_raw(binding, "observation.propose", &proposal.to_string());
        host.assert_denial(binding, &result, ErrorCode::InvalidInput);
        proposal = host.proposal_input();
        proposal["snapshot_id"] = json!(foreign.snapshot_id);
        let result = host.execute_raw(binding, "observation.propose", &proposal.to_string());
        host.assert_denial(binding, &result, ErrorCode::PermissionDenied);
        proposal = host.proposal_input();
        proposal["revision"] = json!(host.snapshot.revision.get() + 1);
        let result = host.execute_raw(binding, "observation.propose", &proposal.to_string());
        host.assert_denial(binding, &result, ErrorCode::StaleSnapshot);
    }
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    let project = host.project.project_id;
    drop(host);
    assert!(
        EvidenceStore::open(Arc::clone(&run.workspace))
            .unwrap()
            .proposals(project)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_approval_is_explicit_and_peer_grant_fields_cannot_authorize_local_effects() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    host.success(
        &bindings[0],
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let input = host.proposal_input();
    let budget = host.ledger.read_budget(host.budget).unwrap();
    for binding in &bindings {
        let prepared = host.prepare(binding, EntityId::new(), "observation.propose", &input);
        let result = host.registry.execute_prepared(binding, prepared).unwrap();
        host.assert_denial(binding, &result, ErrorCode::ApprovalRequired);
        assert_eq!(result.state, InvocationState::WaitingApproval);
        assert!(
            host.ledger
                .read_invocation(result.invocation_id)
                .unwrap()
                .invocation
                .grant_id
                .is_none()
        );
        let mut forged = input.clone();
        forged["grant_id"] = json!(EntityId::new());
        let result = host.execute_raw(binding, "observation.propose", &forged.to_string());
        host.assert_denial(binding, &result, ErrorCode::InvalidInput);
    }
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    let project = host.project.project_id;
    drop(host);
    assert!(
        EvidenceStore::open(Arc::clone(&run.workspace))
            .unwrap()
            .proposals(project)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unavailable_network_provider_is_explicit_and_unknown_tools_never_become_success_stubs() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    host.success(
        &bindings[0],
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let budget = host.ledger.read_budget(host.budget).unwrap();
    for binding in &bindings {
        assert!(host.ledger.read_tool(&catalog("http.send")).is_err());
        let input = json!({"request_snapshot_id": host.snapshot.snapshot_id,
            "base_revision": host.snapshot.revision, "identity_id": host.identity.identity_id});
        let result = host.execute_raw(binding, "http.send", &input.to_string());
        host.assert_denial(binding, &result, ErrorCode::ProviderUnavailable);
        assert_eq!(result.state, InvocationState::Rejected);
        // The independent model port is not an invented registry tool.
        for tool in ["unreviewed.arbitrary", "model.generate"] {
            let result = host.execute_raw(binding, tool, "{}");
            host.assert_denial(binding, &result, ErrorCode::UnknownTool);
        }
    }
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn same_call_uuid_is_distinct_between_bindings_and_duplicate_delivery_never_charges_or_proposes_twice()
 {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    assert_ne!(bindings[0].binding_id(), bindings[1].binding_id());
    let call_id = EntityId::new();
    let input = host.proposal_input();
    let before = host.ledger.read_budget(host.budget).unwrap();
    let mut results = Vec::new();
    for binding in &bindings {
        let prepared = host.prepare(binding, call_id, "observation.propose", &input);
        host.approve(binding, &prepared);
        let result = host.registry.execute_prepared(binding, prepared).unwrap();
        host.assert_success(binding, &result);
        let budget = host.ledger.read_budget(host.budget).unwrap();
        let count = host
            .evidence
            .proposals(host.project.project_id)
            .unwrap()
            .len();
        let artifacts = host.evidence.artifacts().unwrap().len();
        let duplicate_prepared = host.prepare(binding, call_id, "observation.propose", &input);
        let original = host
            .ledger
            .read_invocation(result.invocation_id)
            .unwrap()
            .invocation;
        assert_eq!(
            duplicate_prepared.call().invocation_id,
            original.invocation_id
        );
        assert_eq!(duplicate_prepared.call().input_ref, original.input_ref);
        assert_eq!(host.evidence.artifacts().unwrap().len(), artifacts);
        let duplicate = host
            .registry
            .execute_prepared(binding, duplicate_prepared)
            .unwrap();
        assert_eq!(json!(duplicate), json!(result));
        let raw = RawValue::from_string(input.to_string()).unwrap();
        let duplicate = host
            .registry
            .execute(
                binding,
                &request(
                    call_id,
                    "observation.propose",
                    &raw,
                    binding.control_revision(),
                ),
            )
            .unwrap();
        assert_eq!(json!(duplicate), json!(result));
        assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
        assert_eq!(
            host.evidence
                .proposals(host.project.project_id)
                .unwrap()
                .len(),
            count
        );
        assert_eq!(
            host.evidence.artifacts().unwrap().len(),
            artifacts,
            "duplicates cannot leave orphan input artifacts"
        );
        results.push(result);
    }
    assert_ne!(results[0].invocation_id, results[1].invocation_id);
    assert_ne!(results[0].output_ref, results[1].output_ref);
    let invocations = host.ledger.invocations().unwrap();
    assert_eq!(invocations.len(), 2);
    assert_ne!(
        invocations[0].invocation.deduplication_key,
        invocations[1].invocation.deduplication_key
    );
    let after = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(
        after.consumed.get() - before.consumed.get(),
        results.iter().map(|r| r.usage.units.get()).sum::<u64>()
    );
    let project = host.project.project_id;
    drop(host);
    let reopened = EvidenceStore::open(Arc::clone(&run.workspace)).unwrap();
    assert_eq!(reopened.proposals(project).unwrap().len(), 2);
    let ledger = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(ledger.read_budget(after.budget_id).unwrap(), after);
    assert_eq!(ledger.invocations().unwrap().len(), 2);
}

#[test]
fn revoked_grant_between_prepare_and_dispatch_denies_the_actual_provider() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    host.success(
        &binding,
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let prepared = host.prepare(
        &binding,
        EntityId::new(),
        "observation.propose",
        &host.proposal_input(),
    );
    let grant = host.approve(&binding, &prepared);
    host.ledger.revoke_grant(grant).unwrap();
    let before = host.ledger.read_budget(host.budget).unwrap();
    let result = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_denial(&binding, &result, ErrorCode::ApprovalRequired);
    assert_eq!(result.state, InvocationState::WaitingApproval);
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), before);
}

#[test]
fn actual_shared_control_barrier_denies_all_stale_proposals_and_reopen_proves_zero_effects() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    let healthy: Vec<_> = bindings
        .iter()
        .map(|binding| host.success(binding, "traffic.snapshot.read", &host.snapshot_input(0, 4)))
        .collect();
    let before = host.ledger.read_budget(host.budget).unwrap();
    let mut calls = Vec::new();
    for binding in &bindings {
        let mut prepared_calls = Vec::new();
        for index in 0..8 {
            let mut input = host.proposal_input();
            input["title"] = json!(format!("Public proposal prepared before barrier {index}"));
            let prepared = host.prepare(binding, EntityId::new(), "observation.propose", &input);
            host.approve(binding, &prepared);
            if index == 0 {
                assert_eq!(
                    host.admission
                        .reserve(binding, prepared.call())
                        .unwrap()
                        .state,
                    InvocationState::Reserved
                );
            }
            prepared_calls.push(prepared);
        }
        calls.push(prepared_calls);
    }
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    let server =
        ControlServer::start(Arc::clone(&run.workspace), Arc::clone(&host.control)).unwrap();
    let client = ControlClient::new(&run.workspace).unwrap();
    let started = Instant::now();
    let ack = client
        .request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: host.session.investigation_id,
            expected_revision: WireInt::ZERO,
            action: ControlAction::Pause,
        })
        .unwrap();
    assert!(
        started.elapsed()
            < Duration::from_millis(run.profile.config().control.ack_deadline_ms.get())
    );
    assert_eq!(ack.measurement.late_admissions, WireInt::ZERO);
    assert_eq!(ack.state.revision, wire(1));
    assert!(!ack.state.admission_open);
    for (binding, prepared_calls) in bindings.iter().zip(calls) {
        for prepared in prepared_calls {
            let id = prepared.call().invocation_id;
            let result = host.registry.execute_prepared(binding, prepared).unwrap();
            assert_eq!(result.invocation_id, id);
            assert!(result.error.is_some());
            assert!(result.output_ref.is_none());
            let stored = host.ledger.read_invocation(id).unwrap();
            assert!(
                ![
                    InvocationState::Reserved,
                    InvocationState::Sending,
                    InvocationState::Completed
                ]
                .contains(&stored.invocation.state)
            );
            assert_eq!(stored.reserved_units, WireInt::ZERO);
        }
        // A peer cannot freshen an old trusted binding by copying the acknowledged revision.
        let raw = RawValue::from_string(host.proposal_input().to_string()).unwrap();
        let result = host
            .registry
            .execute(
                binding,
                &request(EntityId::new(), "observation.propose", &raw, wire(1)),
            )
            .unwrap();
        assert!(result.error.is_some());
        assert!(result.output_ref.is_none());
    }
    for (binding, completed) in bindings.iter().zip(&healthy) {
        let raw = RawValue::from_string(host.snapshot_input(0, 4).to_string()).unwrap();
        let duplicate = host
            .registry
            .execute(
                binding,
                &request(
                    completed.call_id,
                    "traffic.snapshot.read",
                    &raw,
                    WireInt::ZERO,
                ),
            )
            .unwrap();
        assert_eq!(
            json!(duplicate),
            json!(completed),
            "barriers prevent new effects, not retention of admitted historical results"
        );
    }
    client
        .request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: host.session.investigation_id,
            expected_revision: wire(1),
            action: ControlAction::Resume,
        })
        .unwrap();
    for binding in &bindings {
        let raw = RawValue::from_string(host.proposal_input().to_string()).unwrap();
        let result = host
            .registry
            .execute(
                binding,
                &request(EntityId::new(), "observation.propose", &raw, wire(2)),
            )
            .unwrap();
        assert!(result.error.is_some());
        assert!(result.output_ref.is_none());
    }
    let fresh = host.bind();
    assert_eq!(fresh.control_revision(), wire(2));
    let context = host.success(
        &fresh,
        "context.read",
        &json!({"kind": "investigation", "record_id": host.session.investigation_id}),
    );
    let record_ref: EntityId =
        serde_json::from_value(host.output(&context)["record_ref"].clone()).unwrap();
    let record: Value = serde_json::from_slice(
        &host
            .evidence
            .read_artifact(host.project.project_id, record_ref, 2_097_152)
            .unwrap(),
    )
    .unwrap();
    let canonical = host
        .ledger
        .read_session(host.session.session_id)
        .unwrap()
        .session;
    assert_eq!(canonical.control_revision, wire(2));
    assert!(contains_value(&record, &json!(canonical)));
    let after = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(after.reserved, WireInt::ZERO);
    assert_eq!(
        after.consumed.get(),
        before.consumed.get() + context.usage.units.get()
    );
    let project = host.project.project_id;
    server.shutdown().unwrap();
    drop(client);
    drop(host);
    let reopened = EvidenceStore::open(Arc::clone(&run.workspace)).unwrap();
    assert!(
        reopened.proposals(project).unwrap().is_empty(),
        "actual persistent provider effects, not a counter, remain zero"
    );
    let ledger = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(ledger.read_budget(after.budget_id).unwrap(), after);
    assert_eq!(
        ledger
            .read_control(canonical.investigation_id)
            .unwrap()
            .revision,
        wire(2)
    );
}

#[test]
fn large_public_binary_chunk_reports_measured_cpu_elapsed_and_real_exposed_bytes() {
    let run = Run::new();
    let mut host = Host::new(&run, fixtures());
    let public = fixtures().body(host.snapshot.body_ref).unwrap().to_vec();
    let bytes = public.repeat(8192);
    let artifact = host
        .evidence
        .write_artifact(
            host.project.project_id,
            catalog("public-binary"),
            EntityId::new(),
            &bytes,
            RedactionStatus::Original,
        )
        .unwrap();
    let mut snapshot = host.snapshot.clone();
    snapshot.snapshot_id = EntityId::new();
    snapshot.body_ref = artifact.artifact_id;
    snapshot.sha256 = artifact.sha256;
    snapshot.length_bytes = artifact.length_bytes;
    for header in &mut snapshot.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            header.value = bytes.len().to_string();
        }
    }
    host.snapshot = (*host.evidence.install_snapshot(snapshot).unwrap()).clone();
    let binding = host.bind();
    let cpu_before = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let started = Instant::now();
    let result = host.success(
        &binding,
        "traffic.snapshot.read",
        &host.snapshot_input(0, 65_536),
    );
    let elapsed = started.elapsed();
    let cpu_after = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let cpu_ns = (i128::from(cpu_after.tv_sec) - i128::from(cpu_before.tv_sec)) * 1_000_000_000
        + i128::from(cpu_after.tv_nsec)
        - i128::from(cpu_before.tv_nsec);
    assert!(
        result.usage.cpu_us.get() > 0,
        "actual encoding/file-provider work must not report an invented zero CPU sample"
    );
    assert!(i128::from(result.usage.cpu_us.get()) <= cpu_ns / 1000 + 2);
    assert!(result.usage.elapsed_us.get() > 0);
    assert!(u128::from(result.usage.elapsed_us.get()) <= elapsed.as_micros());
    assert!(result.usage.bytes.get() >= 65_536);
    let output_bytes = host
        .evidence
        .read_artifact(
            host.project.project_id,
            result.output_ref.unwrap(),
            run.profile
                .config()
                .protocol
                .invocation_output_limit_bytes
                .get() as usize,
        )
        .unwrap();
    let output: Value = serde_json::from_slice(&output_bytes).unwrap();
    assert_eq!(
        STANDARD
            .decode(output["bytes_base64"].as_str().unwrap())
            .unwrap(),
        bytes[..65_536]
    );
    assert_eq!(output["eof"], false);
}

#[test]
fn context_identifiers_never_authorize_another_real_canonical_session() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let mut other_session = host.session.clone();
    other_session.session_id = EntityId::new();
    other_session.investigation_id = EntityId::new();
    other_session.goal = "Another actual canonical session owned by the same user".into();
    let state: ControlState = serde_json::from_value(json!({
        "investigation_id": other_session.investigation_id, "revision": 0,
        "mode": "running", "admission_open": true, "instruction_ref": EntityId::new()
    }))
    .unwrap();
    host.ledger
        .insert_control(
            &state,
            host.project.project_id,
            host.ledger
                .read_scope(host.project.scope_policy_id)
                .unwrap()
                .revision,
        )
        .unwrap();
    host.ledger
        .insert_session(&other_session, host.project.project_id)
        .unwrap();
    // ControlService was constructed before this second session; reconstruct it from the
    // same persistent ledger, rather than inventing a control gate for the second binding.
    let control = Arc::new(
        ControlService::new(
            Arc::clone(&host.ledger),
            &run.profile,
            host.session.investigation_id,
        )
        .unwrap(),
    );
    let admission = Arc::new(HostAdmission::new(Arc::clone(&host.ledger), control));
    let registry = Registry::new(
        Arc::clone(&admission),
        Arc::clone(&host.evidence),
        fixtures(),
        &run.profile,
    )
    .unwrap();
    let bind = |session: &InvestigationSession| {
        admission
            .bind(BindingSpec {
                user_id: host.project.user_id,
                project_id: host.project.project_id,
                investigation_id: session.investigation_id,
                session_id: session.session_id,
                identity_id: host.identity.identity_id,
                budget_id: host.budget,
                provider_digest: host.provider,
                allowed_tools: host
                    .tools
                    .iter()
                    .map(|t| t.descriptor.tool_id.clone())
                    .collect(),
                permissions: host
                    .tools
                    .iter()
                    .flat_map(|t| t.descriptor.permissions.iter().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
            .map(Arc::new)
            .unwrap()
    };
    let bindings = [bind(&host.session), bind(&other_session)];
    for (binding, session, forbidden) in [
        (&bindings[0], &host.session, &other_session),
        (&bindings[1], &other_session, &host.session),
    ] {
        let raw = RawValue::from_string(
            json!({"kind": "investigation", "record_id": session.investigation_id}).to_string(),
        )
        .unwrap();
        let prepared = registry
            .prepare(
                binding,
                &request(EntityId::new(), "context.read", &raw, WireInt::ZERO),
            )
            .unwrap();
        host.approve(binding, &prepared);
        let result = registry.execute_prepared(binding, prepared).unwrap();
        host.assert_success(binding, &result);
        let budget = host.ledger.read_budget(host.budget).unwrap();
        for (kind, id) in [
            ("investigation", forbidden.investigation_id),
            ("memory_examples", forbidden.session_id),
        ] {
            let raw =
                RawValue::from_string(json!({"kind": kind, "record_id": id}).to_string()).unwrap();
            let result = registry
                .execute(
                    binding,
                    &request(EntityId::new(), "context.read", &raw, WireInt::ZERO),
                )
                .unwrap();
            host.assert_denial(binding, &result, ErrorCode::PermissionDenied);
        }
        assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    }
}

#[test]
fn concurrent_duplicate_preparations_dispatch_one_actual_proposal_and_charge_once() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let call_id = EntityId::new();
    let first = host.prepare(
        &binding,
        call_id,
        "observation.propose",
        &host.proposal_input(),
    );
    let second = host.prepare(
        &binding,
        call_id,
        "observation.propose",
        &host.proposal_input(),
    );
    host.approve(&binding, &first);
    assert_eq!(first.call().input_sha256, second.call().input_sha256);
    let before = host.ledger.read_budget(host.budget).unwrap();
    let start = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let registry = &host.registry;
        let binding = &binding;
        let start = &start;
        let first = scope.spawn(move || {
            start.wait();
            registry.execute_prepared(binding, first).unwrap()
        });
        let second = scope.spawn(move || {
            start.wait();
            registry.execute_prepared(binding, second).unwrap()
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    let stored = host.ledger.invocations().unwrap();
    assert_eq!(stored.len(), 1);
    let invocation = &stored[0].invocation;
    assert_eq!(invocation.state, InvocationState::Completed);
    for result in results {
        assert_eq!(result.invocation_id, invocation.invocation_id);
    }
    assert_eq!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .len(),
        1
    );
    let after = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(
        after.consumed.get() - before.consumed.get(),
        invocation.usage.units.get()
    );
    assert_eq!(after.reserved, WireInt::ZERO);
    let project = host.project.project_id;
    drop(host);
    assert_eq!(
        EvidenceStore::open(Arc::clone(&run.workspace))
            .unwrap()
            .proposals(project)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn changed_actual_snapshot_bytes_after_prepare_fail_closed_without_a_proposal_or_success_artifact()
{
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    host.success(
        &binding,
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let prepared = host.prepare(
        &binding,
        EntityId::new(),
        "observation.propose",
        &host.proposal_input(),
    );
    let denied_after_corruption = host.prepare(
        &binding,
        EntityId::new(),
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let invocation_id = prepared.call().invocation_id;
    let before = host.ledger.read_budget(host.budget).unwrap();
    host.approve(&binding, &prepared);
    let artifact = host
        .evidence
        .artifact(host.project.project_id, host.snapshot.body_ref)
        .unwrap();
    let path = run.workspace.path().join(&artifact.relative_path);
    let mut bytes = fs::read(&path).unwrap();
    assert_eq!(Digest::of(&bytes), host.snapshot.sha256);
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
    let error = host
        .registry
        .execute_prepared(&binding, prepared)
        .unwrap_err();
    let stored = host.ledger.read_invocation(invocation_id).unwrap();
    // Fatal integrity loss cannot be turned into a fabricated committed failure.
    // Retain the last durable sending record and its full hold for reconciliation.
    assert_eq!(stored.invocation.state, InvocationState::Sending);
    assert_eq!(stored.history.last(), &stored.invocation);
    assert_eq!(stored.reserved_units, stored.requested.units);
    let after = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(after.consumed, before.consumed);
    assert_eq!(
        after.reserved,
        before.reserved.checked_add(stored.reserved_units).unwrap()
    );
    assert_eq!(
        host.admission.check_integrity().unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        host.admission
            .reserve(&binding, denied_after_corruption.call())
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        host.registry
            .execute_prepared(&binding, denied_after_corruption)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        !host
            .ledger
            .invocations()
            .unwrap()
            .iter()
            .any(
                |row| row.invocation.tool_id == catalog("observation.propose")
                    && (row.invocation.state == InvocationState::Completed
                        || row.invocation.output_ref.is_some())
            )
    );
}

#[test]
fn observation_exact_utf8_byte_boundaries_accept_real_proposals_without_truncating_titles() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let mut input = host.proposal_input();
    input["title"] = json!("é".repeat(128));
    input["rule_id"] = json!("r".repeat(128));
    let result = host.success(&binding, "observation.propose", &input);
    let proposal_id: EntityId =
        serde_json::from_value(host.output(&result)["proposal_id"].clone()).unwrap();
    let proposal = host
        .evidence
        .proposal(host.project.project_id, proposal_id)
        .unwrap();
    assert_eq!(proposal.title, "é".repeat(128));
    assert_eq!(proposal.title.len(), 256);
    assert_eq!(proposal.rule_id.to_string().len(), 128);
}

#[test]
fn changed_metadata_for_completed_same_binding_call_uuid_is_an_error_without_rewriting_history() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let input = host.proposal_input();
    let prepared = host.prepare(&binding, EntityId::new(), "observation.propose", &input);
    let call_id = prepared.call().call_id;
    host.approve(&binding, &prepared);
    let completed = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_success(&binding, &completed);
    let stored = host
        .ledger
        .read_invocation(completed.invocation_id)
        .unwrap();
    let artifacts = host.evidence.artifacts().unwrap().len();
    let budget = host.ledger.read_budget(host.budget).unwrap();
    let mut changed = input.clone();
    changed["title"] = json!("A different but valid public proposal");
    for (tool, input, revision) in [
        ("observation.propose", changed, WireInt::ZERO),
        (
            "context.read",
            json!({"kind": "investigation", "record_id": binding.investigation_id()}),
            WireInt::ZERO,
        ),
        ("observation.propose", input, wire(1)),
    ] {
        let raw = RawValue::from_string(input.to_string()).unwrap();
        let error = host
            .registry
            .execute(&binding, &request(call_id, tool, &raw, revision))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        let current = host
            .ledger
            .read_invocation(completed.invocation_id)
            .unwrap();
        assert_eq!(current.invocation, stored.invocation);
        assert_eq!(
            current.history.event_sequence(),
            stored.history.event_sequence()
        );
        assert_eq!(host.ledger.invocations().unwrap().len(), 1);
        assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
        assert_eq!(host.evidence.artifacts().unwrap().len(), artifacts);
        assert_eq!(
            host.evidence
                .proposals(host.project.project_id)
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn prepared_invocation_cannot_be_retargeted_to_another_trusted_binding() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let bindings = [host.bind(), host.bind()];
    let input = host.proposal_input();
    let call_id = EntityId::new();
    let prepared = host.prepare(&bindings[0], call_id, "observation.propose", &input);
    host.approve(&bindings[0], &prepared);
    let before = host.ledger.read_budget(host.budget).unwrap();
    let artifact_count = host.evidence.artifacts().unwrap().len();
    let error = host
        .registry
        .execute_prepared(&bindings[1], prepared)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        host.ledger.invocations().unwrap()[0].invocation.state,
        InvocationState::Proposed
    );
    assert!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), before);
    assert_eq!(host.evidence.artifacts().unwrap().len(), artifact_count);
    let prepared = host.prepare(&bindings[0], call_id, "observation.propose", &input);
    let completed = host
        .registry
        .execute_prepared(&bindings[0], prepared)
        .unwrap();
    host.assert_success(&bindings[0], &completed);
    assert_eq!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn identical_rejected_delivery_returns_canonical_denial_without_another_metadata_artifact() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    host.success(
        &binding,
        "traffic.snapshot.read",
        &host.snapshot_input(0, 4),
    );
    let mut stale = host.snapshot_input(0, 4);
    stale["revision"] = json!(host.snapshot.revision.get() + 1);
    let mut unknown_field = host.snapshot_input(0, 4);
    unknown_field["grant_id"] = json!(EntityId::new());
    for (input, code) in [
        (stale, ErrorCode::StaleSnapshot),
        (unknown_field, ErrorCode::InvalidInput),
    ] {
        let raw = RawValue::from_string(input.to_string()).unwrap();
        let call_id = EntityId::new();
        let request = request(
            call_id,
            "traffic.snapshot.read",
            &raw,
            binding.control_revision(),
        );
        let rejected = host.registry.execute(&binding, &request).unwrap();
        host.assert_denial(&binding, &rejected, code);
        let artifact_count = host.evidence.artifacts().unwrap().len();
        let invocation_count = host.ledger.invocations().unwrap().len();
        let budget = host.ledger.read_budget(host.budget).unwrap();
        let repeated = host.registry.execute(&binding, &request).unwrap();
        assert_eq!(json!(repeated), json!(rejected));
        assert_eq!(host.evidence.artifacts().unwrap().len(), artifact_count);
        assert_eq!(host.ledger.invocations().unwrap().len(), invocation_count);
        assert_eq!(host.ledger.read_budget(host.budget).unwrap(), budget);
    }
}

#[test]
fn explicit_preparation_approval_and_request_delivery_keep_one_canonical_input_origin() {
    let run = Run::new();
    let host = Host::new(&run, fixtures());
    let binding = host.bind();
    let call_id = EntityId::new();
    let input = host.proposal_input();
    let prepared = host.prepare(&binding, call_id, "observation.propose", &input);
    let invocation_id = prepared.call().invocation_id;
    let input_ref = prepared.call().input_ref;
    host.approve(&binding, &prepared);
    drop(prepared);
    let raw = RawValue::from_string(input.to_string()).unwrap();
    let delivered = host
        .registry
        .execute(
            &binding,
            &request(
                call_id,
                "observation.propose",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.assert_success(&binding, &delivered);
    assert_eq!(delivered.invocation_id, invocation_id);
    let canonical = host.ledger.read_invocation(invocation_id).unwrap();
    assert_eq!(canonical.invocation.input_ref, input_ref);
    let inputs: Vec<_> = host
        .evidence
        .artifacts()
        .unwrap()
        .into_iter()
        .filter(|artifact| {
            artifact.kind.as_str() == "tool-input" && artifact.origin_invocation_id == invocation_id
        })
        .collect();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].artifact_id, input_ref);
    assert_eq!(
        inputs[0].origin_invocation_id,
        canonical.invocation.invocation_id
    );
    assert_eq!(
        host.evidence
            .proposals(host.project.project_id)
            .unwrap()
            .len(),
        1
    );
}

#[path = "support/registry_receiver.rs"]
mod registry_receiver;

fn network_host(run: &Run, receiver: &registry_receiver::Receiver) -> Host {
    use razen_engine::domain::authority::{DestinationRule, PathKind, PathRule, Scheme};
    let mut host = Host::new(run, fixtures());
    let mut scope = host
        .ledger
        .read_scope(host.project.scope_policy_id)
        .unwrap();
    let previous = scope.revision;
    scope.revision = previous.checked_add(wire(1)).unwrap();
    scope.allowed_destinations = vec![DestinationRule {
        scheme: Scheme::Http,
        host: "registry.razen.invalid".to_owned(),
        port: receiver.address.port(),
        path: PathRule {
            kind: PathKind::Prefix,
            value: "/".to_owned(),
        },
        resolved_addresses: vec![receiver.address.ip()],
    }];
    scope.exclusions.clear();
    host.ledger.replace_scope(&scope, previous).unwrap();
    let tool =
        razen_engine::application::http_send::registered_tool(host.provider, &run.profile).unwrap();
    host.ledger.insert_tool(&tool).unwrap();
    host.tools.push(tool);
    host.registry = network_registry(run, &host);
    host
}

fn network_registry(run: &Run, host: &Host) -> Registry {
    network_registry_with_secret(run, host, None)
}

fn network_registry_with_secret(
    run: &Run,
    host: &Host,
    secret: Option<(EntityId, Vec<razen_engine::domain::evidence::Header>)>,
) -> Registry {
    use razen_engine::adapters::transport::{
        Mode, TransportConfig,
        scope_connector::{FixtureZone, Resolver},
    };
    use razen_engine::application::http_send::HttpSendProvider;
    let zone = Arc::new(FixtureZone::default());
    zone.publish("registry.razen.invalid", vec!["127.0.0.1".parse().unwrap()])
        .unwrap();
    let roots = Arc::new(rustls::RootCertStore::empty());
    let provider = HttpSendProvider::new(
        Arc::clone(&host.admission),
        Arc::clone(&host.evidence),
        &run.profile,
        TransportConfig {
            mode: Mode::Http1Forward,
            resolver: Resolver::Fixture(zone),
            upstream_roots: Arc::clone(&roots),
            client_roots: roots,
            ingress_tls: None,
            tls_server_name: None,
            connect_authority: None,
        },
    )
    .unwrap();
    let provider = match secret {
        Some((identity, headers)) => provider.with_secret_headers(identity, headers).unwrap(),
        None => provider,
    };
    Registry::with_http(
        Arc::clone(&host.admission),
        Arc::clone(&host.evidence),
        fixtures(),
        &run.profile,
        provider,
    )
    .unwrap()
}

fn network_request(
    host: &Host,
    receiver: &registry_receiver::Receiver,
) -> razen_engine::application::http_send::RequestSnapshot {
    use razen_engine::domain::evidence::Header;
    razen_engine::application::http_send::RequestSnapshot {
        body_snapshot_id: host.snapshot.snapshot_id,
        body_revision: host.snapshot.revision,
        url: format!(
            "http://registry.razen.invalid:{}/echo",
            receiver.address.port()
        ),
        method: "POST".into(),
        headers: vec![Header {
            name: "host".into(),
            value: format!("registry.razen.invalid:{}", receiver.address.port()),
        }],
        request_count: wire(1),
        reset_first_stream: false,
    }
}

fn publish_network_input(
    host: &Host,
    descriptor: razen_engine::application::http_send::RequestSnapshot,
) -> Box<RawValue> {
    let input = razen_engine::application::http_send::install_request(
        &host.evidence,
        &host.bind(),
        EntityId::new(),
        descriptor,
    )
    .unwrap();
    RawValue::from_string(serde_json::to_string(&input).unwrap()).unwrap()
}

fn network_input(host: &Host, receiver: &registry_receiver::Receiver) -> Box<RawValue> {
    publish_network_input(host, network_request(host, receiver))
}

fn make_request_body_unavailable(host: &Host, run: &Run) {
    let artifact = host
        .evidence
        .artifact(host.project.project_id, host.snapshot.body_ref)
        .unwrap();
    let path = run.workspace.path().join(&artifact.relative_path);
    fs::rename(&path, path.with_extension("retained-for-cleanup")).unwrap();
    assert_eq!(
        fs::read(&path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn http_registry_transfers_real_body_and_exact_duplicate_returns_history_without_charge() {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let request = request(
        EntityId::new(),
        "http.send",
        &raw,
        binding.control_revision(),
    );
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    let grant = host.approve(&binding, &prepared);
    let before = host.ledger.read_budget(host.budget).unwrap();
    let first = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_success(&binding, &first);
    let output = host.output(&first);
    exact_keys(
        &output,
        &["exchange_ref", "response_snapshot_ref", "timing_ref"],
    );
    let public: razen_engine::application::http_send::HttpSendOutput =
        serde_json::from_value(output).unwrap();
    let exchange_artifact = host
        .evidence
        .artifact(host.project.project_id, public.exchange_ref)
        .unwrap();
    assert_eq!(exchange_artifact.kind.as_str(), "http-send-result");
    assert_eq!(exchange_artifact.origin_invocation_id, first.invocation_id);
    let record: razen_engine::application::http_send::SendRecord = serde_json::from_slice(
        &host
            .evidence
            .read_artifact(host.project.project_id, public.exchange_ref, 2_097_152)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        record.exchanges.last().unwrap().response_snapshot_id,
        public.response_snapshot_ref
    );
    let snapshot = host
        .evidence
        .snapshot(
            host.project.project_id,
            public.response_snapshot_ref.unwrap(),
            WireInt::ZERO,
        )
        .unwrap();
    assert!(!snapshot.truncated);
    let timing_artifact = host
        .evidence
        .artifact(host.project.project_id, public.timing_ref)
        .unwrap();
    assert_eq!(timing_artifact.kind.as_str(), "http-send-timing");
    assert_eq!(timing_artifact.origin_invocation_id, first.invocation_id);
    let timing: razen_engine::application::http_send::HttpSendTiming = serde_json::from_slice(
        &host
            .evidence
            .read_artifact(host.project.project_id, public.timing_ref, 1024)
            .unwrap(),
    )
    .unwrap();
    assert!(timing.finished_us >= timing.started_us);
    assert_eq!(timing.network_elapsed_us, record.network_elapsed_us);
    assert!(timing.network_elapsed_us > 0);
    assert_eq!(receiver.count(), 1);
    let expected = host
        .evidence
        .snapshot_reader(
            host.project.project_id,
            host.snapshot.snapshot_id,
            host.snapshot.revision,
        )
        .unwrap()
        .read(WireInt::ZERO, host.snapshot.length_bytes)
        .unwrap();
    assert_eq!(receiver.bodies(), vec![expected]);
    let charged = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(charged.consumed.get() - before.consumed.get(), 1);
    host.ledger.revoke_grant(grant).unwrap();
    // Historical delivery must not reopen or allocate the original request body.
    make_request_body_unavailable(&host, &run);
    let duplicate = host.registry.execute(&binding, &request).unwrap();
    assert_eq!(
        serde_json::to_value(&duplicate).unwrap(),
        serde_json::to_value(&first).unwrap()
    );
    assert_eq!(receiver.count(), 1);
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), charged);
}

#[test]
fn http_registry_denies_unapproved_and_revoked_calls_before_receiver_effect() {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let unapproved = host
        .registry
        .execute(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.assert_denial(&binding, &unapproved, ErrorCode::ApprovalRequired);
    let prepared = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    let grant = host.approve(&binding, &prepared);
    host.ledger.revoke_grant(grant).unwrap();
    let denied = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_denial(&binding, &denied, ErrorCode::ApprovalRequired);
    assert_eq!(receiver.count(), 0);
    let healthy = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.approve(&binding, &healthy);
    host.assert_success(
        &binding,
        &host.registry.execute_prepared(&binding, healthy).unwrap(),
    );
    assert_eq!(
        receiver.count(),
        1,
        "denials must not rely on a broken receiver"
    );
}

#[test]
fn http_registry_prepared_call_cannot_move_binding_or_configuration_and_reused_id_cannot_change_input()
 {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let other_binding = host.bind();
    let other_registry = network_registry(&run, &host);
    let raw = network_input(&host, &receiver);
    let call_id = EntityId::new();
    let request = request(call_id, "http.send", &raw, binding.control_revision());
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    host.approve(&binding, &prepared);
    assert_eq!(
        host.registry
            .execute_prepared(&other_binding, prepared)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    assert_eq!(
        other_registry
            .execute_prepared(&binding, prepared)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        other_registry
            .prepare(&binding, &request)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    let mut changed = network_request(&host, &receiver);
    changed.method = "PUT".into();
    let changed = publish_network_input(&host, changed);
    let changed_request = ToolRequest {
        input: &changed,
        tool_id: request.tool_id.clone(),
        call_id,
        tool_version: request.tool_version,
        source_control_revision: request.source_control_revision,
    };
    assert_eq!(
        host.registry
            .prepare(&binding, &changed_request)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    let changed_revision = ToolRequest {
        source_control_revision: wire(1),
        tool_id: request.tool_id.clone(),
        call_id,
        tool_version: request.tool_version,
        input: request.input,
    };
    assert_eq!(
        host.registry
            .prepare(&binding, &changed_revision)
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(receiver.count(), 0);
    host.assert_success(
        &binding,
        &host.registry.execute(&binding, &request).unwrap(),
    );
    assert_eq!(receiver.count(), 1);
}

#[test]
fn http_registry_duplicate_while_sending_is_explicit_and_never_resends() {
    let receiver = registry_receiver::Receiver::start(false, true);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let request = request(
        EntityId::new(),
        "http.send",
        &raw,
        binding.control_revision(),
    );
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    host.approve(&binding, &prepared);
    let first = std::thread::scope(|scope| {
        let first = scope.spawn(|| host.registry.execute_prepared(&binding, prepared).unwrap());
        receiver.wait_for_effect();
        make_request_body_unavailable(&host, &run);
        let duplicate = host.registry.execute(&binding, &request).unwrap();
        assert_eq!(duplicate.state, InvocationState::Sending);
        assert_eq!(duplicate.output_ref, None);
        assert_eq!(receiver.count(), 1);
        receiver.release_response();
        first.join().unwrap()
    });
    host.assert_success(&binding, &first);
    assert_eq!(receiver.count(), 1);
    assert_eq!(
        host.ledger.read_budget(host.budget).unwrap().consumed,
        wire(1)
    );
}

#[test]
fn http_registry_lost_response_remains_unknown_and_duplicate_does_not_replay_post() {
    let receiver = registry_receiver::Receiver::start(true, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let request = request(
        EntityId::new(),
        "http.send",
        &raw,
        binding.control_revision(),
    );
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    host.approve(&binding, &prepared);
    let first = host.registry.execute_prepared(&binding, prepared).unwrap();
    assert_eq!(receiver.count(), 1);
    assert_eq!(first.state, InvocationState::OutcomeUnknown);
    assert_eq!(
        first.error.as_ref().unwrap().code,
        ErrorCode::OutcomeUnknown
    );
    assert!(first.output_ref.is_none());
    assert!(!host.evidence.artifacts().unwrap().iter().any(
        |artifact| artifact.origin_invocation_id == first.invocation_id
            && artifact.kind.as_str() == "http-send-output"
    ));
    let held = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(held.reserved, wire(1));
    make_request_body_unavailable(&host, &run);
    let duplicate = host.registry.execute(&binding, &request).unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(duplicate).unwrap()
    );
    assert_eq!(receiver.count(), 1);
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), held);
}

#[test]
fn http_registry_revocation_after_reservation_cancels_before_native_transfer() {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let prepared = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    let grant = host.approve(&binding, &prepared);
    assert_eq!(
        host.admission
            .reserve(&binding, prepared.call())
            .unwrap()
            .state,
        InvocationState::Reserved
    );
    host.ledger.revoke_grant(grant).unwrap();
    let cancelled = host.registry.execute_prepared(&binding, prepared).unwrap();
    assert_eq!(cancelled.state, InvocationState::Cancelled);
    assert_eq!(
        cancelled.error.as_ref().unwrap().code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(receiver.count(), 0);
    let budget = host.ledger.read_budget(host.budget).unwrap();
    assert_eq!(budget.consumed, WireInt::ZERO);
    assert_eq!(budget.reserved, WireInt::ZERO);
    let healthy = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.approve(&binding, &healthy);
    host.assert_success(
        &binding,
        &host.registry.execute_prepared(&binding, healthy).unwrap(),
    );
    assert_eq!(receiver.count(), 1);
}

#[test]
fn http_registry_peer_input_cannot_override_host_transport_configuration() {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    for key in [
        "mode",
        "resolver",
        "tls_server_name",
        "connect_authority",
        "upstream_roots",
        "provider_configuration_id",
        "binding_id",
        "grant_id",
        "control_revision",
    ] {
        let mut value: Value = serde_json::from_str(raw.get()).unwrap();
        value[key] = json!("peer-chosen");
        let value = RawValue::from_string(value.to_string()).unwrap();
        let request = request(
            EntityId::new(),
            "http.send",
            &value,
            binding.control_revision(),
        );
        let denied = host.registry.execute(&binding, &request).unwrap();
        host.assert_denial(&binding, &denied, ErrorCode::InvalidInput);
        let duplicate = host.registry.execute(&binding, &request).unwrap();
        assert_eq!(
            serde_json::to_value(duplicate).unwrap(),
            serde_json::to_value(denied).unwrap()
        );
    }
    assert_eq!(receiver.count(), 0);
    let healthy = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.approve(&binding, &healthy);
    host.assert_success(
        &binding,
        &host.registry.execute_prepared(&binding, healthy).unwrap(),
    );
    assert_eq!(receiver.count(), 1);
}

#[test]
fn http_registry_concurrent_duplicate_preparations_own_one_transfer_and_one_quota_charge() {
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let request = request(
        EntityId::new(),
        "http.send",
        &raw,
        binding.control_revision(),
    );
    let first = host.registry.prepare(&binding, &request).unwrap();
    let second = host.registry.prepare(&binding, &request).unwrap();
    assert_eq!(first.call().invocation_id, second.call().invocation_id);
    assert_eq!(first.call().input_ref, second.call().input_ref);
    host.approve(&binding, &first);
    let start = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let registry = &host.registry;
        let binding = &binding;
        let start = &start;
        let first = scope.spawn(move || {
            start.wait();
            registry.execute_prepared(binding, first).unwrap()
        });
        let second = scope.spawn(move || {
            start.wait();
            registry.execute_prepared(binding, second).unwrap()
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    let stored = host.ledger.invocations().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].invocation.state, InvocationState::Completed);
    assert_eq!(receiver.count(), 1);
    assert_eq!(
        host.ledger.read_budget(host.budget).unwrap().consumed,
        wire(1)
    );
    assert_eq!(
        host.ledger.read_budget(host.budget).unwrap().reserved,
        WireInt::ZERO
    );
    for result in results {
        assert_eq!(result.invocation_id, stored[0].invocation.invocation_id);
    }
    let input_artifacts = host
        .evidence
        .artifacts()
        .unwrap()
        .into_iter()
        .filter(|artifact| artifact.kind.as_str() == "http-send-input")
        .count();
    assert_eq!(input_artifacts, 1);
}

#[test]
fn http_registry_delivers_identity_bound_private_credentials_without_publishing_them() {
    use razen_engine::domain::evidence::Header;
    let token = format!("registry-private-{}", EntityId::new());
    let authorization = format!("Bearer {token}");
    let receiver = registry_receiver::Receiver::authenticated(authorization.clone(), false);
    let run = Run::new();
    let mut host = network_host(&run, &receiver);
    host.registry = network_registry_with_secret(
        &run,
        &host,
        Some((
            host.identity.identity_id,
            vec![Header {
                name: "authorization".into(),
                value: authorization.clone(),
            }],
        )),
    );
    let binding = host.bind();
    let mut unsafe_descriptor = network_request(&host, &receiver);
    unsafe_descriptor.headers.push(Header {
        name: "authorization".into(),
        value: authorization.clone(),
    });
    let before_publication = host.evidence.artifacts().unwrap().len();
    assert_eq!(
        razen_engine::application::http_send::install_request(
            &host.evidence,
            &binding,
            EntityId::new(),
            unsafe_descriptor
        )
        .unwrap_err()
        .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(host.evidence.artifacts().unwrap().len(), before_publication);
    let raw = network_input(&host, &receiver);
    exact_keys(
        &serde_json::from_str(raw.get()).unwrap(),
        &["request_snapshot_id", "base_revision", "identity_id"],
    );
    let request = request(
        EntityId::new(),
        "http.send",
        &raw,
        binding.control_revision(),
    );
    let prepared = host.registry.prepare(&binding, &request).unwrap();
    host.approve(&binding, &prepared);
    let result = host.registry.execute_prepared(&binding, prepared).unwrap();
    host.assert_success(&binding, &result);
    assert_eq!(receiver.authorizations(), vec![Some(authorization.clone())]);
    let output = host.output(&result);
    let record = host
        .evidence
        .read_artifact(
            host.project.project_id,
            serde_json::from_value(output["exchange_ref"].clone()).unwrap(),
            2_097_152,
        )
        .unwrap();
    let record: razen_engine::application::http_send::SendRecord =
        serde_json::from_slice(&record).unwrap();
    assert_eq!(
        record.exchanges[0].status, 200,
        "real receiver must require the credential"
    );
    for artifact in host.evidence.artifacts().unwrap() {
        let bytes = host
            .evidence
            .read_artifact(host.project.project_id, artifact.artifact_id, 33_554_432)
            .unwrap();
        assert!(
            !bytes
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
    }
    let charged = host.ledger.read_budget(host.budget).unwrap();
    let duplicate = host.registry.execute(&binding, &request).unwrap();
    assert_eq!(
        serde_json::to_value(&duplicate).unwrap(),
        serde_json::to_value(&result).unwrap()
    );
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), charged);
    assert_eq!(receiver.count(), 1);
    let rotated = network_registry_with_secret(
        &run,
        &host,
        Some((
            host.identity.identity_id,
            vec![Header {
                name: "authorization".into(),
                value: authorization,
            }],
        )),
    );
    assert_eq!(
        rotated.prepare(&binding, &request).err().unwrap().code,
        ErrorCode::InvalidInput
    );
    let wrong_identity = network_registry_with_secret(
        &run,
        &host,
        Some((
            EntityId::new(),
            vec![Header {
                name: "authorization".into(),
                value: format!("Bearer {token}"),
            }],
        )),
    );
    assert_eq!(
        wrong_identity
            .prepare(&binding, &request)
            .err()
            .unwrap()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(receiver.count(), 1);
}

#[test]
fn http_registry_rejects_credential_echo_before_public_capture_and_never_publishes_success() {
    use razen_engine::domain::evidence::Header;
    let token = format!("registry-echo-private-{}", EntityId::new());
    let authorization = format!("Bearer {token}");
    let receiver = registry_receiver::Receiver::authenticated(authorization.clone(), true);
    let run = Run::new();
    let mut host = network_host(&run, &receiver);
    host.registry = network_registry_with_secret(
        &run,
        &host,
        Some((
            host.identity.identity_id,
            vec![Header {
                name: "authorization".into(),
                value: authorization.clone(),
            }],
        )),
    );
    let binding = host.bind();
    let raw = network_input(&host, &receiver);
    let prepared = host
        .registry
        .prepare(
            &binding,
            &request(
                EntityId::new(),
                "http.send",
                &raw,
                binding.control_revision(),
            ),
        )
        .unwrap();
    host.approve(&binding, &prepared);
    let result = host.registry.execute_prepared(&binding, prepared).unwrap();
    assert_eq!(receiver.authorizations(), vec![Some(authorization)]);
    assert_eq!(result.state, InvocationState::Failed);
    assert_eq!(
        result.error.as_ref().unwrap().code,
        ErrorCode::PermissionDenied
    );
    assert!(result.output_ref.is_none());
    for artifact in host.evidence.artifacts().unwrap() {
        let bytes = host
            .evidence
            .read_artifact(host.project.project_id, artifact.artifact_id, 33_554_432)
            .unwrap();
        assert!(
            !bytes
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
        assert!(
            !(artifact.origin_invocation_id == result.invocation_id
                && artifact.kind.as_str() == "http-send-output")
        );
    }
}

#[test]
fn http_registry_revalidates_actual_descriptor_and_body_bytes_before_dispatch_or_charge() {
    for corrupt_descriptor in [true, false] {
        let receiver = registry_receiver::Receiver::start(false, false);
        let run = Run::new();
        let host = network_host(&run, &receiver);
        let binding = host.bind();
        let raw = network_input(&host, &receiver);
        let input: razen_engine::application::http_send::HttpSendInput =
            serde_json::from_str(raw.get()).unwrap();
        let prepared = host
            .registry
            .prepare(
                &binding,
                &request(
                    EntityId::new(),
                    "http.send",
                    &raw,
                    binding.control_revision(),
                ),
            )
            .unwrap();
        host.approve(&binding, &prepared);
        let before = host.ledger.read_budget(host.budget).unwrap();
        let snapshot = if corrupt_descriptor {
            host.evidence
                .snapshot(
                    host.project.project_id,
                    input.request_snapshot_id,
                    input.base_revision,
                )
                .unwrap()
        } else {
            host.evidence
                .snapshot(
                    host.project.project_id,
                    host.snapshot.snapshot_id,
                    host.snapshot.revision,
                )
                .unwrap()
        };
        let artifact = host
            .evidence
            .artifact(host.project.project_id, snapshot.body_ref)
            .unwrap();
        let path = run.workspace.path().join(&artifact.relative_path);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        assert_eq!(
            host.registry
                .execute_prepared(&binding, prepared)
                .unwrap_err()
                .code,
            ErrorCode::IntegrityError
        );
        assert_eq!(receiver.count(), 0);
        assert_eq!(host.ledger.read_budget(host.budget).unwrap(), before);
        assert!(
            !host
                .ledger
                .invocations()
                .unwrap()
                .iter()
                .any(|stored| stored.invocation.tool_id.as_str() == "http.send"
                    && stored.invocation.output_ref.is_some())
        );
    }
}

#[test]
fn http_host_descriptor_publication_does_not_grant_or_dispatch_invalid_url_or_framing() {
    use razen_engine::domain::evidence::Header;
    let receiver = registry_receiver::Receiver::start(false, false);
    let run = Run::new();
    let host = network_host(&run, &receiver);
    let binding = host.bind();
    let before = host.ledger.read_budget(host.budget).unwrap();
    let mut invalid_url = network_request(&host, &receiver);
    invalid_url.url = "not an HTTP URL".into();
    let mut invalid_framing = network_request(&host, &receiver);
    invalid_framing.headers.push(Header {
        name: "content-length".into(),
        value: (host.snapshot.length_bytes.get() + 1).to_string(),
    });
    for descriptor in [invalid_url, invalid_framing] {
        let raw = publish_network_input(&host, descriptor);
        assert_eq!(
            host.registry
                .prepare(
                    &binding,
                    &request(
                        EntityId::new(),
                        "http.send",
                        &raw,
                        binding.control_revision()
                    )
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidInput
        );
    }
    assert_eq!(receiver.count(), 0);
    assert_eq!(host.ledger.read_budget(host.budget).unwrap(), before);
}
