use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::admission::TrustedBinding;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::domain::values::{CatalogId, ContractVersion, Digest, EntityId, WireInt};
use razen_engine::protocol::codec::{PROTOCOL, encode_frame};
use razen_engine::protocol::contracts::CanonicalFixtures;
use razen_engine::protocol::engine::{RuntimeBroker, RuntimeIngressKind};
use razen_engine::protocol::messages::{BudgetSummary, ToolRequest};
use serde_json::{Value, json, value::RawValue};

#[path = "private_root.rs"]
mod private_root;

pub struct ConsumerFixture {
    pub host: ProofHost,
    pub profile: LoadedProfile,
    _root: private_root::PrivateRoot,
}

impl ConsumerFixture {
    pub fn new() -> Self {
        let root = private_root::PrivateRoot::new();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let bytes = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::of(b"consumer policy-test provider metadata"),
        )
        .unwrap();
        Self {
            host,
            profile,
            _root: root,
        }
    }

    pub fn summary(&self) -> BudgetSummary {
        let budget = self.host.ledger.read_budget(self.host.budget_id).unwrap();
        BudgetSummary {
            limit: budget.limit,
            consumed: budget.consumed,
            reserved: budget.reserved,
        }
    }

    pub fn broker(&self) -> RuntimeBroker {
        RuntimeBroker::new(
            self.host.bind_local().unwrap(),
            Arc::clone(&self.host.registry),
            &self.profile,
        )
        .unwrap()
    }

    pub fn started(&self) -> (RuntimeBroker, EntityId) {
        let mut broker = self.broker();
        let start = broker.start(vec![], self.summary()).unwrap();
        let start_id = serde_json::from_value::<EntityId>(
            serde_json::from_slice::<Value>(&start).unwrap()["message_id"].clone(),
        )
        .unwrap();
        let inbound = frame(EntityId::new(), "started", Some(start_id), capabilities());
        assert!(matches!(
            broker.receive(&inbound).unwrap().kind,
            RuntimeIngressKind::Started(_)
        ));
        (broker, start_id)
    }

    pub fn snapshot_input(&self) -> Box<RawValue> {
        let snapshot = self
            .host
            .evidence
            .snapshots()
            .unwrap()
            .into_iter()
            .find(|snapshot| snapshot.length_bytes.get() >= 4)
            .unwrap();
        raw(
            json!({"snapshot_id": snapshot.snapshot_id, "revision": snapshot.revision, "offset": 0, "max_bytes": 4}),
        )
    }

    pub fn proposal_input(&self) -> Box<RawValue> {
        let snapshot = self
            .host
            .evidence
            .snapshots()
            .unwrap()
            .into_iter()
            .find(|snapshot| snapshot.length_bytes.get() >= 4)
            .unwrap();
        raw(
            json!({"rule_id": "fixture.public-byte-observation", "title": "Reviewed consumer proposal",
            "snapshot_id": snapshot.snapshot_id, "revision": snapshot.revision, "range_start": 0, "range_end": 4}),
        )
    }

    pub fn approve(&self, binding: &Arc<TrustedBinding>, request: &ToolRequest<'_>) {
        let prepared = self.host.registry.prepare(binding, request).unwrap();
        self.host.approve(binding, prepared.call()).unwrap();
    }
}

pub fn raw(value: Value) -> Box<RawValue> {
    RawValue::from_string(value.to_string()).unwrap()
}

pub fn request<'a>(
    call_id: EntityId,
    tool: &str,
    input: &'a RawValue,
    revision: WireInt,
) -> ToolRequest<'a> {
    ToolRequest {
        call_id,
        tool_id: CatalogId::parse(tool).unwrap(),
        tool_version: ContractVersion::V0_1_0,
        input,
        source_control_revision: revision,
    }
}

pub fn capabilities() -> Value {
    json!({"capabilities": ["brokered_calls", "events", "results", "usage", "cancellation", "closure"]})
}

pub fn frame(id: EntityId, kind: &str, correlation: Option<EntityId>, payload: Value) -> Vec<u8> {
    let mut envelope =
        json!({"protocol": PROTOCOL, "message_id": id, "kind": kind, "payload": payload});
    if let Some(correlation) = correlation {
        envelope["correlation_id"] = json!(correlation);
    }
    encode_frame(&envelope, 1_048_576).unwrap()
}
