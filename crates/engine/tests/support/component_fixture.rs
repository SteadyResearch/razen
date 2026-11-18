use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::{
    profile::LoadedProfile,
    proof_host::ProofHost,
    suites::{CaseObservation, components},
};
use razen_engine::domain::values::{CatalogId, Digest, EntityId};
use razen_engine::protocol::contracts::CanonicalFixtures;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[path = "private_root.rs"]
mod private_root;

pub struct Fixture {
    pub host: ProofHost,
    pub profile: LoadedProfile,
    pub repository: PathBuf,
    _control: razen_engine::application::control_owner::OwnedControl,
    _root: private_root::PrivateRoot,
}
impl Fixture {
    pub fn new() -> Self {
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
            Digest::of(b"component behavioral integration provider"),
        )
        .unwrap();
        let control = razen_engine::application::control_owner::OwnedControl::start(
            Arc::clone(&host.workspace),
            Arc::clone(&host.control),
        )
        .unwrap();
        host.install_control_client(control.client().unwrap())
            .unwrap();
        Self {
            host,
            profile,
            repository,
            _control: control,
            _root: root,
        }
    }
    pub fn execute(&self, case: &str) -> CaseObservation {
        let id = CatalogId::parse(case).unwrap();
        let observation =
            components::execute(&self.host, &self.profile, &self.repository, &id).unwrap();
        assert_eq!(observation.case_id, id);
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.repository.join("fixtures/scenarios/manifest.json")).unwrap(),
        )
        .unwrap();
        let expected = manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["case_id"] == case)
            .unwrap()["expected"]
            .as_object()
            .unwrap();
        assert_eq!(observation.observed.iter().count(), expected.len());
        let actual = serde_json::to_value(&observation.observed).unwrap();
        for name in expected.keys() {
            assert_eq!(actual[name], true, "{case} missing fixed assertion {name}");
        }
        for (name, passed) in observation.observed.iter() {
            assert!(passed, "{case} {name:?}: {}", observation.report);
        }
        observation
    }
}
pub fn assert_reaped_successors(report: &serde_json::Value) {
    let runs = report["runs"]
        .as_array()
        .expect("actual component lifecycle facts");
    assert!(!runs.is_empty());
    for run in runs {
        assert!(run["pid"].as_u64().unwrap() > 0);
        assert_eq!(run["reaped"], true);
        assert_eq!(run["invocations_after"], 0);
        assert_eq!(run["host_calls_after"], 0);
        assert!(run["elapsed_us"].as_u64().unwrap() > 0);
        assert!(
            run["rss_samples"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_u64().unwrap() > 0)
        );
    }
    if runs.iter().any(|run| run["variant"] != "fixture-valid") {
        let controls = report["control_measurements"].as_array().unwrap();
        assert!(
            !controls.is_empty(),
            "every adversarial variant requires actual durable control samples"
        );
        assert!(
            controls
                .iter()
                .all(|sample| sample["ack_elapsed_us"].as_u64().unwrap() <= 1_000_000)
        );
    }
    for pair in runs.windows(2) {
        if pair[0]["variant"] != "fixture-valid" {
            assert_eq!(
                pair[1]["variant"], "fixture-valid",
                "a fresh valid run must follow EACH failure"
            );
            assert_eq!(pair[1]["outcome"], "completed");
            assert_ne!(pair[0]["invocation_id"], pair[1]["invocation_id"]);
        }
    }
    assert_eq!(runs.last().unwrap()["outcome"], "completed");
}
