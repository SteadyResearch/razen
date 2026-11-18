use razen_engine::adapters::{guest::proofs, workspace::OwnedDirectory};
use razen_engine::application::{
    profile::LoadedProfile, proof_host::ProofHost, suites::CaseObservation,
};
use razen_engine::domain::values::{CatalogId, Digest, EntityId};
use razen_engine::protocol::contracts::CanonicalFixtures;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[path = "private_root.rs"]
mod private_root;
pub use private_root::PrivateRoot;

pub struct Fixture {
    host: ProofHost,
    profile: LoadedProfile,
    repository: PathBuf,
    _control: razen_engine::application::control_owner::OwnedControl,
    _root: PrivateRoot,
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
        let root = PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        use sha2::Digest as _;
        use std::io::Read as _;
        let mut engine = std::fs::File::open(env!("CARGO_BIN_EXE_razen-engine")).unwrap();
        let mut hash = sha2::Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let length = engine.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            hash.update(&buffer[..length]);
        }
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::from_sha256(hash.finalize().into()),
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
            proofs::execute(&self.host, &self.profile, &self.repository, &id).unwrap();
        assert_eq!(observation.case_id, id);
        for (name, passed) in observation.observed.iter() {
            assert!(passed, "{case} {name:?}: {}", observation.report);
        }
        observation
    }
}
pub fn assert_fresh_successors(report: &serde_json::Value) {
    let runs = report["runs"].as_array().unwrap();
    assert!(!runs.is_empty());
    for run in runs {
        assert_eq!(run["empty_cgroup"], true);
        assert_eq!(run["live_slots_after"], 0);
    }
    for pair in runs.windows(2) {
        if pair[0]["variant"] != "snapshot_control" {
            assert_eq!(pair[1]["variant"], "snapshot_control");
            assert_eq!(pair[1]["outcome"], "completed");
            assert_ne!(pair[0]["invocation_id"], pair[1]["invocation_id"]);
        }
    }
    assert_eq!(runs.last().unwrap()["outcome"], "completed");
}
