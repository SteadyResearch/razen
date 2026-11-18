use razen_engine::{
    adapters::workspace::OwnedDirectory,
    application::{
        control_owner::OwnedControl,
        profile::LoadedProfile,
        proof_host::ProofHost,
        suites::{CaseObservation, runtime},
    },
    domain::values::{CatalogId, Digest, EntityId},
    protocol::contracts::CanonicalFixtures,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
#[path = "private_root.rs"]
mod private_root;

pub struct Fixture {
    pub host: ProofHost,
    pub profile: LoadedProfile,
    pub repository: PathBuf,
    pub run: razen_engine::domain::proofs::Run,
    _control: OwnedControl,
    _root: private_root::PrivateRoot,
}
impl Fixture {
    pub fn new() -> Self {
        use sha2::Digest as _;
        use std::io::Read as _;
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
        let mut engine = std::fs::File::open(env!("CARGO_BIN_EXE_razen-engine")).unwrap();
        let mut hash = sha2::Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let count = engine.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        let engine_digest = Digest::from_sha256(hash.finalize().into());
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            engine_digest,
        )
        .unwrap();
        let control =
            OwnedControl::start(Arc::clone(&host.workspace), Arc::clone(&host.control)).unwrap();
        host.install_control_client(control.client().unwrap())
            .unwrap();
        let runtime_cases = [
            "RUN-01", "RUN-02", "RUN-03", "RUN-04", "RUN-05", "RUN-06", "RUN-07", "RUN-08",
        ]
        .map(|case| CatalogId::parse(case).unwrap());
        let environment = razen_engine::application::environment::observe(
            &repository,
            &host.workspace,
            &profile,
            std::collections::BTreeMap::from([(
                CatalogId::parse("razen-engine").unwrap(),
                engine_digest,
            )]),
            &runtime_cases,
        )
        .unwrap();
        environment.validate().unwrap();
        let run = razen_engine::domain::proofs::Run {
            run_id: host.workspace.run_id(),
            contract_version: razen_engine::domain::values::ContractVersion::V0_1_0,
            profile_id: profile.config().profile_id.clone(),
            profile_sha256: profile.sha256(),
            clock_epoch_id: host.control.clock_epoch_id(),
            started_at: razen_engine::domain::values::AuditTime::now(),
            finished_at: None,
            environment,
            dependency_record_refs: vec![],
            fixture_manifest_sha256: Digest::of(
                &std::fs::read(repository.join("fixtures/scenarios/manifest.json")).unwrap(),
            ),
        };
        Self {
            host,
            profile,
            repository,
            run,
            _control: control,
            _root: root,
        }
    }
    pub fn execute(&self, case: &str) -> CaseObservation {
        let result = runtime::execute(
            &self.host,
            &self.profile,
            &self.repository,
            &CatalogId::parse(case).unwrap(),
        )
        .unwrap();
        for (name, passed) in result.observed.iter() {
            assert!(passed, "{case}: {name:?}: {}", result.report);
        }
        assert_eq!(
            self.verify(&result, &result.report).unwrap(),
            result.observed
        );
        result
    }
    pub fn verify(
        &self,
        observation: &CaseObservation,
        report: &serde_json::Value,
    ) -> razen_engine::protocol::error::ProofResult<razen_engine::domain::proofs::Assertions> {
        use razen_engine::domain::{
            evidence::EvidenceRef,
            proofs::{CaseStatus, ProofResult},
            values::Usage,
        };
        let mut usage = Usage::default();
        let mut refs = Vec::new();
        for fact in observation.report["runs"].as_array().unwrap() {
            let id = EntityId::parse(fact["invocation_id"].as_str().unwrap()).unwrap();
            let charged = self
                .host
                .ledger
                .read_invocation(id)
                .unwrap()
                .invocation
                .usage;
            usage.units = usage.units.checked_add(charged.units).unwrap();
            usage.bytes = usage.bytes.checked_add(charged.bytes).unwrap();
            usage.cpu_us = usage.cpu_us.checked_add(charged.cpu_us).unwrap();
            usage.elapsed_us = usage.elapsed_us.checked_add(charged.elapsed_us).unwrap();
            let artifact_id = EntityId::parse(fact["fact_artifact_id"].as_str().unwrap()).unwrap();
            let artifact = self
                .host
                .evidence
                .artifact(self.host.project.project_id, artifact_id)
                .unwrap();
            refs.push(EvidenceRef::Artifact {
                artifact_id,
                sha256: artifact.sha256,
                range: None,
            });
        }
        let expected = self
            .host
            .registry
            .contract_examples()
            .records()
            .iter()
            .find_map(|record| match &record.record {
                razen_engine::protocol::contracts::ContractRecord::ProofCase(case)
                    if case.case_id == observation.case_id =>
                {
                    Some(case.expected.clone())
                }
                _ => None,
            })
            .unwrap();
        let result = ProofResult {
            run_id: self.run.run_id,
            case_id: observation.case_id.clone(),
            status: CaseStatus::Passed,
            expected,
            observed: observation.observed.clone(),
            evidence_refs: refs,
            elapsed_us: usage.elapsed_us,
            usage,
            error: None,
        };
        result.validate().unwrap();
        runtime::verify_report(
            &result,
            report,
            self.host.project.project_id,
            &self.run,
            &self.profile,
            &self.host.evidence,
            &self.host.ledger,
        )
    }
}
