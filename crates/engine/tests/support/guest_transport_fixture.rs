use razen_engine::{
    adapters::guest::{
        preflight::PreparedGuest,
        transport::{GuestInvocation, encode_runtime_program},
    },
    application::profile::LoadedProfile,
    domain::values::{CatalogId, ContractVersion, Digest, EntityId, WireInt},
    protocol::messages::{ArtifactEvidenceRef, BudgetSummary, RuntimeStart, SupervisorLaunch},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Fixture {
    pub repository: PathBuf,
    pub profile: LoadedProfile,
    pub guest: Arc<PreparedGuest>,
    pub run_id: EntityId,
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
        let guest = Arc::new(
            PreparedGuest::discover(&repository, &profile)
                .expect("explicitly prepared Linux VM required"),
        );
        Self {
            repository,
            profile,
            guest,
            run_id: EntityId::new(),
        }
    }
    pub fn stage_launch(&self) -> SupervisorLaunch {
        let binding_id = EntityId::new();
        let invocation_id = EntityId::new();
        let artifact_id = EntityId::new();
        let start = RuntimeStart {
            binding_id,
            contract_version: ContractVersion::V0_1_0,
            context_refs: vec![EntityId::new()],
            tool_ids: vec![],
            budget_summary: BudgetSummary {
                limit: WireInt::new(64).unwrap(),
                consumed: WireInt::ZERO,
                reserved: WireInt::ZERO,
            },
        };
        let program = encode_runtime_program(EntityId::new(), &start).unwrap();
        self.guest
            .stage_runtime(invocation_id, artifact_id, &program)
            .unwrap();
        SupervisorLaunch {
            binding_id,
            invocation_id,
            run_id: self.run_id,
            attestation_id: EntityId::new(),
            profile_sha256: self.profile.sha256(),
            approved_fixture_id: CatalogId::parse("runtime_blocked").unwrap(),
            input_artifact_refs: vec![ArtifactEvidenceRef {
                artifact_id,
                sha256: Digest::of(&program),
                range_start: None,
                range_end: None,
            }],
            lease_id: EntityId::new(),
            control_revision: WireInt::ZERO,
        }
    }
    pub fn launch(&self) -> GuestInvocation {
        let launch = self.stage_launch();
        let mut invocation = self.guest.launch(launch, &self.profile).unwrap();
        let started = Instant::now();
        loop {
            if let Some(frame) = invocation.poll().unwrap()
                && frame["kind"] == "started"
            {
                return invocation;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "real sandbox did not reach attested release"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
