#![allow(dead_code)]
// CONTROLLEDGATEFIXTURE: record-policy inputs, never operational runtime evidence.
use razen_engine::{
    application::{
        cli::Suite,
        harness::{CaseSelection, ScenarioManifest},
        profile::LoadedProfile,
    },
    domain::{
        proofs::{ProofResult, Run},
        values::{Digest, EntityId},
    },
};
use serde_json::{Value, json};
pub fn profile() -> LoadedProfile {
    LoadedProfile::from_bytes(include_bytes!(
        "../../../../specs/001-r0-feasibility/contracts/pilot-profile.json"
    ))
    .unwrap()
}
pub fn selection() -> CaseSelection {
    let bytes = include_bytes!("../../../../fixtures/scenarios/manifest.json");
    serde_json::from_slice::<ScenarioManifest>(bytes)
        .unwrap()
        .select(Suite::All, None, Digest::of(bytes))
        .unwrap()
}
pub fn run() -> Run {
    let p = profile();
    let s = selection();
    let d = Digest::of(b"CONTROLLEDGATEFIXTURE");
    serde_json::from_value(json!({"run_id":EntityId::new(),"contract_version":"0.1.0","profile_id":"macos-arm64-proof","profile_sha256":p.sha256(),"clock_epoch_id":EntityId::new(),"started_at":"2026-11-16T12:00:00Z","finished_at":"2026-11-16T12:01:00Z","environment":{"hardware_model":"CONTROLLEDGATEFIXTURE","logical_cpus":8,"memory_mib":16384,"os":"macOS","os_version":"26.5.1","arch":"arm64","os_build":"CONTROLLEDGATEFIXTURE","kernel":"CONTROLLEDGATEFIXTURE","filesystem":"APFS","storage":"fixture","component_target":"wasm32-wasip2","backend":"lima-vz-plain-bubblewrap-cgroup-v2","isolation_status":"prepared","guest_os":"Debian 13.7 arm64","image_digest":p.config().external_runner.image_digest,"dependency_versions":{"rust":"1.100.0","lima":"2.3.0","bubblewrap":"0.13.1"},"fixture_digests":{"contracts":d},"binary_digests":{"engine":d},"lockfile_sha256":d,"component_lockfile_sha256":d,"guest_package_manifest_sha256":d,"provisioning_sha256":d,"effective_config_sha256":d,"seccomp_sha256":d,"wit_sha256":d},"dependency_record_refs":[],"fixture_manifest_sha256":s.fixture_manifest_sha256})).unwrap()
}
pub fn results(run: &Run) -> Vec<ProofResult> {
    selection().inventory.cases().iter().map(|case|serde_json::from_value(json!({"run_id":run.run_id,"case_id":case.case_id,"status":"passed","expected":case.expected,"observed":case.expected,"evidence_refs":[evidence()],"elapsed_us":1,"usage":{"units":1,"bytes":1,"cpu_us":1,"elapsed_us":1}})).unwrap()).collect()
}
pub fn evidence() -> Value {
    json!({"artifact_id":"10000000-0000-4000-8000-000000000003","sha256":Digest::of(b"CONTROLLEDGATEFIXTURE artifact")})
}
pub fn decision(run: &Run, manifest: Digest) -> Value {
    json!({"decision_id":"EXIT-REVIEW","subject":"R0 exit","decision":"Approve exact reviewed R0 packet","rationale":"CONTROLLEDGATEFIXTURE exercises policy only; no operational proof claim","alternatives":["Reject","Keep pending"],"evidence_refs":[{"kind":"run_manifest","run_id":run.run_id,"sha256":manifest},{"kind":"evidence","reference":evidence()}],"status":"approved","reviewer":"fixture-maintainer","reviewed_at":"2026-11-16T12:02:00Z"})
}
