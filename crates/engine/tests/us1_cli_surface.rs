use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use razen_engine::adapters::evidence_store::EvidenceStore;
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::domain::evidence::EvidenceRef;
use razen_engine::domain::proofs::{CaseStatus, ProofResult, Run};
use razen_engine::domain::values::{Digest, EntityId};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};

const PROFILE: &str = "specs/001-r0-feasibility/contracts/pilot-profile.json";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

struct Output {
    relative: String,
    path: PathBuf,
}

impl Output {
    fn new() -> Self {
        let relative = format!("target/r0-evidence/cli-test-{}", EntityId::new());
        let path = repo().join(&relative);
        assert!(!path.exists(), "test never adopts another run");
        Self { relative, path }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
        {
            let removed = std::fs::remove_dir_all(&self.path);
            if !std::thread::panicking() {
                removed.expect("remove this test's unique newly created output");
            }
        }
    }
}

async fn bounded(mut stream: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut stream).take(65_537).read_to_end(&mut bytes).await?;
    if bytes.len() > 65_536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "CLI exceeded diagnostic byte limit",
        ));
    }
    Ok(bytes)
}

async fn cli(args: &[&str]) -> (ExitStatus, Value, Vec<u8>) {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_razen-proof"));
    command
        .args(args)
        .current_dir(repo())
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("launch actual proof CLI");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let completion = tokio::time::timeout(Duration::from_secs(90), async {
        tokio::try_join!(child.wait(), bounded(stdout), bounded(stderr))
    })
    .await;
    let (status, stdout, stderr) = match completion {
        Ok(Ok(observed)) => observed,
        other => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            panic!("Actual CLI did not terminate with bounded output: {other:?}");
        }
    };
    let summary: Value = serde_json::from_slice(&stdout)
        .expect("exactly one final JSON document, no progress chatter");
    assert_eq!(summary["protocol"], "razen.proof/0.1.0");
    assert_eq!(summary["review_status"], "unreviewed");
    assert_eq!(summary["r0_exit_ready"], false);
    let counts = &summary["counts"];
    let total = counts["total"].as_u64().unwrap();
    let sum: u64 = ["passed", "failed", "blocked", "unexecuted"]
        .iter()
        .map(|key| counts[*key].as_u64().unwrap())
        .sum();
    assert_eq!(sum, total);
    (status, summary, stderr)
}

async fn contracts(output: &Output) -> Value {
    let (status, summary, _) = cli(&[
        "run",
        "--profile",
        PROFILE,
        "--suite",
        "contracts",
        "--out",
        &output.relative,
    ])
    .await;
    assert_eq!(
        status.code(),
        Some(0),
        "selected contracts must genuinely satisfy their command"
    );
    assert_eq!(summary["status"], "passed");
    assert_eq!(
        summary["counts"],
        serde_json::json!({"total":35,"passed":5,"failed":0,"blocked":0,"unexecuted":30})
    );
    let run_ref = summary["run_ref"].as_str().expect("real run reference");
    assert!(
        !Path::new(run_ref).is_absolute(),
        "exported run references do not disclose home paths"
    );
    summary
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_flags_never_provision_create_output_or_echo_private_argument_text() {
    let output = Output::new();
    let marker = "PRIVATE-INVALID-ARGUMENT-DO-NOT-ECHO";
    let (status, summary, stderr) = cli(&[
        "run",
        "--profile",
        PROFILE,
        "--suite",
        "contracts",
        "--out",
        &output.relative,
        "--confirm-provision",
        marker,
    ])
    .await;
    assert_eq!(status.code(), Some(2));
    assert_ne!(summary["status"], "passed");
    assert_eq!(summary["counts"]["total"], 0);
    assert!(!output.path.exists(), "argument rejection precedes effects");
    assert!(!String::from_utf8_lossy(&stderr).contains(marker));
    assert!(!summary.to_string().contains(marker));
}

#[tokio::test(flavor = "current_thread")]
async fn actual_contracts_run_emits_full_partial_inventory_and_verify_never_promotes_it_to_full_readiness()
 {
    let output = Output::new();
    contracts(&output).await;
    let run: Run =
        serde_json::from_slice(&std::fs::read(output.path.join("run.json")).unwrap()).unwrap();
    let profile = std::fs::read(output.path.join("profile.json")).unwrap();
    assert_eq!(Digest::of(&profile), run.profile_sha256);
    let results: Vec<ProofResult> =
        serde_json::from_slice(&std::fs::read(output.path.join("results.json")).unwrap()).unwrap();
    let mut ids = BTreeSet::new();
    for result in &results {
        result.validate().unwrap();
        assert_eq!(result.run_id, run.run_id);
        assert!(ids.insert(result.case_id.as_str()));
        if result.case_id.as_str().starts_with("CON-") {
            assert_eq!(result.status, CaseStatus::Passed);
            assert!(!result.evidence_refs.is_empty());
        } else {
            assert_eq!(result.status, CaseStatus::Unexecuted);
        }
    }
    assert_eq!(ids.len(), 35);
    for name in [
        "versions.json",
        "cases.json",
        "trace.jsonl",
        "ledger.sqlite",
        "exit.json",
        "manifest.json",
    ] {
        assert!(
            output.path.join(name).is_file(),
            "required actual evidence packet file missing"
        );
    }
    let (status, summary, _) = cli(&["verify", "--run", &output.relative]).await;
    assert_eq!(status.code(), Some(4));
    assert_eq!(summary["status"], "incomplete");
    assert_eq!(summary["counts"]["passed"], 5);
    let before = std::fs::read(output.path.join("results.json")).unwrap();
    let (status, summary, _) = cli(&["cleanup", "--run", &output.relative]).await;
    assert_eq!(status.code(), Some(0));
    assert_eq!(summary["status"], "passed");
    assert_eq!(
        std::fs::read(output.path.join("results.json")).unwrap(),
        before
    );
    assert!(output.path.join("ledger.sqlite").is_file());
    assert!(output.path.join("manifest.json").is_file());
}

#[tokio::test(flavor = "current_thread")]
async fn actual_verify_detects_changed_real_artifact_without_rerunning_cases_or_rewriting_results()
{
    let output = Output::new();
    contracts(&output).await;
    let before = std::fs::read(output.path.join("results.json")).unwrap();
    let results: Vec<ProofResult> = serde_json::from_slice(&before).unwrap();
    let artifact_id = results
        .iter()
        .find(|result| result.case_id.as_str() == "CON-01")
        .and_then(|result| {
            result
                .evidence_refs
                .iter()
                .find_map(|reference| match reference {
                    EvidenceRef::Artifact { artifact_id, .. } => Some(*artifact_id),
                    _ => None,
                })
        })
        .expect("a passed case references actual immutable evidence");
    let workspace = std::sync::Arc::new(
        OwnedDirectory::open(
            output.path.parent().unwrap(),
            Path::new(output.path.file_name().unwrap()),
        )
        .unwrap(),
    );
    let store = EvidenceStore::open(std::sync::Arc::clone(&workspace)).unwrap();
    let artifact = store
        .artifacts()
        .unwrap()
        .into_iter()
        .find(|artifact| artifact.artifact_id == artifact_id)
        .expect("referenced actual evidence exists");
    let path = output.path.join(&artifact.relative_path);
    let mut bytes = std::fs::read(&path).unwrap();
    assert_eq!(Digest::of(&bytes), artifact.sha256);
    bytes[0] ^= 1;
    std::fs::write(path, bytes).unwrap();
    drop(store);
    let (status, summary, _) = cli(&["verify", "--run", &output.relative]).await;
    assert_eq!(status.code(), Some(1));
    assert_eq!(summary["status"], "failed");
    assert_eq!(
        std::fs::read(output.path.join("results.json")).unwrap(),
        before
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cleanup_accepts_failed_launch_with_no_packet_and_preserves_its_owned_sources() {
    let output = Output::new();
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(output.path.parent().unwrap())
        .unwrap();
    let workspace = OwnedDirectory::create(
        output.path.parent().unwrap(),
        Path::new(output.path.file_name().unwrap()),
        EntityId::new(),
    )
    .unwrap();
    let profile = std::fs::read(repo().join(PROFILE)).unwrap();
    workspace
        .write_new(Path::new("profile.json"), &profile)
        .unwrap();
    workspace
        .write_new(
            Path::new("ephemeral/partial-launch.bin"),
            b"owned transient input",
        )
        .unwrap();
    let (status, summary, _) = cli(&["cleanup", "--run", &output.relative]).await;
    assert_eq!(status.code(), Some(0));
    assert_eq!(summary["command"], "cleanup");
    assert_eq!(summary["status"], "passed");
    assert_eq!(
        std::fs::read(output.path.join("profile.json")).unwrap(),
        profile
    );
    assert!(!output.path.join("ephemeral/partial-launch.bin").exists());
    assert!(!output.path.join("run.json").exists());
    assert!(!output.path.join("results.json").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn cleanup_refuses_unknown_ephemeral_symlink_without_removing_it_or_its_target() {
    let output = Output::new();
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(output.path.parent().unwrap())
        .unwrap();
    let workspace = OwnedDirectory::create(
        output.path.parent().unwrap(),
        Path::new(output.path.file_name().unwrap()),
        EntityId::new(),
    )
    .unwrap();
    workspace
        .write_new(
            Path::new("profile.json"),
            &std::fs::read(repo().join(PROFILE)).unwrap(),
        )
        .unwrap();
    let target = output.path.join("retained-source.bin");
    workspace
        .write_new(Path::new("retained-source.bin"), b"immutable owned source")
        .unwrap();
    workspace
        .write_new(
            Path::new("ephemeral/retained.bin"),
            b"must survive rejected cleanup",
        )
        .unwrap();
    std::os::unix::fs::symlink(&target, output.path.join("ephemeral/unknown-link")).unwrap();
    let (status, summary, _) = cli(&["cleanup", "--run", &output.relative]).await;
    assert_eq!(status.code(), Some(1));
    assert_eq!(summary["status"], "failed");
    let refs = summary["error_refs"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    let id = EntityId::parse(refs[0].as_str().unwrap()).unwrap();
    let diagnostic = workspace
        .read(Path::new(&format!("errors/{id}.json")), 65_536)
        .unwrap();
    let diagnostic: Value = serde_json::from_slice(&diagnostic).unwrap();
    assert_eq!(diagnostic["command"], "cleanup");
    assert_eq!(diagnostic["run_id"], workspace.run_id().to_string());
    assert_eq!(diagnostic["error_id"], id.to_string());
    assert_eq!(diagnostic["error"]["code"], "permission_denied");
    assert!(!diagnostic["error"]["message"].as_str().unwrap().is_empty());
    assert!(
        !String::from_utf8(serde_json::to_vec(&summary).unwrap())
            .unwrap()
            .contains(&output.relative)
    );
    assert!(
        output
            .path
            .join("ephemeral/unknown-link")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"immutable owned source");
}
