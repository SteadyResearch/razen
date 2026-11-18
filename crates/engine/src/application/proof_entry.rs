//! Bounded trusted CLI orchestration. A selected-suite pass is not the full exit gate.
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command as Process;
use tokio::signal::unix::{SignalKind, signal};

use super::cli::{Command, Suite, parse_command};
use super::cli_workspace::{self, EXAMPLES, SCENARIOS};
use super::harness::{
    BOOTSTRAP_PATH, CommandStatus, CommandSummary, Counts, EXAMPLES_PATH, EngineBootstrap,
    EngineOutcome, MAX_METADATA_BYTES, OUTCOME_PATH, PacketVerdict, ScenarioManifest,
};
use super::{packet, profile::LoadedProfile};
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::Ledger;
use crate::adapters::native_files::executable_digest;
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::proofs::{ProofResult as CaseResult, Run};
use crate::domain::values::{AuditTime, ContractVersion, Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

struct Reply {
    summary: CommandSummary,
    exit_code: u8,
}

pub async fn run(args: Vec<OsString>) -> u8 {
    let name = match args.first().and_then(|value| value.to_str()) {
        Some("run") => "run",
        Some("verify") => "verify",
        Some("cleanup") => "cleanup",
        Some("doctor") => "doctor",
        Some("prepare-isolation") => "prepare-isolation",
        _ => "invalid",
    };
    let parsed = parse_command(args);
    let reply = match parsed {
        Err(error) => failure(name, error, None),
        Ok(command) => match std::env::current_dir().and_then(|path| path.canonicalize()) {
            Err(_) => failure(name, invalid(), None),
            Ok(repo) => dispatch(command, &repo).await,
        },
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &reply.summary).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        eprintln!("Proof summary output is unavailable");
        return 1;
    }
    reply.exit_code
}

async fn dispatch(command: Command, repo: &Path) -> Reply {
    let name = command.name();
    match command {
        Command::Run {
            profile,
            suite,
            case,
            out,
        } => match execute(repo, &profile, suite, case.as_ref(), &out).await {
            Ok(verdict) => from_verdict(name, verdict, true),
            Err(error) => match cli_workspace::open(repo, &out) {
                Ok(workspace) => failure(name, error, Some(&workspace)),
                Err(_) => failure(name, error, None),
            },
        },
        Command::Verify { run } => match cli_workspace::open(repo, &run) {
            Err(error) => failure(name, error, None),
            Ok(workspace) => match packet::verify(&workspace) {
                Ok(verdict) => from_verdict(name, verdict, false),
                Err(error) => failure(name, error, Some(&workspace)),
            },
        },
        Command::Cleanup {
            run,
            stop_isolation,
        } => match cli_workspace::open(repo, &run) {
            Err(error) => failure(name, error, None),
            Ok(workspace) => match cleanup(repo, &workspace, stop_isolation) {
                Ok(()) => {
                    let mut summary = CommandSummary::without_run(name, CommandStatus::Passed);
                    fill_existing(&mut summary, &workspace);
                    Reply {
                        summary,
                        exit_code: 0,
                    }
                }
                Err(error) => failure(name, error, Some(&workspace)),
            },
        },
        Command::Doctor { profile, out } => match doctor(repo, &profile, out.as_deref()) {
            Ok(available) => {
                let status = if available {
                    CommandStatus::Passed
                } else {
                    CommandStatus::Blocked
                };
                Reply {
                    summary: CommandSummary::without_run(name, status),
                    exit_code: status.exit_code(),
                }
            }
            Err(error) => failure(name, error, None),
        },
        Command::PrepareIsolation { profile, out } => match prepare_isolation(repo, &profile, &out)
        {
            Ok(()) => Reply {
                summary: CommandSummary::without_run(name, CommandStatus::Passed),
                exit_code: 0,
            },
            Err(error) => match cli_workspace::open(repo, &out) {
                Ok(workspace) => failure(name, error, Some(&workspace)),
                Err(_) => failure(name, error, None),
            },
        },
    }
}

async fn execute(
    repo: &Path,
    profile_path: &Path,
    suite: Suite,
    case: Option<&crate::domain::values::CatalogId>,
    out: &Path,
) -> ProofResult<PacketVerdict> {
    let profile = cli_workspace::profile(repo, profile_path, MAX_METADATA_BYTES)?;
    LoadedProfile::from_bytes(&profile)?;
    let scenarios = cli_workspace::reviewed(repo, Path::new(SCENARIOS), MAX_METADATA_BYTES)?;
    let examples = cli_workspace::reviewed(repo, Path::new(EXAMPLES), MAX_METADATA_BYTES)?;
    let manifest: ScenarioManifest = serde_json::from_slice(&scenarios).map_err(|_| invalid())?;
    let selection = manifest.select(suite, case, Digest::of(&scenarios))?;
    let run_id = EntityId::new();
    let bootstrap = EngineBootstrap {
        schema_version: ContractVersion::V0_1_0,
        run_id,
        started_at: AuditTime::now(),
        profile_sha256: Digest::of(&profile),
        fixture_manifest_sha256: Digest::of(&scenarios),
        contract_examples_sha256: Digest::of(&examples),
        orchestrator_sha256: executable_digest()?,
    };
    let workspace = cli_workspace::create(repo, out, run_id)?;
    let lease = super::harness::EngineLease::create(&workspace)?;
    let execution = async {
        workspace.write_new(Path::new("profile.json"), &profile)?;
        workspace.write_new(Path::new("fixture-manifest.json"), &scenarios)?;
        workspace.write_new(Path::new("cases.json"), &encode(&selection)?)?;
        workspace.write_new(Path::new(BOOTSTRAP_PATH), &encode(&bootstrap)?)?;
        workspace.write_new(Path::new(EXAMPLES_PATH), &examples)?;
        let status = engine(repo, &workspace, selection.selected_case_ids.len(), &lease).await;
        let bytes = match workspace.read(Path::new(OUTCOME_PATH), MAX_METADATA_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(match status {
                    Err(error) => error,
                    Ok(status) if status.code() == Some(3) => unavailable(),
                    Ok(status) if status.code() == Some(2) => invalid(),
                    Ok(status) if status.code() == Some(4) => {
                        ProofError::new(ErrorCode::Cancelled, "Owned engine was cancelled")
                    }
                    Ok(_) => integrity(),
                });
            }
        };
        let outcome: EngineOutcome = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
        let verdict = packet::publish(&workspace, &bootstrap, &selection, &outcome)?;
        if !status?.success() && verdict.selected_status == CommandStatus::Passed {
            return Err(integrity());
        }
        Ok(verdict)
    }
    .await;
    drop(lease);
    let quiescent = super::harness::EngineLease::quiescent(&workspace)?;
    super::control_owner::OwnedControl::reclaim_all(&workspace, quiescent.as_ref())?;
    // The engine has joined before this point. Immutable packet bytes and the
    // durable ledger are outside ephemeral and are never removed.
    workspace.cleanup_ephemeral()?;
    execution
}

async fn engine(
    repo: &Path,
    workspace: &OwnedDirectory,
    selected: usize,
    lease: &super::harness::EngineLease,
) -> ProofResult<ExitStatus> {
    let program = std::env::current_exe()
        .map_err(|_| unavailable())?
        .with_file_name("razen-engine");
    let metadata = std::fs::symlink_metadata(&program).map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(unavailable());
    }
    let profile =
        LoadedProfile::from_bytes(&workspace.read(Path::new("profile.json"), MAX_METADATA_BYTES)?)?;
    let duration = super::case_execution::execution_deadline(&profile)?
        .checked_mul(u32::try_from(selected).map_err(|_| invalid())?)
        .and_then(|duration| duration.checked_add(Duration::from_secs(60)))
        .ok_or_else(invalid)?;
    let deadline = Instant::now().checked_add(duration).ok_or_else(invalid)?;
    let mut interrupts = signal(SignalKind::interrupt()).map_err(|_| unavailable())?;
    let mut termination = signal(SignalKind::terminate()).map_err(|_| unavailable())?;
    let mut process = Process::new(program);
    process
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--run-id")
        .arg(workspace.run_id().to_string())
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(lease.child_stdio()?)
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = process.spawn().map_err(|_| unavailable())?;
    drop(process);
    // Child::wait closes its stored stdin; retain the sole parent-liveness writer ourselves.
    let mut keepalive = child.stdin.take();
    let stderr = child.stderr.take().ok_or_else(unavailable)?;
    let waiting = async {
        let mut stop_deadline = None;
        let mut timed_out = false;
        loop {
            if let Some(status) = child.try_wait().map_err(|_| unavailable())? {
                keepalive.take();
                if timed_out {
                    return Err(timeout());
                }
                return Ok(status);
            }
            if Instant::now() >= deadline && stop_deadline.is_none() {
                keepalive.take();
                stop_deadline = Some(Instant::now() + Duration::from_secs(75));
                timed_out = true;
            }
            if stop_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                child.start_kill().map_err(|_| unavailable())?;
                tokio::time::timeout(Duration::from_secs(5), child.wait())
                    .await
                    .map_err(|_| timeout())?
                    .map_err(|_| unavailable())?;
                return Err(timeout());
            }
            tokio::select! {
                _ = interrupts.recv(), if stop_deadline.is_none() => {
                    keepalive.take(); stop_deadline = Some(Instant::now() + Duration::from_secs(75));
                }
                _ = termination.recv(), if stop_deadline.is_none() => {
                    keepalive.take(); stop_deadline = Some(Instant::now() + Duration::from_secs(75));
                }
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    };
    let completion = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline + Duration::from_secs(80)),
        async { tokio::join!(waiting, drain(stderr)) },
    )
    .await;
    let (status, diagnostics) = match completion {
        Ok(observed) => observed,
        Err(_) => {
            keepalive.take();
            if child.try_wait().map_err(|_| unavailable())?.is_none() {
                child.start_kill().map_err(|_| unavailable())?;
                tokio::time::timeout(Duration::from_secs(5), child.wait())
                    .await
                    .map_err(|_| timeout())?
                    .map_err(|_| unavailable())?;
            }
            return Err(timeout());
        }
    };
    if status.is_err() || diagnostics.is_err() {
        keepalive.take();
        if child.try_wait().map_err(|_| unavailable())?.is_none() {
            child.start_kill().map_err(|_| unavailable())?;
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .map_err(|_| timeout())?
                .map_err(|_| unavailable())?;
        }
    }
    diagnostics?;
    status
}

async fn drain(mut stream: impl AsyncRead + Unpin) -> ProofResult<()> {
    let mut bytes = [0; 4096];
    let mut total = 0_usize;
    loop {
        let count = stream.read(&mut bytes).await.map_err(|_| unavailable())?;
        if count == 0 {
            return Ok(());
        }
        total = total.checked_add(count).ok_or_else(integrity)?;
        if total > 65_536 {
            return Err(integrity());
        }
    }
}

fn cleanup(repo: &Path, workspace: &OwnedDirectory, stop_isolation: bool) -> ProofResult<()> {
    let profile =
        LoadedProfile::from_bytes(&workspace.read(Path::new("profile.json"), MAX_METADATA_BYTES)?)?;
    let quiescent = super::harness::EngineLease::quiescent(workspace)?;
    super::control_owner::OwnedControl::reclaim_all(workspace, quiescent.as_ref())?;
    if workspace.path().join("run.json").symlink_metadata().is_ok() {
        let run: Run =
            serde_json::from_slice(&workspace.read(Path::new("run.json"), MAX_METADATA_BYTES)?)
                .map_err(|_| integrity())?;
        if run.run_id != workspace.run_id() || run.profile_sha256 != profile.sha256() {
            return Err(integrity());
        }
        let _ledger = Ledger::open_readonly(workspace, &profile)?;
        let evidence_root = OwnedDirectory::open(
            workspace.path().parent().ok_or_else(integrity)?,
            Path::new(workspace.path().file_name().ok_or_else(integrity)?),
        )?;
        let _evidence = EvidenceStore::open_readonly(std::sync::Arc::new(evidence_root))?;
    }
    if stop_isolation {
        if repo
            .join("target/r0-guest/prepared.json")
            .symlink_metadata()
            .is_ok()
        {
            crate::adapters::guest::preflight::PreparedGuestStop::discover(repo, &profile)?
                .stop_for_run(workspace.run_id())?;
        } else {
            crate::adapters::guest::preflight::retire_failed_preparation(
                repo,
                &profile,
                workspace.run_id(),
            )?;
        }
    }
    workspace.cleanup_ephemeral()
}

fn doctor(repo: &Path, profile_path: &Path, out: Option<&Path>) -> ProofResult<bool> {
    let bytes = cli_workspace::profile(repo, profile_path, MAX_METADATA_BYTES)?;
    let profile = LoadedProfile::from_bytes(&bytes)?;
    let report = super::isolation::doctor(repo, &profile)?;
    if let Some(out) = out {
        let workspace = cli_workspace::create(repo, out, EntityId::new())?;
        workspace.write_new(Path::new("profile.json"), &bytes)?;
        workspace.write_new(Path::new("doctor.json"), &encode(&report)?)?;
        workspace.cleanup_ephemeral()?;
    }
    Ok(report.available)
}

fn prepare_isolation(repo: &Path, profile_path: &Path, out: &Path) -> ProofResult<()> {
    let bytes = cli_workspace::profile(repo, profile_path, MAX_METADATA_BYTES)?;
    let profile = LoadedProfile::from_bytes(&bytes)?;
    let workspace = cli_workspace::create(repo, out, EntityId::new())?;
    workspace.write_new(Path::new("profile.json"), &bytes)?;
    let prepared = super::isolation::prepare(repo, &profile, &workspace);
    match prepared {
        Ok(guest) => {
            let publication = encode(guest.provenance()).and_then(|bytes| {
                workspace
                    .write_new(Path::new("isolation.json"), &bytes)
                    .map(|_| ())
            });
            let cleanup = workspace.cleanup_ephemeral();
            if let Err(error) = publication.and(cleanup) {
                guest.stop_for_run(workspace.run_id())?;
                return Err(error);
            }
            Ok(())
        }
        Err(error) => {
            workspace.cleanup_ephemeral()?;
            Err(error)
        }
    }
}

fn from_verdict(command: &'static str, verdict: PacketVerdict, selected: bool) -> Reply {
    let status = if selected {
        verdict.selected_status
    } else {
        verdict.full_status
    };
    let mut summary = CommandSummary::without_run(command, status);
    summary.run_ref = Some("run.json");
    summary.counts = verdict.counts;
    summary.review_status = verdict.review_status;
    summary.r0_exit_ready = verdict.r0_exit_ready;
    Reply {
        summary,
        exit_code: status.exit_code(),
    }
}

fn failure(command: &'static str, error: ProofError, workspace: Option<&OwnedDirectory>) -> Reply {
    let exit_code = match error.code {
        ErrorCode::InvalidInput | ErrorCode::UnsupportedVersion => 2,
        ErrorCode::ProviderUnavailable => 3,
        ErrorCode::Cancelled => 4,
        _ => 1,
    };
    let status = match exit_code {
        3 => CommandStatus::Blocked,
        4 => CommandStatus::Incomplete,
        _ => CommandStatus::Failed,
    };
    let mut summary = CommandSummary::without_run(command, status);
    if let Some(workspace) = workspace {
        fill_existing(&mut summary, workspace);
        #[derive(serde::Serialize)]
        struct Diagnostic<'a> {
            protocol: &'static str,
            command: &'static str,
            run_id: EntityId,
            error_id: EntityId,
            error: &'a ProofError,
        }
        let error_id = EntityId::new();
        let diagnostic = Diagnostic {
            protocol: "razen.proof/0.1.0",
            command,
            run_id: workspace.run_id(),
            error_id,
            error: &error,
        };
        let recorded = encode(&diagnostic).and_then(|bytes| {
            workspace.write_new(Path::new(&format!("errors/{error_id}.json")), &bytes)
        });
        match recorded {
            Ok(_) => summary.error_refs.push(error_id),
            Err(_) => eprintln!("Owned proof failure diagnostic could not be persisted"),
        }
    }
    eprintln!("Proof command failed: {:?}", error.code);
    Reply { summary, exit_code }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct ResultList(
    #[serde(deserialize_with = "crate::domain::validation::bounded_vec")] Vec<CaseResult>,
);

fn fill_existing(summary: &mut CommandSummary, workspace: &OwnedDirectory) {
    if let Ok(bytes) = workspace.read(Path::new("run.json"), MAX_METADATA_BYTES)
        && let Ok(run) = serde_json::from_slice::<Run>(&bytes)
        && run.run_id == workspace.run_id()
    {
        summary.run_ref = Some("run.json");
    }
    if let Ok(bytes) = workspace.read(Path::new("results.json"), MAX_METADATA_BYTES)
        && let Ok(results) = serde_json::from_slice::<ResultList>(&bytes)
        && results
            .0
            .iter()
            .all(|result| result.run_id == workspace.run_id())
        && let Ok(counts) = Counts::from_results(&results.0)
    {
        summary.counts = counts;
    }
}

fn encode(value: &impl serde::Serialize) -> ProofResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| integrity())?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(integrity());
    }
    Ok(bytes)
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Proof launch inputs do not match reviewed contracts",
    )
}
fn unavailable() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Selected proof operation or owned executable is unavailable",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Owned proof execution or packet integrity failed",
    )
}
fn timeout() -> ProofError {
    ProofError::new(
        ErrorCode::Timeout,
        "Owned proof engine exceeded its bounded execution deadline",
    )
}
