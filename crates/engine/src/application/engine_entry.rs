//! Private engine process boundary. Parent EOF is monitored outside the work thread.
use std::ffi::OsString;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

use rustix::fs::{self, OFlags};
use tokio::signal::unix::{SignalKind, signal};

use super::harness::EngineOutcome;
use super::{cli_workspace, engine};
use crate::domain::values::EntityId;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub async fn run(args: Vec<OsString>) -> u8 {
    let worker = match args.first().and_then(|arg| arg.to_str()) {
        Some("--recovery-fixture") => Some(super::recovery::engine_worker(&args[1..])),
        Some("--guest-orphan-worker") => {
            Some(crate::adapters::guest::proofs::orphan_worker(&args[1..]))
        }
        _ => None,
    };
    if let Some(result) = worker {
        return match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("Private fixture worker failed: {:?}", error.code);
                1
            }
        };
    }
    match execute(args).await {
        Ok(outcome) => {
            if outcome.interrupted {
                4
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("Engine boundary failed: {:?}", error.code);
            match error.code {
                ErrorCode::InvalidInput | ErrorCode::UnsupportedVersion => 2,
                ErrorCode::ProviderUnavailable => 3,
                ErrorCode::Cancelled => 4,
                _ => 1,
            }
        }
    }
}

async fn execute(args: Vec<OsString>) -> ProofResult<EngineOutcome> {
    let (path, run_id) = arguments(args)?;
    let repo = std::env::current_dir()
        .map_err(|_| invalid())?
        .canonicalize()
        .map_err(|_| invalid())?;
    let workspace = Arc::new(cli_workspace::open(&repo, &path)?);
    if workspace.run_id() != run_id {
        return Err(invalid());
    }
    let _lease = super::harness::EngineLease::inherit(&workspace)?;
    let mut interrupts = signal(SignalKind::interrupt()).map_err(|_| unavailable())?;
    let mut termination = signal(SignalKind::terminate()).map_err(|_| unavailable())?;
    let stdin = std::io::stdin();
    let flags = fs::fcntl_getfl(&stdin).map_err(|_| invalid())?;
    fs::fcntl_setfl(&stdin, flags | OFlags::NONBLOCK).map_err(|_| invalid())?;
    let mut input = stdin.lock();
    let stop = loop {
        let mut bytes = [0; 64];
        match input.read(&mut bytes) {
            Ok(0) => break true,
            Ok(_) => return Err(invalid()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => break false,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(unavailable()),
        }
    };
    let cancel = Arc::new(AtomicBool::new(stop));
    let worker_cancel = Arc::clone(&cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("razen-engine-work".into())
        .spawn(move || engine::execute(workspace, &repo, worker_cancel, sender))
        .map_err(|_| unavailable())?;
    let mut controller = None;
    let mut stop = stop;
    let mut barrier_attempted = false;
    let mut boundary_error = None;
    loop {
        if controller.is_none() {
            match receiver.try_recv() {
                Ok(ready) => controller = Some(ready),
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {}
            }
        }
        if stop && !barrier_attempted {
            if let Some(controller) = &controller {
                if let Err(error) = controller.cancel_barrier() {
                    boundary_error = Some(error);
                }
                barrier_attempted = true;
            }
            cancel.store(true, Ordering::SeqCst);
        }
        if worker.is_finished() {
            break;
        }
        if !stop {
            let mut bytes = [0; 64];
            match input.read(&mut bytes) {
                Ok(0) => stop = true,
                Ok(_) => {
                    stop = true;
                    boundary_error = Some(invalid());
                }
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock
                        || error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    stop = true;
                    boundary_error = Some(unavailable());
                }
            }
            if stop {
                continue;
            }
        }
        tokio::select! {
            _ = interrupts.recv() => stop = true,
            _ = termination.recv() => stop = true,
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
    let outcome = worker.join().map_err(|_| integrity())??;
    if let Some(error) = boundary_error {
        return Err(error);
    }
    Ok(outcome)
}

fn arguments(args: Vec<OsString>) -> ProofResult<(PathBuf, EntityId)> {
    if args.len() != 4 {
        return Err(invalid());
    }
    let mut workspace = None;
    let mut run_id = None;
    for pair in args.as_chunks::<2>().0 {
        match pair[0].to_str() {
            Some("--workspace") if workspace.is_none() => {
                let path = PathBuf::from(&pair[1]);
                if !path.is_absolute() {
                    return Err(invalid());
                }
                workspace = Some(path);
            }
            Some("--run-id") if run_id.is_none() => {
                run_id = Some(EntityId::parse(pair[1].to_str().ok_or_else(invalid)?)?);
            }
            _ => return Err(invalid()),
        }
    }
    Ok((workspace.ok_or_else(invalid)?, run_id.ok_or_else(invalid)?))
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Private engine launch contract is invalid",
    )
}
fn unavailable() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Owned engine lifetime channel is unavailable",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Owned engine worker did not terminate normally",
    )
}
