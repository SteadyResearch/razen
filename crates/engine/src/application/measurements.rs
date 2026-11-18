//! Warm, local fixture measurements. No product latency/load threshold is an R0 gate.
use super::profile::LoadedProfile;
use crate::adapters::command::{CommandLimits, capture};
use crate::domain::values::{Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Direct,
    Proxy,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub invocation_id: EntityId,
    pub result_artifact_id: EntityId,
    pub elapsed_us: u64,
    pub receiver_sequence: u64,
    pub body_bytes: u64,
    pub body_sha256: Digest,
    pub receiver_before: u64,
    pub receiver_after: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub profile_sha256: Digest,
    pub fixture_sha256: Digest,
    pub context_source: String,
    pub method: String,
    pub warmup_exchanges: u64,
    pub sample_body_bytes: u64,
    pub direct_warmup: Vec<Sample>,
    pub proxy_warmup: Vec<Sample>,
    pub direct_samples: Vec<Sample>,
    pub proxy_samples: Vec<Sample>,
    pub direct_us: Vec<u64>,
    pub proxy_us: Vec<u64>,
    pub direct_p50_us: u64,
    pub direct_p95_us: u64,
    pub proxy_p50_us: u64,
    pub proxy_p95_us: u64,
    pub direct_receiver_count: u64,
    pub proxy_receiver_count: u64,
    pub rss_kib_before: u64,
    pub rss_kib_after: u64,
    pub max_sampled_rss_kib: u64,
}

pub fn measure(
    profile: &LoadedProfile,
    fixture_sha256: Digest,
    mut exchange: impl FnMut(Route) -> ProofResult<Sample>,
) -> ProofResult<Measurements> {
    let config = &profile.config().measurement;
    let rss_kib_before = rss()?;
    let mut direct_warmup = Vec::with_capacity(config.latency_warmup_exchanges.get() as usize);
    let mut proxy_warmup = Vec::with_capacity(config.latency_warmup_exchanges.get() as usize);
    let mut direct_samples = Vec::with_capacity(config.latency_sample_exchanges.get() as usize);
    let mut proxy_samples = Vec::with_capacity(config.latency_sample_exchanges.get() as usize);
    for _ in 0..config.latency_warmup_exchanges.get() {
        direct_warmup.push(exchange(Route::Direct)?);
        proxy_warmup.push(exchange(Route::Proxy)?);
    }
    // Interleave routes on the SAME already-running fixture, avoiding a cold
    // direct batch versus a warm proxied batch or hidden compilation/provisioning.
    for _ in 0..config.latency_sample_exchanges.get() {
        direct_samples.push(exchange(Route::Direct)?);
        proxy_samples.push(exchange(Route::Proxy)?);
    }
    let direct_us: Vec<_> = direct_samples.iter().map(|s| s.elapsed_us).collect();
    let proxy_us: Vec<_> = proxy_samples.iter().map(|s| s.elapsed_us).collect();
    let rss_kib_after = rss()?;
    let direct_receiver_count = arrivals(direct_warmup.iter().chain(&direct_samples))?;
    let proxy_receiver_count = arrivals(proxy_warmup.iter().chain(&proxy_samples))?;
    Ok(Measurements { profile_sha256: profile.sha256(), fixture_sha256, context_source: "run.environment".to_owned(),
        method: "Interleaved warm runtime/receiver; full local exchange includes fresh scoped proxy/TCP setup and owned I/O closure; admission/publication and RSS sampling excluded".to_owned(),
        warmup_exchanges: config.latency_warmup_exchanges.get(), sample_body_bytes: config.sample_body_bytes.get(),
        direct_receiver_count, proxy_receiver_count,
        direct_p50_us: percentile(&direct_us, 50)?, direct_p95_us: percentile(&direct_us, 95)?,
        proxy_p50_us: percentile(&proxy_us, 50)?, proxy_p95_us: percentile(&proxy_us, 95)?,
        direct_us, proxy_us, direct_warmup, proxy_warmup, direct_samples, proxy_samples,
        rss_kib_before, rss_kib_after, max_sampled_rss_kib: rss_kib_before.max(rss_kib_after) })
}
pub fn percentile(samples: &[u64], percentile: usize) -> ProofResult<u64> {
    if samples.is_empty() || samples.len() > 4096 || percentile == 0 || percentile > 100 {
        return Err(invalid());
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = sorted
        .len()
        .checked_mul(percentile)
        .ok_or_else(invalid)?
        .div_ceil(100);
    Ok(sorted[rank - 1])
}
fn rss() -> ProofResult<u64> {
    let pid = std::process::id().to_string();
    let output = capture(
        Path::new("/bin/ps"),
        &[
            OsStr::new("-o"),
            OsStr::new("rss="),
            OsStr::new("-p"),
            OsStr::new(&pid),
        ],
        None,
        CommandLimits {
            stdin_bytes: 0,
            stdout_bytes: 1024,
            stderr_bytes: 1024,
            timeout: Duration::from_secs(2),
        },
    )?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| invalid())?
        .trim()
        .parse::<u64>()
        .map_err(|_| invalid())?;
    if value == 0 {
        return Err(invalid());
    }
    Ok(value)
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Warm fixture measurement facts are incomplete or invalid",
    )
}
fn arrivals<'a>(mut samples: impl Iterator<Item = &'a Sample>) -> ProofResult<u64> {
    samples.try_fold(0_u64, |sum, sample| {
        let arrivals = sample
            .receiver_after
            .checked_sub(sample.receiver_before)
            .ok_or_else(invalid)?;
        if arrivals != 1 {
            return Err(invalid());
        }
        sum.checked_add(arrivals).ok_or_else(invalid)
    })
}

pub(crate) fn write_raw(
    workspace: &crate::adapters::workspace::OwnedDirectory,
    bytes: &[u8],
) -> ProofResult<std::path::PathBuf> {
    let path = std::path::PathBuf::from(format!(
        "ephemeral/us2-measurements/{}.json",
        EntityId::new()
    ));
    workspace.write_new(&path, bytes)?;
    Ok(path)
}
