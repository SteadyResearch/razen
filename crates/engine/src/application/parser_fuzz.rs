//! Versioned, deterministic byte campaigns shared by proofs and the host CLI.
//! Campaign input counts include baseline replays. A failing input is additionally
//! replayed from immutable evidence, even if the execution deadline has expired.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use rustix::fs::{self, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};

use crate::adapters::workspace::OwnedDirectory;
use crate::application::profile::LoadedProfile;
use crate::domain::values::{ContractVersion, Digest, WireInt, non_null_optional};
use crate::protocol::codec::{ChannelRole, Direction, decode_frame, encode_frame_into};
use crate::protocol::contracts::{TrustedContractContext, parse_document};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_CORPUS_ENTRIES: usize = 256;
const MAX_CORPUS_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const SOURCE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzTarget {
    Framing,
    Contracts,
}

impl FuzzTarget {
    fn report_path(self) -> &'static Path {
        Path::new(match self {
            Self::Framing => "framing-fuzz.json",
            Self::Contracts => "contracts-fuzz.json",
        })
    }

    fn failure_report_path(self) -> &'static Path {
        Path::new(match self {
            Self::Framing => "framing-fuzz-failure.json",
            Self::Contracts => "contracts-fuzz-failure.json",
        })
    }

    fn counterexample_path(self) -> &'static Path {
        Path::new(match self {
            Self::Framing => "framing-counterexample.bin",
            Self::Contracts => "contracts-counterexample.bin",
        })
    }

    fn replay_path(self) -> &'static Path {
        Path::new(match self {
            Self::Framing => "framing-replay.json",
            Self::Contracts => "contracts-replay.json",
        })
    }

    fn seed_replays_path(self) -> &'static Path {
        Path::new(match self {
            Self::Framing => "framing-seed-replays.json",
            Self::Contracts => "contracts-seed-replays.json",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedValidity {
    Accept,
    Reject,
    Either,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzContext {
    pub expectation: ExpectedValidity,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub role: Option<ChannelRole>,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub direction: Option<Direction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleOutcome {
    AcceptedRoundTrip,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "ReportFields")]
pub struct FuzzReport {
    pub target: FuzzTarget,
    pub profile_sha256: Digest,
    pub corpus_sha256: Digest,
    pub seed: u64,
    pub mutation_version: ContractVersion,
    pub max_inputs: u64,
    pub max_input_bytes: u64,
    pub deadline_ms: u64,
    pub executed_inputs: u64,
    pub elapsed_us: u64,
    pub valid_round_trips: u64,
    pub explicit_rejections: u64,
    pub replay_checks: u64,
    pub counterexamples: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportFields {
    target: FuzzTarget,
    profile_sha256: Digest,
    corpus_sha256: Digest,
    seed: WireInt,
    mutation_version: ContractVersion,
    max_inputs: WireInt,
    max_input_bytes: WireInt,
    deadline_ms: WireInt,
    executed_inputs: WireInt,
    elapsed_us: WireInt,
    valid_round_trips: WireInt,
    explicit_rejections: WireInt,
    replay_checks: WireInt,
    counterexamples: WireInt,
}

impl TryFrom<ReportFields> for FuzzReport {
    type Error = &'static str;

    fn try_from(fields: ReportFields) -> Result<Self, Self::Error> {
        let report = Self {
            target: fields.target,
            profile_sha256: fields.profile_sha256,
            corpus_sha256: fields.corpus_sha256,
            seed: fields.seed.get(),
            mutation_version: fields.mutation_version,
            max_inputs: fields.max_inputs.get(),
            max_input_bytes: fields.max_input_bytes.get(),
            deadline_ms: fields.deadline_ms.get(),
            executed_inputs: fields.executed_inputs.get(),
            elapsed_us: fields.elapsed_us.get(),
            valid_round_trips: fields.valid_round_trips.get(),
            explicit_rejections: fields.explicit_rejections.get(),
            replay_checks: fields.replay_checks.get(),
            counterexamples: fields.counterexamples.get(),
        };
        if report.max_inputs == 0
            || report.max_inputs > 10_000
            || report.max_input_bytes == 0
            || report.max_input_bytes > 65_536
            || report.deadline_ms == 0
            || report.deadline_ms > 30_000
            || report.counterexamples > 1
            || report.executed_inputs > report.max_inputs + report.counterexamples
            || report.valid_round_trips > report.executed_inputs
            || report.explicit_rejections > report.executed_inputs - report.valid_round_trips
            || report.replay_checks > report.executed_inputs
        {
            return Err("invalid parser fuzz report counts or limits");
        }
        if report.counterexamples == 0
            && (report.executed_inputs != report.max_inputs
                || report.valid_round_trips + report.explicit_rejections != report.executed_inputs
                || report.valid_round_trips == 0
                || report.explicit_rejections == 0
                || report.replay_checks == 0
                || report.elapsed_us > report.deadline_ms * 1000)
        {
            return Err("incomplete parser fuzz report cannot establish success");
        }
        Ok(report)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: ContractVersion,
    mutation_version: ContractVersion,
    entries: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    path: String,
    target: FuzzTarget,
    valid: bool,
    sha256: Digest,
    #[serde(default, deserialize_with = "non_null_optional")]
    role: Option<ChannelRole>,
    #[serde(default, deserialize_with = "non_null_optional")]
    direction: Option<Direction>,
}

struct Seed {
    bytes: Vec<u8>,
    sha256: Digest,
    context: FuzzContext,
}

struct Corpus {
    sha256: Digest,
    seeds: Vec<Seed>,
    invalid_count: usize,
}

struct Clock {
    started: Instant,
    limit: Duration,
}

impl Clock {
    fn exceeded(&self) -> bool {
        self.started.elapsed() >= self.limit
    }

    fn elapsed_us(&self) -> ProofResult<u64> {
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).map_err(|_| {
            ProofError::new(
                ErrorCode::Timeout,
                "Parser fuzz elapsed time exceeds wire bounds",
            )
        })?;
        Ok(WireInt::new(elapsed)?.get())
    }
}

/// Execute the complete per-target profile budget. The caller's oracle must perform
/// a real parser round-trip for acceptance and explicitly classify parser rejection.
/// Ordinary mutations have no presumed validity; only NUL-prefix mutations must reject.
pub fn run_campaign<F>(
    profile: &LoadedProfile,
    corpus_root: &Path,
    evidence: &OwnedDirectory,
    target: FuzzTarget,
    mut oracle: F,
) -> ProofResult<FuzzReport>
where
    F: FnMut(&[u8], FuzzContext) -> ProofResult<OracleOutcome>,
{
    let limits = &profile.config().parser_fuzz;
    let clock = Clock {
        started: Instant::now(),
        limit: Duration::from_millis(limits.deadline_ms.get()),
    };
    let max_bytes =
        usize::try_from(limits.max_input_bytes.get()).map_err(|_| provenance_error())?;
    let corpus = load_corpus(corpus_root, target, max_bytes, limits.max_inputs.get())?;
    let mut report = FuzzReport {
        target,
        profile_sha256: profile.sha256(),
        corpus_sha256: corpus.sha256,
        seed: limits.seed.get(),
        mutation_version: limits.mutation_version,
        max_inputs: limits.max_inputs.get(),
        max_input_bytes: limits.max_input_bytes.get(),
        deadline_ms: limits.deadline_ms.get(),
        executed_inputs: 0,
        elapsed_us: 0,
        valid_round_trips: 0,
        explicit_rejections: 0,
        replay_checks: 0,
        counterexamples: 0,
    };
    let mut output = Vec::with_capacity(4096);
    for seed in &corpus.seeds {
        if let Err(failure) = check_input(
            &seed.bytes,
            seed.context,
            false,
            &clock,
            &mut report,
            &mut oracle,
        ) {
            return save_failure(
                evidence,
                FailedCase {
                    input: &seed.bytes,
                    context: seed.context,
                    failure,
                },
                &clock,
                &mut report,
                &mut oracle,
                target.report_path(),
                &mut output,
            );
        }
    }
    let mut baseline_replays = Vec::with_capacity(corpus.invalid_count);
    for seed in &corpus.seeds {
        if seed.context.expectation != ExpectedValidity::Reject {
            continue;
        }
        if let Err(failure) = check_input(
            &seed.bytes,
            seed.context,
            true,
            &clock,
            &mut report,
            &mut oracle,
        ) {
            return save_failure(
                evidence,
                FailedCase {
                    input: &seed.bytes,
                    context: seed.context,
                    failure,
                },
                &clock,
                &mut report,
                &mut oracle,
                target.report_path(),
                &mut output,
            );
        }
        baseline_replays.push(SeedReplay {
            input_sha256: seed.sha256,
            context: seed.context,
            original: OracleOutcome::Rejected,
            replay: OracleOutcome::Rejected,
        });
    }
    let mut input = Vec::with_capacity(max_bytes);
    let mut random = Random(limits.seed.get());
    let mut mutation_index = 0_u64;
    let mut last_context = corpus.seeds[0].context;
    while report.executed_inputs < report.max_inputs {
        let seed = &corpus.seeds[random.index(corpus.seeds.len())];
        let donor = &corpus.seeds[random.index(corpus.seeds.len())];
        let guaranteed_invalid = mutate(
            &mut input,
            &seed.bytes,
            &donor.bytes,
            mutation_index,
            max_bytes,
            &mut random,
        );
        let context = FuzzContext {
            expectation: if guaranteed_invalid {
                ExpectedValidity::Reject
            } else {
                ExpectedValidity::Either
            },
            ..seed.context
        };
        last_context = context;
        if let Err(failure) = check_input(&input, context, false, &clock, &mut report, &mut oracle)
        {
            return save_failure(
                evidence,
                FailedCase {
                    input: &input,
                    context,
                    failure,
                },
                &clock,
                &mut report,
                &mut oracle,
                target.report_path(),
                &mut output,
            );
        }
        mutation_index += 1;
    }
    report.elapsed_us = clock.elapsed_us()?;
    write_json(
        evidence,
        target.seed_replays_path(),
        &baseline_replays,
        &mut output,
    )?;
    // Persistence is part of the aggregate deadline too. Do not publish a passing
    // report when the final replay evidence write has consumed the remaining budget.
    if clock.exceeded() {
        return save_failure(
            evidence,
            FailedCase {
                input: &input,
                context: last_context,
                failure: FailedInput {
                    kind: FailureKind::Deadline,
                    observation: Observation::expired(),
                },
            },
            &clock,
            &mut report,
            &mut oracle,
            target.report_path(),
            &mut output,
        );
    }
    report.elapsed_us = clock.elapsed_us()?;
    write_json(evidence, target.report_path(), &report, &mut output)?;
    if clock.exceeded() {
        // Immutable publication cannot be replaced. Retain the terminal failure
        // separately as well as the exact counterexample and its real replay.
        return save_failure(
            evidence,
            FailedCase {
                input: &input,
                context: last_context,
                failure: FailedInput {
                    kind: FailureKind::Deadline,
                    observation: Observation::expired(),
                },
            },
            &clock,
            &mut report,
            &mut oracle,
            target.failure_report_path(),
            &mut output,
        );
    }
    Ok(report)
}

pub fn run_framing(
    profile: &LoadedProfile,
    corpus_root: &Path,
    evidence: &OwnedDirectory,
) -> ProofResult<FuzzReport> {
    let max_bytes = usize::try_from(profile.config().parser_fuzz.max_input_bytes.get())
        .map_err(|_| provenance_error())?;
    let mut encoded = Vec::new();
    run_campaign(
        profile,
        corpus_root,
        evidence,
        FuzzTarget::Framing,
        |bytes, context| {
            let role = context.role.ok_or_else(provenance_error)?;
            let direction = context.direction.ok_or_else(provenance_error)?;
            let first = match decode_frame(bytes, max_bytes, role, direction) {
                Ok(envelope) => envelope,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::InvalidInput
                            | ErrorCode::UnsupportedVersion
                            | ErrorCode::UnsupportedProtocol
                            | ErrorCode::BudgetExhausted
                    ) =>
                {
                    return Ok(OracleOutcome::Rejected);
                }
                Err(_) => return Err(oracle_error()),
            };
            encode_frame_into(&first, &mut encoded, max_bytes).map_err(|_| oracle_error())?;
            let second =
                decode_frame(&encoded, max_bytes, role, direction).map_err(|_| oracle_error())?;
            if first.protocol != second.protocol
                || first.message_id != second.message_id
                || first.kind != second.kind
                || first.correlation_id != second.correlation_id
                || first.payload.get() != second.payload.get()
            {
                return Err(oracle_error());
            }
            Ok(OracleOutcome::AcceptedRoundTrip)
        },
    )
}

pub fn run_contracts(
    profile: &LoadedProfile,
    corpus_root: &Path,
    evidence: &OwnedDirectory,
    trusted_context: &TrustedContractContext,
) -> ProofResult<FuzzReport> {
    let wire_limit = usize::try_from(profile.config().protocol.message_limit_bytes.get())
        .map_err(|_| provenance_error())?;
    let mut encoded = Vec::new();
    run_campaign(
        profile,
        corpus_root,
        evidence,
        FuzzTarget::Contracts,
        |bytes, _context| {
            let first = match parse_document(bytes, trusted_context) {
                Ok(document) => document,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::InvalidInput
                            | ErrorCode::UnsupportedVersion
                            | ErrorCode::BudgetExhausted
                    ) =>
                {
                    return Ok(OracleOutcome::Rejected);
                }
                Err(_) => return Err(oracle_error()),
            };
            encode_frame_into(&first, &mut encoded, wire_limit).map_err(|_| oracle_error())?;
            let second = parse_document(&encoded, trusted_context).map_err(|_| oracle_error())?;
            if first != second {
                return Err(oracle_error());
            }
            Ok(OracleOutcome::AcceptedRoundTrip)
        },
    )
}

fn load_corpus(
    root: &Path,
    target: FuzzTarget,
    max_bytes: usize,
    max_inputs: u64,
) -> ProofResult<Corpus> {
    let directory = open_source_root(root)?;
    let bytes = read_source(&directory, Path::new("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| provenance_error())?;
    if manifest.schema_version != ContractVersion::V0_1_0
        || manifest.mutation_version != ContractVersion::V0_1_0
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_CORPUS_ENTRIES
    {
        return Err(provenance_error());
    }
    let mut paths = BTreeSet::new();
    let mut selected_count = 0;
    let mut invalid_count = 0;
    for entry in &manifest.entries {
        validate_source_path(&entry.path)?;
        if !paths.insert(entry.path.as_str()) {
            return Err(provenance_error());
        }
        match entry.target {
            FuzzTarget::Framing if entry.role.is_some() && entry.direction.is_some() => {}
            FuzzTarget::Contracts if entry.role.is_none() && entry.direction.is_none() => {}
            _ => return Err(provenance_error()),
        }
        if entry.target == target {
            selected_count += 1;
            invalid_count += usize::from(!entry.valid);
        }
    }
    // Reserve one complete cycle of the four byte operators and the guaranteed
    // invalid mutation, in addition to every baseline and every invalid replay.
    if invalid_count == 0
        || invalid_count == selected_count
        || (selected_count + invalid_count + 5) as u64 > max_inputs
    {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Parser fuzz budget must cover valid and invalid seed oracles and mutations",
        ));
    }
    let mut seeds = Vec::with_capacity(selected_count);
    let mut total_bytes = 0_usize;
    for entry in manifest.entries {
        if entry.target != target {
            continue;
        }
        let input = read_source(&directory, Path::new(&entry.path), max_bytes)?;
        total_bytes = total_bytes
            .checked_add(input.len())
            .ok_or_else(provenance_error)?;
        if total_bytes > MAX_CORPUS_BYTES || Digest::of(&input) != entry.sha256 {
            return Err(provenance_error());
        }
        seeds.push(Seed {
            bytes: input,
            sha256: entry.sha256,
            context: FuzzContext {
                expectation: if entry.valid {
                    ExpectedValidity::Accept
                } else {
                    ExpectedValidity::Reject
                },
                role: entry.role,
                direction: entry.direction,
            },
        });
    }
    Ok(Corpus {
        sha256: Digest::of(&bytes),
        seeds,
        invalid_count,
    })
}

fn validate_source_path(path: &str) -> ProofResult<()> {
    if path.is_empty()
        || path.len() > 512
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(provenance_error());
    }
    Ok(())
}

fn open_source_root(root: &Path) -> ProofResult<File> {
    if root.as_os_str().is_empty() {
        return Err(provenance_error());
    }
    let start = if root.is_absolute() { "/" } else { "." };
    let mut directory = File::from(
        fs::open(start, DIRECTORY_FLAGS, Mode::empty()).map_err(|_| provenance_error())?,
    );
    for component in root.components() {
        match component {
            Component::Normal(name) => {
                directory = File::from(
                    fs::openat(&directory, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|_| provenance_error())?,
                );
            }
            Component::RootDir | Component::CurDir => {}
            _ => return Err(provenance_error()),
        }
    }
    Ok(directory)
}

fn read_source(directory: &File, relative: &Path, max_bytes: usize) -> ProofResult<Vec<u8>> {
    let mut parent = File::from(
        fs::openat(directory, ".", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| provenance_error())?,
    );
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(provenance_error());
        };
        if components.peek().is_some() {
            parent = File::from(
                fs::openat(&parent, name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|_| provenance_error())?,
            );
            continue;
        }
        let file = File::from(
            fs::openat(&parent, name, SOURCE_FLAGS, Mode::empty())
                .map_err(|_| provenance_error())?,
        );
        let stat = fs::fstat(&file).map_err(|_| provenance_error())?;
        let length = usize::try_from(stat.st_size).map_err(|_| provenance_error())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || length > max_bytes {
            return Err(provenance_error());
        }
        let mut bytes = Vec::with_capacity(length);
        file.take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| provenance_error())?;
        if bytes.len() > max_bytes || bytes.len() != length {
            return Err(provenance_error());
        }
        return Ok(bytes);
    }
    Err(provenance_error())
}

/// SplitMix64: wrapping integer arithmetic is part of mutation version 0.1.0.
/// It is reproducible byte generation, never an identity or security primitive.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, upper_exclusive: usize) -> usize {
        (self.next() % upper_exclusive as u64) as usize
    }
}

fn mutate(
    input: &mut Vec<u8>,
    seed: &[u8],
    donor: &[u8],
    iteration: u64,
    max_bytes: usize,
    random: &mut Random,
) -> bool {
    input.clear();
    input.extend_from_slice(seed);
    match iteration % 5 {
        0 if input.len() < max_bytes => {
            let position = random.index(input.len() + 1);
            input.insert(position, random.next() as u8);
        }
        1 if !input.is_empty() => {
            input.remove(random.index(input.len()));
        }
        3 => {
            let prefix = random.index(input.len() + 1);
            let start = random.index(donor.len() + 1);
            let length = random
                .index(donor.len() - start + 1)
                .min(max_bytes - prefix);
            input.truncate(prefix);
            input.extend_from_slice(&donor[start..start + length]);
        }
        4 => {
            if input.is_empty() {
                input.push(0);
            } else {
                input[0] = 0;
            }
            return true;
        }
        _ => {
            let byte = random.next() as u8;
            if input.is_empty() {
                input.push(byte);
            } else {
                let position = random.index(input.len());
                input[position] = byte;
            }
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Deadline,
    Panic,
    OracleError,
    AcceptanceMismatch,
}

#[derive(Serialize)]
struct Observation {
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<OracleOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<ErrorCode>,
    panicked: bool,
    deadline_exceeded: bool,
}

impl Observation {
    fn expired() -> Self {
        Self {
            outcome: None,
            error_code: None,
            panicked: false,
            deadline_exceeded: true,
        }
    }

    fn failure(&self, expectation: ExpectedValidity) -> Option<FailureKind> {
        if self.deadline_exceeded {
            return Some(FailureKind::Deadline);
        }
        if self.panicked {
            return Some(FailureKind::Panic);
        }
        if self.error_code.is_some() {
            return Some(FailureKind::OracleError);
        }
        match (expectation, self.outcome) {
            (ExpectedValidity::Accept, Some(OracleOutcome::AcceptedRoundTrip))
            | (ExpectedValidity::Reject, Some(OracleOutcome::Rejected))
            | (ExpectedValidity::Either, Some(_)) => None,
            _ => Some(FailureKind::AcceptanceMismatch),
        }
    }
}

struct FailedInput {
    kind: FailureKind,
    observation: Observation,
}

fn observe<F>(input: &[u8], context: FuzzContext, clock: &Clock, oracle: &mut F) -> Observation
where
    F: FnMut(&[u8], FuzzContext) -> ProofResult<OracleOutcome>,
{
    let result = catch_unwind(AssertUnwindSafe(|| oracle(input, context)));
    let mut observation = Observation {
        outcome: None,
        error_code: None,
        panicked: false,
        deadline_exceeded: clock.exceeded(),
    };
    match result {
        Ok(Ok(outcome)) => observation.outcome = Some(outcome),
        Ok(Err(error)) => observation.error_code = Some(error.code),
        Err(_) => observation.panicked = true,
    }
    observation
}

fn count_outcome(report: &mut FuzzReport, observation: &Observation) {
    if observation.deadline_exceeded || observation.panicked || observation.error_code.is_some() {
        return;
    }
    match observation.outcome {
        Some(OracleOutcome::AcceptedRoundTrip) => report.valid_round_trips += 1,
        Some(OracleOutcome::Rejected) => report.explicit_rejections += 1,
        None => {}
    }
}

fn check_input<F>(
    input: &[u8],
    context: FuzzContext,
    replay: bool,
    clock: &Clock,
    report: &mut FuzzReport,
    oracle: &mut F,
) -> Result<(), FailedInput>
where
    F: FnMut(&[u8], FuzzContext) -> ProofResult<OracleOutcome>,
{
    if clock.exceeded() {
        return Err(FailedInput {
            kind: FailureKind::Deadline,
            observation: Observation::expired(),
        });
    }
    report.executed_inputs += 1;
    report.replay_checks += u64::from(replay);
    let observation = observe(input, context, clock, oracle);
    count_outcome(report, &observation);
    if let Some(kind) = observation.failure(context.expectation) {
        return Err(FailedInput { kind, observation });
    }
    Ok(())
}

#[derive(Serialize)]
struct SeedReplay {
    input_sha256: Digest,
    context: FuzzContext,
    original: OracleOutcome,
    replay: OracleOutcome,
}

#[derive(Serialize)]
struct CounterexampleReplay<'a> {
    target: FuzzTarget,
    profile_sha256: Digest,
    corpus_sha256: Digest,
    seed: u64,
    mutation_version: ContractVersion,
    max_inputs: u64,
    max_input_bytes: u64,
    deadline_ms: u64,
    input_index: u64,
    input_sha256: Digest,
    input_bytes: u64,
    context: FuzzContext,
    failure: FailureKind,
    original: &'a Observation,
    replay: &'a Observation,
    replay_failure: Option<FailureKind>,
    replay_matches_original: bool,
}

struct FailedCase<'a> {
    input: &'a [u8],
    context: FuzzContext,
    failure: FailedInput,
}

fn save_failure<F>(
    evidence: &OwnedDirectory,
    failed: FailedCase<'_>,
    clock: &Clock,
    report: &mut FuzzReport,
    oracle: &mut F,
    report_path: &Path,
    output: &mut Vec<u8>,
) -> ProofResult<FuzzReport>
where
    F: FnMut(&[u8], FuzzContext) -> ProofResult<OracleOutcome>,
{
    let FailedCase {
        input,
        context,
        failure,
    } = failed;
    report.counterexamples = 1;
    let original_was_called = failure.observation.outcome.is_some()
        || failure.observation.error_code.is_some()
        || failure.observation.panicked;
    let input_index = if original_was_called {
        report.executed_inputs - 1
    } else {
        report.executed_inputs
    };
    let digest = evidence.write_new(report.target.counterexample_path(), input)?;
    let saved = evidence.read(
        report.target.counterexample_path(),
        report.max_input_bytes as usize,
    )?;
    if Digest::of(&saved) != digest {
        return Err(provenance_error());
    }
    // Diagnostic replay is deliberately attempted after timeout as well. Neither
    // a timeout nor a panic is ever converted into an expected parser rejection.
    let replay = observe(&saved, context, clock, oracle);
    report.executed_inputs += 1;
    report.replay_checks += 1;
    count_outcome(report, &replay);
    report.elapsed_us = clock.elapsed_us()?;
    let metadata = CounterexampleReplay {
        target: report.target,
        profile_sha256: report.profile_sha256,
        corpus_sha256: report.corpus_sha256,
        seed: report.seed,
        mutation_version: report.mutation_version,
        max_inputs: report.max_inputs,
        max_input_bytes: report.max_input_bytes,
        deadline_ms: report.deadline_ms,
        input_index,
        input_sha256: digest,
        input_bytes: WireInt::new(saved.len() as u64)?.get(),
        context,
        failure: failure.kind,
        original: &failure.observation,
        replay: &replay,
        replay_failure: replay.failure(context.expectation),
        replay_matches_original: failure.observation.outcome == replay.outcome
            && failure.observation.error_code == replay.error_code
            && failure.observation.panicked == replay.panicked,
    };
    write_json(evidence, report.target.replay_path(), &metadata, output)?;
    report.elapsed_us = clock.elapsed_us()?;
    write_json(evidence, report_path, report, output)?;
    Err(match failure.kind {
        FailureKind::Deadline => ProofError::new(
            ErrorCode::Timeout,
            "Parser fuzz campaign exceeded the aggregate deadline",
        ),
        FailureKind::Panic => ProofError::new(
            ErrorCode::OutputInvalid,
            "Parser fuzz oracle panicked; replay evidence retained",
        ),
        FailureKind::OracleError => ProofError::new(
            ErrorCode::OutputInvalid,
            "Parser fuzz oracle failed; replay evidence retained",
        ),
        FailureKind::AcceptanceMismatch => ProofError::new(
            ErrorCode::OutputInvalid,
            "Parser fuzz acceptance counterexample; replay evidence retained",
        ),
    })
}

struct BoundedOutput<'a>(&'a mut Vec<u8>);

impl Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_EVIDENCE_BYTES - self.0.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_json<T: Serialize + ?Sized>(
    evidence: &OwnedDirectory,
    path: &Path,
    value: &T,
    output: &mut Vec<u8>,
) -> ProofResult<()> {
    output.clear();
    serde_json::to_writer(BoundedOutput(&mut *output), value).map_err(|_| {
        ProofError::new(
            ErrorCode::OutputInvalid,
            "Parser fuzz evidence cannot be encoded within bounds",
        )
    })?;
    evidence.write_new(path, output)?;
    Ok(())
}

fn provenance_error() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Parser corpus provenance is missing or invalid",
    )
}

fn oracle_error() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Parser fuzz round-trip or rejection classification failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use crate::domain::values::EntityId;

    const VALID: &[u8] = b"{\"value\":1}";
    const INVALID: &[u8] = b"{\"value\":-1}";

    struct Fixture {
        root: PathBuf,
        corpus: PathBuf,
        evidence: OwnedDirectory,
    }

    impl Fixture {
        fn new(valid: &[u8]) -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("razen-parser-fuzz-{}", EntityId::new()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let corpus = root.join("corpus");
            std::fs::create_dir(&corpus).unwrap();
            std::fs::write(corpus.join("valid.json"), valid).unwrap();
            std::fs::write(corpus.join("invalid.json"), INVALID).unwrap();
            let manifest = serde_json::json!({
                "schema_version": "0.1.0",
                "mutation_version": "0.1.0",
                "entries": [
                    {"path":"valid.json", "target":"contracts", "valid":true, "sha256":Digest::of(valid)},
                    {"path":"invalid.json", "target":"contracts", "valid":false, "sha256":Digest::of(INVALID)}
                ]
            });
            std::fs::write(
                corpus.join("manifest.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let evidence =
                OwnedDirectory::create(&root, Path::new("evidence"), EntityId::new()).unwrap();
            Self {
                root,
                corpus,
                evidence,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn profile(deadline_ms: u64) -> LoadedProfile {
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../specs/001-r0-feasibility/contracts/pilot-profile.json"
        ))
        .unwrap();
        value["parser_fuzz"]["max_inputs"] = 32.into();
        value["parser_fuzz"]["max_input_bytes"] = 128.into();
        value["parser_fuzz"]["deadline_ms"] = deadline_ms.into();
        LoadedProfile::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        value: WireInt,
    }

    fn typed_oracle(bytes: &[u8], _: FuzzContext) -> ProofResult<OracleOutcome> {
        let Ok(record) = serde_json::from_slice::<Record>(bytes) else {
            return Ok(OracleOutcome::Rejected);
        };
        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: Record = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(record, decoded);
        Ok(OracleOutcome::AcceptedRoundTrip)
    }

    #[test]
    fn mutation_version_has_fixed_wrapping_generator_outputs() {
        let mut random = Random(0);
        assert_eq!(random.next(), 0xe220a8397b1dcdaf);
        assert_eq!(random.next(), 0x6e789e6aa1b965f4);
    }

    #[test]
    fn seeded_campaign_repeats_the_same_full_bounded_inputs_and_invalid_replays() {
        let first = Fixture::new(VALID);
        let second = Fixture::new(VALID);
        let profile = profile(1000);
        let mut first_inputs = Vec::new();
        let first_report = run_campaign(
            &profile,
            &first.corpus,
            &first.evidence,
            FuzzTarget::Contracts,
            |bytes, context| {
                first_inputs.push((bytes.to_vec(), context));
                typed_oracle(bytes, context)
            },
        )
        .unwrap();
        let mut second_inputs = Vec::new();
        let second_report = run_campaign(
            &profile,
            &second.corpus,
            &second.evidence,
            FuzzTarget::Contracts,
            |bytes, context| {
                second_inputs.push((bytes.to_vec(), context));
                typed_oracle(bytes, context)
            },
        )
        .unwrap();
        assert_eq!(first_inputs, second_inputs);
        let mut encoded_report = serde_json::to_value(&first_report).unwrap();
        encoded_report["seed"] = 9_007_199_254_740_992_u64.into();
        assert!(serde_json::from_value::<FuzzReport>(encoded_report.clone()).is_err());
        encoded_report["seed"] = first_report.seed.into();
        encoded_report["executed_inputs"] = 31.into();
        assert!(serde_json::from_value::<FuzzReport>(encoded_report).is_err());
        assert_eq!(first_inputs.len(), 32);
        assert!(first_inputs.iter().all(|(bytes, _)| bytes.len() <= 128));
        assert_eq!(first_report.executed_inputs, 32);
        assert_eq!(
            first_report.valid_round_trips,
            second_report.valid_round_trips
        );
        assert_eq!(
            first_report.explicit_rejections,
            second_report.explicit_rejections
        );
        assert_eq!(first_report.replay_checks, 1);
        assert_eq!(first_report.counterexamples, 0);
        assert!(
            first_inputs
                .iter()
                .any(|(_, context)| context.expectation == ExpectedValidity::Either)
        );
        assert!(
            first_inputs
                .iter()
                .any(|(bytes, context)| bytes.first() == Some(&0)
                    && context.expectation == ExpectedValidity::Reject)
        );
    }

    #[test]
    fn mislabeled_seed_saves_exact_bytes_and_replays_the_real_parser_failure() {
        let fixture = Fixture::new(b"{\"value\":-2}");
        let mut observed = Vec::new();
        let error = run_campaign(
            &profile(1000),
            &fixture.corpus,
            &fixture.evidence,
            FuzzTarget::Contracts,
            |bytes, context| {
                observed.push(bytes.to_vec());
                typed_oracle(bytes, context)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputInvalid);
        assert_eq!(
            observed,
            [b"{\"value\":-2}".to_vec(), b"{\"value\":-2}".to_vec()]
        );
        assert_eq!(
            fixture
                .evidence
                .read(Path::new("contracts-counterexample.bin"), 128)
                .unwrap(),
            observed[0]
        );
        let replay: serde_json::Value = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-replay.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replay["original"]["outcome"], "rejected");
        assert_eq!(replay["replay"]["outcome"], "rejected");
        assert_eq!(replay["context"]["expectation"], "accept");
        let report: FuzzReport = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-fuzz.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report.executed_inputs, 2);
        assert_eq!(report.replay_checks, 1);
        assert_eq!(report.counterexamples, 1);
    }

    #[test]
    fn oracle_panics_are_saved_replayed_and_never_counted_as_rejections() {
        let fixture = Fixture::new(VALID);
        let error = run_campaign(
            &profile(1000),
            &fixture.corpus,
            &fixture.evidence,
            FuzzTarget::Contracts,
            |_, _| panic!("isolated oracle panic"),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputInvalid);
        let replay: serde_json::Value = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-replay.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replay["original"]["panicked"], true);
        assert_eq!(replay["replay"]["panicked"], true);
        let report: FuzzReport = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-fuzz.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report.explicit_rejections, 0);
        assert_eq!(report.replay_checks, 1);
        assert_eq!(report.counterexamples, 1);
    }

    #[test]
    fn deadline_overrun_is_failure_even_when_the_parser_returns_normally() {
        let fixture = Fixture::new(VALID);
        let error = run_campaign(
            &profile(10),
            &fixture.corpus,
            &fixture.evidence,
            FuzzTarget::Contracts,
            |bytes, context| {
                std::thread::sleep(Duration::from_millis(20));
                typed_oracle(bytes, context)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Timeout);
        let replay: serde_json::Value = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-replay.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replay["failure"], "deadline");
        assert_eq!(replay["replay"]["deadline_exceeded"], true);
        let report: FuzzReport = serde_json::from_slice(
            &fixture
                .evidence
                .read(Path::new("contracts-fuzz.json"), 65_536)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report.valid_round_trips, 0);
        assert_eq!(report.explicit_rejections, 0);
        assert_eq!(report.counterexamples, 1);
    }

    #[test]
    fn symlinked_seed_fails_provenance_before_the_oracle_runs() {
        let fixture = Fixture::new(VALID);
        std::fs::rename(
            fixture.corpus.join("valid.json"),
            fixture.corpus.join("actual.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink("actual.json", fixture.corpus.join("valid.json")).unwrap();
        let mut calls = 0;
        let error = run_campaign(
            &profile(1000),
            &fixture.corpus,
            &fixture.evidence,
            FuzzTarget::Contracts,
            |bytes, context| {
                calls += 1;
                typed_oracle(bytes, context)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::IntegrityError);
        assert_eq!(calls, 0);
    }
}
