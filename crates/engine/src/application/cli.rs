//! Pure argument parsing. Filesystem ownership and provisioning are execution-time checks.
use std::ffi::OsString;
use std::path::PathBuf;

use crate::domain::proofs::package_for_case;
use crate::domain::values::CatalogId;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    All,
    Contracts,
    Transport,
    Components,
    Runtime,
    Recovery,
    Exit,
}

impl Suite {
    pub fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Contracts => "contracts",
            Self::Transport => "transport",
            Self::Components => "components",
            Self::Runtime => "runtime",
            Self::Recovery => "recovery",
            Self::Exit => "exit",
        }
    }

    fn parse(value: &str) -> ProofResult<Self> {
        match value {
            "all" => Ok(Self::All),
            "contracts" => Ok(Self::Contracts),
            "transport" => Ok(Self::Transport),
            "components" => Ok(Self::Components),
            "runtime" => Ok(Self::Runtime),
            "recovery" => Ok(Self::Recovery),
            "exit" => Ok(Self::Exit),
            _ => Err(invalid("Unknown proof suite")),
        }
    }

    pub fn contains(self, case_id: &CatalogId) -> ProofResult<bool> {
        let package = package_for_case(case_id)?;
        Ok(match self {
            Self::All => true,
            Self::Contracts => package == "R0-01",
            Self::Transport => package == "R0-02",
            Self::Components => package == "R0-03",
            Self::Runtime => package == "R0-04" && case_id.as_str().starts_with("RUN-"),
            Self::Recovery => package == "R0-04" && case_id.as_str().starts_with("REC-"),
            Self::Exit => package == "R0-05",
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Doctor {
        profile: PathBuf,
        out: Option<PathBuf>,
    },
    // This variant can only be parsed with --confirm-provision present.
    PrepareIsolation {
        profile: PathBuf,
        out: PathBuf,
    },
    Run {
        profile: PathBuf,
        suite: Suite,
        case: Option<CatalogId>,
        out: PathBuf,
    },
    Verify {
        run: PathBuf,
    },
    Cleanup {
        run: PathBuf,
        stop_isolation: bool,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Doctor { .. } => "doctor",
            Self::PrepareIsolation { .. } => "prepare-isolation",
            Self::Run { .. } => "run",
            Self::Verify { .. } => "verify",
            Self::Cleanup { .. } => "cleanup",
        }
    }
}

const PROFILE: u8 = 1;
const OUT: u8 = 2;
const RUN: u8 = 4;
const SUITE: u8 = 8;
const CASE: u8 = 16;
const CONFIRM: u8 = 32;
const STOP: u8 = 64;

#[derive(Default)]
struct Options {
    profile: Option<PathBuf>,
    out: Option<PathBuf>,
    run: Option<PathBuf>,
    suite: Option<Suite>,
    case: Option<CatalogId>,
    seen: u8,
}

/// Takes arguments after argv[0]; never reads files, launches tools, or provisions isolation.
pub fn parse_command(args: impl IntoIterator<Item = OsString>) -> ProofResult<Command> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| invalid("A proof command is required"))?;
    let allowed = match command.to_str() {
        Some("doctor") => PROFILE | OUT,
        Some("prepare-isolation") => PROFILE | OUT | CONFIRM,
        Some("run") => PROFILE | OUT | SUITE | CASE,
        Some("verify") => RUN,
        Some("cleanup") => RUN | STOP,
        _ => return Err(invalid("Unknown proof command")),
    };
    let mut options = Options::default();
    while let Some(flag) = args.next() {
        let bit = match flag.to_str() {
            Some("--profile") => PROFILE,
            Some("--out") => OUT,
            Some("--run") => RUN,
            Some("--suite") => SUITE,
            Some("--case") => CASE,
            Some("--confirm-provision") => CONFIRM,
            Some("--stop-isolation") => STOP,
            _ => return Err(invalid("Unknown option or positional argument")),
        };
        if bit & allowed == 0 {
            return Err(invalid("Option is not valid for this command"));
        }
        if bit & options.seen != 0 {
            return Err(invalid("Duplicate option is ambiguous"));
        }
        options.seen |= bit;
        if bit == CONFIRM || bit == STOP {
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| invalid("An option value is required"))?;
        if value.as_encoded_bytes().starts_with(b"--") {
            return Err(invalid("An option value is required"));
        }
        match bit {
            PROFILE => options.profile = Some(path(value)?),
            OUT => options.out = Some(path(value)?),
            RUN => options.run = Some(path(value)?),
            SUITE => {
                options.suite = Some(Suite::parse(
                    value
                        .to_str()
                        .ok_or_else(|| invalid("Suite must be UTF-8"))?,
                )?)
            }
            CASE => {
                let id = CatalogId::parse(
                    value
                        .to_str()
                        .ok_or_else(|| invalid("Case ID must be UTF-8"))?,
                )?;
                package_for_case(&id)?;
                options.case = Some(id);
            }
            _ => unreachable!("Only value-bearing options reach this branch"),
        }
    }
    match command.to_str() {
        Some("doctor") => Ok(Command::Doctor {
            profile: required(options.profile)?,
            out: options.out,
        }),
        Some("prepare-isolation") => {
            if options.seen & CONFIRM == 0 {
                return Err(invalid(
                    "Isolation preparation requires --confirm-provision",
                ));
            }
            Ok(Command::PrepareIsolation {
                profile: required(options.profile)?,
                out: required(options.out)?,
            })
        }
        Some("run") => {
            let suite = options
                .suite
                .ok_or_else(|| invalid("A proof suite is required"))?;
            if let Some(case_id) = &options.case
                && !suite.contains(case_id)?
            {
                return Err(invalid("Selected case does not belong to this suite"));
            }
            Ok(Command::Run {
                profile: required(options.profile)?,
                suite,
                case: options.case,
                out: required(options.out)?,
            })
        }
        Some("verify") => Ok(Command::Verify {
            run: required(options.run)?,
        }),
        Some("cleanup") => Ok(Command::Cleanup {
            run: required(options.run)?,
            stop_isolation: options.seen & STOP != 0,
        }),
        _ => unreachable!("Command was validated before parsing options"),
    }
}

fn required(value: Option<PathBuf>) -> ProofResult<PathBuf> {
    value.ok_or_else(|| invalid("A required path option is missing"))
}

fn path(value: OsString) -> ProofResult<PathBuf> {
    let bytes = value.as_encoded_bytes();
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes.contains(&0)
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(invalid("Path is empty, oversized, or contains traversal"));
    }
    Ok(PathBuf::from(value))
}

fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}
