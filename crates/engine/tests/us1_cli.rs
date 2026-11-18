use std::ffi::OsString;

use razen_engine::application::cli::{Command, Suite, parse_command};
use razen_engine::protocol::error::ErrorCode;

fn parse(args: &[&str]) -> Result<Command, razen_engine::protocol::error::ProofError> {
    parse_command(args.iter().map(OsString::from))
}

const PROFILE: &str = "specs/001-r0-feasibility/contracts/pilot-profile.json";
const OUT: &str = "target/r0-evidence/cli";

#[test]
fn provisioning_authority_is_explicit_and_cannot_leak_into_an_ordinary_command() {
    assert!(matches!(
        parse(&[
            "prepare-isolation",
            "--profile",
            PROFILE,
            "--out",
            OUT,
            "--confirm-provision"
        ])
        .unwrap(),
        Command::PrepareIsolation { .. }
    ));
    for args in [
        vec!["prepare-isolation", "--profile", PROFILE, "--out", OUT],
        vec!["doctor", "--profile", PROFILE, "--confirm-provision"],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "contracts",
            "--out",
            OUT,
            "--confirm-provision",
        ],
        vec!["verify", "--run", OUT, "--confirm-provision"],
        vec!["cleanup", "--run", OUT, "--confirm-provision"],
    ] {
        assert_eq!(parse(&args).unwrap_err().code, ErrorCode::InvalidInput);
    }
}

#[test]
fn unknown_missing_duplicate_or_irrelevant_options_are_never_silently_ignored() {
    for args in [
        vec![],
        vec!["deploy"],
        vec!["run"],
        vec!["doctor", "--profile"],
        vec!["doctor", "--profile", PROFILE, "--profile", PROFILE],
        vec!["doctor", "--profile", PROFILE, "--out", OUT, "--out", OUT],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "contracts",
            "--out",
            OUT,
            "--suite",
            "transport",
        ],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "missing",
            "--out",
            OUT,
        ],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "contracts",
            "--out",
            OUT,
            "--network",
        ],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "contracts",
            "--out",
            OUT,
            "--stop-isolation",
        ],
        vec![
            "run",
            "--profile",
            PROFILE,
            "--suite",
            "contracts",
            "--out",
            OUT,
            "extra",
        ],
        vec!["verify", "--run", OUT, "--profile", PROFILE],
        vec!["cleanup", "--run", OUT, "--suite", "all"],
        vec![
            "prepare-isolation",
            "--profile",
            PROFILE,
            "--out",
            OUT,
            "--confirm-provision",
            "--confirm-provision",
        ],
    ] {
        assert_eq!(
            parse(&args).unwrap_err().code,
            ErrorCode::InvalidInput,
            "accepted ambiguous or ignored option"
        );
    }
}

#[test]
fn a_selected_case_must_exist_and_belong_to_its_requested_suite() {
    for (suite, case) in [
        ("contracts", "CON-01"),
        ("transport", "NET-04"),
        ("components", "CMP-07"),
        ("runtime", "RUN-08"),
        ("recovery", "REC-05"),
        ("exit", "EXIT-02"),
        ("all", "CON-05"),
    ] {
        assert!(matches!(
            parse(&[
                "run",
                "--profile",
                PROFILE,
                "--suite",
                suite,
                "--case",
                case,
                "--out",
                OUT
            ])
            .unwrap(),
            Command::Run { .. }
        ));
    }
    for (suite, case) in [
        ("contracts", "NET-01"),
        ("runtime", "REC-01"),
        ("recovery", "RUN-01"),
        ("all", "CON-99"),
        ("all", "CON-1"),
        ("all", "foo"),
        ("exit", "EXIT-03"),
    ] {
        assert_eq!(
            parse(&[
                "run",
                "--profile",
                PROFILE,
                "--suite",
                suite,
                "--case",
                case,
                "--out",
                OUT
            ])
            .unwrap_err()
            .code,
            ErrorCode::InvalidInput
        );
    }
    let Command::Run { suite, case, .. } = parse(&[
        "run",
        "--profile",
        PROFILE,
        "--suite",
        "recovery",
        "--case",
        "REC-01",
        "--out",
        OUT,
    ])
    .unwrap() else {
        panic!("Expected run")
    };
    assert_eq!(suite, Suite::Recovery);
    assert_eq!(case.unwrap().as_str(), "REC-01");
}

#[test]
fn lexical_path_escapes_empty_paths_and_embedded_nuls_fail_before_filesystem_work() {
    for path in [
        "",
        ".",
        "target/../outside",
        "target/./run",
        "../outside",
        "target/invalid\0name",
    ] {
        assert!(parse(&["verify", "--run", path]).is_err());
        assert!(parse(&["doctor", "--profile", path]).is_err());
        assert!(
            parse(&[
                "run",
                "--profile",
                PROFILE,
                "--suite",
                "contracts",
                "--out",
                path
            ])
            .is_err()
        );
    }
    assert!(parse(&["doctor", "--profile", PROFILE, "--out", "--suite"]).is_err());
    assert!(parse(&["cleanup", "--run", OUT, "--stop-isolation"]).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn private_engine_prefixes_reach_only_closed_workers_and_strip_the_prefix() {
    for prefix in ["--recovery-fixture", "--guest-orphan-worker"] {
        // Both workers reject an empty remaining argument list, independently
        // of the ordinary engine --workspace/--run-id parser.
        assert_eq!(
            razen_engine::application::engine_entry::run(vec![OsString::from(prefix)]).await,
            1
        );
    }
    assert_eq!(
        razen_engine::application::engine_entry::run(vec![
            OsString::from("--arbitrary-worker"),
            OsString::from("/bin/sh")
        ])
        .await,
        2
    );
}
