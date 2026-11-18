use std::path::{Path, PathBuf};

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::parser_fuzz::{FuzzReport, FuzzTarget};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::values::{Digest, EntityId};
use razen_engine::protocol::error::ProofResult;

pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub fn assert_campaign<F>(target: FuzzTarget, campaign: F)
where
    F: FnOnce(&LoadedProfile, &Path, &OwnedDirectory) -> ProofResult<FuzzReport>,
{
    let root = repository();
    let profile =
        LoadedProfile::load(&root.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
            .unwrap();
    let corpus = root.join("fixtures/scenarios/parser-corpus");
    let id = EntityId::new();
    let (prefix, report_name) = match target {
        FuzzTarget::Framing => ("foundation/framing", "framing-fuzz.json"),
        FuzzTarget::Contracts => ("us1-contracts/typed-fuzz", "contracts-fuzz.json"),
    };
    let relative = PathBuf::from(format!("{prefix}-{id}"));
    let base = root.join("target/r0-evidence");
    std::fs::create_dir_all(&base).unwrap();
    let evidence = OwnedDirectory::create(&base, &relative, id).unwrap();
    let report = campaign(&profile, &corpus, &evidence).unwrap();
    assert_eq!(report.target, target);
    assert_eq!(
        report.executed_inputs,
        profile.config().parser_fuzz.max_inputs.get()
    );
    assert!(report.valid_round_trips > 0);
    assert!(report.explicit_rejections > 0);
    assert!(report.replay_checks > 0);
    assert_eq!(report.counterexamples, 0);
    assert!(report.elapsed_us <= profile.config().parser_fuzz.deadline_ms.get() * 1000);
    assert_eq!(report.profile_sha256, profile.sha256());
    assert_eq!(
        report.corpus_sha256,
        Digest::of(&std::fs::read(corpus.join("manifest.json")).unwrap())
    );
    let saved: FuzzReport =
        serde_json::from_slice(&evidence.read(Path::new(report_name), 65_536).unwrap()).unwrap();
    assert_eq!(saved.executed_inputs, report.executed_inputs);
    assert_eq!(saved.seed, profile.config().parser_fuzz.seed.get());
    assert_eq!(saved.corpus_sha256, report.corpus_sha256);
}
