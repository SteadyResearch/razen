use std::path::Path;

use razen_engine::application::parser_fuzz::{FuzzTarget, run_contracts};
use razen_engine::domain::values::EntityId;
use razen_engine::protocol::contracts::{
    CanonicalFixtures, ContractRecord, TrustedContractContext, parse_document,
};

#[path = "support/parser_mutation.rs"]
mod parser_mutation;

#[test]
fn project_documents_preserve_typed_ownership_without_treating_ids_as_authority() {
    let source = br#"{"schema_version":"0.1.0","record":{"type":"fixture_project","fields":{"project_id":"a13be608-16ac-4ab4-ae10-248b266318a1","user_id":"c677cbca-e6c7-4e83-9150-640b80085f43","scope_policy_id":"1bc50034-487c-49d7-8ab7-c2a5756a1700","revision":0}}}"#;
    let context = TrustedContractContext::from_histories(Vec::new()).unwrap();
    let document = parse_document(source, &context).unwrap();
    let restored = parse_document(&serde_json::to_vec(&document).unwrap(), &context).unwrap();
    let ContractRecord::FixtureProject(project) = restored.record else {
        panic!("Expected fixture project")
    };
    project
        .validate_owner(EntityId::parse("c677cbca-e6c7-4e83-9150-640b80085f43").unwrap())
        .unwrap();
    assert!(project.validate_owner(EntityId::new()).is_err());
}

#[test]
fn canonical_document_discriminators_versions_duplicates_and_unknown_fields_are_not_inferred() {
    let context = TrustedContractContext::from_histories(Vec::new()).unwrap();
    let fields = r#"{"project_id":"a13be608-16ac-4ab4-ae10-248b266318a1","user_id":"c677cbca-e6c7-4e83-9150-640b80085f43","scope_policy_id":"1bc50034-487c-49d7-8ab7-c2a5756a1700","revision":0}"#;
    for source in [
        format!(
            r#"{{"schema_version":"0.2.0","record":{{"type":"fixture_project","fields":{fields}}}}}"#
        ),
        format!(
            r#"{{"schema_version":"0.1.0","record":{{"type":"project_guess","fields":{fields}}}}}"#
        ),
        format!(
            r#"{{"schema_version":"0.1.0","schema_version":"0.1.0","record":{{"type":"fixture_project","fields":{fields}}}}}"#
        ),
        format!(
            r#"{{"schema_version":"0.1.0","record":{{"type":"fixture_project","type":"fixture_project","fields":{fields}}}}}"#
        ),
        format!(
            r#"{{"schema_version":"0.1.0","record":{{"type":"fixture_project","fields":{fields},"authority":true}}}}"#
        ),
        format!(
            r#"{{"schema_version":"0.1.0","record":{{"type":"fixture_project","fields":{fields}}},"role":"host"}}"#
        ),
    ] {
        assert!(parse_document(source.as_bytes(), &context).is_err());
    }
    assert!(parse_document(&vec![b' '; 1_048_577], &context).is_err());
}

#[test]
fn complete_seeded_typed_campaign_checks_canonical_records_and_trusted_cancellation_history() {
    let fixtures = CanonicalFixtures::load(
        &parser_mutation::repository().join("fixtures/scenarios/contracts.json"),
    )
    .unwrap();
    parser_mutation::assert_campaign(FuzzTarget::Contracts, |profile, corpus: &Path, evidence| {
        run_contracts(profile, corpus, evidence, fixtures.context())
    });
}
