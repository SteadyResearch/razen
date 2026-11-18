use razen_engine::domain::knowledge::{
    AssetGraph, InvestigationGraph, InvestigationSession, MemoryItem, MemoryLevel, PromotionReview,
    Trace, WorkflowDefinition, prefilter_memory, validate_example_links,
};
use razen_engine::domain::values::{AuditTime, Digest, EntityId};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn id(n: u64) -> EntityId {
    EntityId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
}

fn now() -> AuditTime {
    AuditTime::parse("2026-11-16T12:00:00Z").unwrap()
}

fn evidence() -> Value {
    json!({"artifact_id": id(30), "sha256": Digest::of(b"synthetic graph evidence")})
}

fn session_json() -> Value {
    json!({
        "investigation_id": id(1), "goal": "Inspect the owned binary fixture", "control_revision": 3,
        "session_id": id(2), "user_id": id(3), "branch_refs": [id(4)],
        "evidence_refs": [evidence()]
    })
}

fn assets_json() -> Value {
    json!({
        "graph_id": id(5), "project_id": id(6),
        "assets": [
            {"asset_id": id(7), "kind": "host", "identity": "fixture.example", "version": "1"},
            {"asset_id": id(8), "kind": "endpoint", "identity": "https://fixture.example/binary", "version": "1"}
        ],
        "relations": [{"relation_id": id(9), "from_asset_id": id(7), "to_asset_id": id(8),
            "kind": "contains", "provenance_refs": [evidence()]}]
    })
}

fn investigation_json() -> Value {
    json!({
        "graph_id": id(10), "project_id": id(6), "investigation_id": id(1),
        "nodes": [
            {"node_id": id(11), "kind": "hypothesis", "label": "Binary fixture has an observable marker",
                "asset_refs": [id(8)], "evidence_refs": []},
            {"node_id": id(12), "kind": "action", "label": "Read the permitted binary range",
                "asset_refs": [id(8)], "evidence_refs": []},
            {"node_id": id(13), "kind": "observation", "label": "Marker bytes observed",
                "asset_refs": [id(8)], "evidence_refs": [evidence()]}
        ],
        "relations": [{"relation_id": id(14), "from_node_id": id(13), "to_node_id": id(11),
            "kind": "supports", "evidence_refs": [evidence()]}]
    })
}

fn workflow_json() -> Value {
    json!({
        "workflow_id": id(15), "project_id": id(6), "investigation_id": id(1), "version": "0.1.0",
        "steps": [{"step_id": "read-fixture", "action_node_id": id(12), "depends_on": []}]
    })
}

fn trace_json() -> Value {
    json!({
        "trace_id": id(16), "project_id": id(6), "investigation_id": id(1), "session_id": id(2),
        "workflow_id": id(15), "workflow_version": "0.1.0",
        "entries": [{"invocation_id": id(17), "step_id": "read-fixture", "action_node_id": id(12),
            "actor_ref": id(18), "sequence": 0, "evidence_refs": [evidence()]}]
    })
}

fn memory_json(memory_id: u64, level: &str, user_id: u64, session_id: Option<u64>) -> Value {
    let mut value = json!({
        "memory_id": id(memory_id), "level": level, "user_id": id(user_id), "kind": "lesson",
        "content_ref": id(40), "origin_ref": id(17), "status": "active",
        "valid_until": "2026-12-16T12:00:00Z"
    });
    if let Some(session_id) = session_id {
        value["session_id"] = json!(id(session_id));
    }
    value
}

fn memory(value: Value) -> MemoryItem {
    serde_json::from_value(value).unwrap()
}

fn promoted_json() -> Value {
    let mut value = memory_json(42, "user", 3, None);
    value["content_ref"] = json!(id(41));
    value["promotion_source_id"] = json!(id(39));
    value
}

fn review() -> PromotionReview {
    PromotionReview {
        source_memory_id: id(39),
        reviewer_user_id: id(3),
        reviewed_at: now(),
        generalized_content_ref: id(41),
        confidential_data_removed: true,
        conflicts_checked: true,
        explicit_user_decision: false,
    }
}

fn strict_record<T: DeserializeOwned + Serialize + std::fmt::Debug + PartialEq>(
    document: Value,
    required: &[&str],
) {
    let parsed: T = serde_json::from_value(document.clone()).unwrap();
    let restored: T = serde_json::from_slice(&serde_json::to_vec(&parsed).unwrap()).unwrap();
    assert_eq!(
        restored, parsed,
        "Serialization must preserve canonical values, not UTC spelling"
    );
    for field in required {
        let mut invalid = document.clone();
        invalid.as_object_mut().unwrap().remove(*field);
        assert!(
            serde_json::from_value::<T>(invalid).is_err(),
            "missing {field}"
        );
    }
    let mut extra = document.clone();
    extra["permissions"] = json!(["active_network"]);
    assert!(serde_json::from_value::<T>(extra).is_err());
    let first = required[0];
    let encoded = serde_json::to_string(&document).unwrap();
    let duplicate = format!("{{\"{first}\":{},{}", document[first], &encoded[1..]);
    assert!(serde_json::from_str::<T>(&duplicate).is_err());
}

#[test]
fn four_graph_contracts_have_distinct_wire_shapes_and_link_to_one_persistent_session() {
    strict_record::<AssetGraph>(
        assets_json(),
        &["graph_id", "project_id", "assets", "relations"],
    );
    strict_record::<InvestigationGraph>(
        investigation_json(),
        &[
            "graph_id",
            "project_id",
            "investigation_id",
            "nodes",
            "relations",
        ],
    );
    strict_record::<WorkflowDefinition>(
        workflow_json(),
        &[
            "workflow_id",
            "project_id",
            "investigation_id",
            "version",
            "steps",
        ],
    );
    strict_record::<Trace>(
        trace_json(),
        &[
            "trace_id",
            "project_id",
            "investigation_id",
            "session_id",
            "workflow_id",
            "workflow_version",
            "entries",
        ],
    );
    strict_record::<InvestigationSession>(
        session_json(),
        &[
            "investigation_id",
            "goal",
            "control_revision",
            "session_id",
            "user_id",
            "branch_refs",
            "evidence_refs",
        ],
    );
    let documents = [
        assets_json(),
        investigation_json(),
        workflow_json(),
        trace_json(),
    ];
    for (index, document) in documents.iter().enumerate() {
        assert_eq!(
            serde_json::from_value::<AssetGraph>(document.clone()).is_ok(),
            index == 0
        );
        assert_eq!(
            serde_json::from_value::<InvestigationGraph>(document.clone()).is_ok(),
            index == 1
        );
        assert_eq!(
            serde_json::from_value::<WorkflowDefinition>(document.clone()).is_ok(),
            index == 2
        );
        assert_eq!(
            serde_json::from_value::<Trace>(document.clone()).is_ok(),
            index == 3
        );
    }
    validate_example_links(
        &serde_json::from_value(assets_json()).unwrap(),
        &serde_json::from_value(investigation_json()).unwrap(),
        &serde_json::from_value(workflow_json()).unwrap(),
        &serde_json::from_value(trace_json()).unwrap(),
        &serde_json::from_value(session_json()).unwrap(),
    )
    .unwrap();
}

#[test]
fn graph_relationships_dag_steps_and_actual_trace_attribution_cannot_be_substituted() {
    let assets: AssetGraph = serde_json::from_value(assets_json()).unwrap();
    let investigation: InvestigationGraph = serde_json::from_value(investigation_json()).unwrap();
    let workflow: WorkflowDefinition = serde_json::from_value(workflow_json()).unwrap();
    let trace: Trace = serde_json::from_value(trace_json()).unwrap();
    let session: InvestigationSession = serde_json::from_value(session_json()).unwrap();
    for (field, replacement) in [
        ("session_id", json!(id(99))),
        ("investigation_id", json!(id(99))),
        ("project_id", json!(id(99))),
        ("workflow_id", json!(id(99))),
    ] {
        let mut invalid = trace_json();
        invalid[field] = replacement;
        let invalid: Trace = serde_json::from_value(invalid).unwrap();
        assert!(
            validate_example_links(&assets, &investigation, &workflow, &invalid, &session).is_err(),
            "accepted {field}"
        );
    }
    let mut foreign_asset = investigation_json();
    foreign_asset["nodes"][0]["asset_refs"] = json!([id(99)]);
    let foreign_asset: InvestigationGraph = serde_json::from_value(foreign_asset).unwrap();
    assert!(validate_example_links(&assets, &foreign_asset, &workflow, &trace, &session).is_err());
    let mut wrong_node_kind = workflow_json();
    wrong_node_kind["steps"][0]["action_node_id"] = json!(id(11));
    let wrong_node_kind: WorkflowDefinition = serde_json::from_value(wrong_node_kind).unwrap();
    assert!(
        validate_example_links(&assets, &investigation, &wrong_node_kind, &trace, &session)
            .is_err()
    );
    let mut wrong_trace_action = trace_json();
    wrong_trace_action["entries"][0]["action_node_id"] = json!(id(13));
    let wrong_trace_action: Trace = serde_json::from_value(wrong_trace_action).unwrap();
    assert!(
        validate_example_links(
            &assets,
            &investigation,
            &workflow,
            &wrong_trace_action,
            &session
        )
        .is_err()
    );
    let mut unknown_step = trace_json();
    unknown_step["entries"][0]["step_id"] = json!("unplanned-send");
    let unknown_step: Trace = serde_json::from_value(unknown_step).unwrap();
    assert!(
        validate_example_links(&assets, &investigation, &workflow, &unknown_step, &session)
            .is_err()
    );
}

#[test]
fn malformed_graphs_reject_cycles_dangling_edges_duplicates_and_unattributed_execution() {
    let mut dangling_asset = assets_json();
    dangling_asset["relations"][0]["to_asset_id"] = json!(id(99));
    assert!(serde_json::from_value::<AssetGraph>(dangling_asset).is_err());
    let mut unproven_asset = assets_json();
    unproven_asset["relations"][0]["provenance_refs"] = json!([]);
    assert!(serde_json::from_value::<AssetGraph>(unproven_asset).is_err());
    let mut duplicate_asset = assets_json();
    let duplicate = duplicate_asset["assets"][0].clone();
    duplicate_asset["assets"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(serde_json::from_value::<AssetGraph>(duplicate_asset).is_err());
    let mut dangling_investigation = investigation_json();
    dangling_investigation["relations"][0]["from_node_id"] = json!(id(99));
    assert!(serde_json::from_value::<InvestigationGraph>(dangling_investigation).is_err());
    let mut conflated_node = investigation_json();
    conflated_node["nodes"][0]["kind"] = json!("asset");
    assert!(serde_json::from_value::<InvestigationGraph>(conflated_node).is_err());
    for steps in [
        json!([{"step_id": "read-fixture", "action_node_id": id(12), "depends_on": ["read-fixture"]}]),
        json!([
            {"step_id": "a", "action_node_id": id(12), "depends_on": ["b"]},
            {"step_id": "b", "action_node_id": id(12), "depends_on": ["a"]}
        ]),
        json!([{"step_id": "read-fixture", "action_node_id": id(12), "depends_on": ["missing"]}]),
        json!([
            {"step_id": "read-fixture", "action_node_id": id(12), "depends_on": []},
            {"step_id": "read-fixture", "action_node_id": id(12), "depends_on": []}
        ]),
    ] {
        let mut invalid = workflow_json();
        invalid["steps"] = steps;
        assert!(serde_json::from_value::<WorkflowDefinition>(invalid).is_err());
    }
    let mut missing_actor = trace_json();
    missing_actor["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("actor_ref");
    assert!(serde_json::from_value::<Trace>(missing_actor).is_err());
    let mut duplicate_trace = trace_json();
    let duplicate = duplicate_trace["entries"][0].clone();
    duplicate_trace["entries"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(serde_json::from_value::<Trace>(duplicate_trace).is_err());
    let duplicate_nested = serde_json::to_string(&workflow_json()).unwrap().replace(
        "\"step_id\":\"read-fixture\"",
        "\"step_id\":\"read-fixture\",\"step_id\":\"forged\"",
    );
    assert!(serde_json::from_str::<WorkflowDefinition>(&duplicate_nested).is_err());
}

#[test]
fn canonical_session_access_is_owned_not_runtime_owned_or_cross_session_history() {
    let session: InvestigationSession = serde_json::from_value(session_json()).unwrap();
    let before = serde_json::to_value(&session).unwrap();
    session.authorize_access(id(3), id(2)).unwrap();
    assert!(session.authorize_access(id(99), id(2)).is_err());
    assert!(session.authorize_access(id(3), id(99)).is_err());
    let reconstructed: InvestigationSession =
        serde_json::from_slice(&serde_json::to_vec(&session).unwrap()).unwrap();
    reconstructed.authorize_access(id(3), id(2)).unwrap();
    assert_eq!(serde_json::to_value(reconstructed).unwrap(), before);
    for field in ["runtime_id", "model_id", "owner_agent_id", "scope_grant"] {
        let mut invalid = session_json();
        invalid[field] = json!(id(99));
        assert!(serde_json::from_value::<InvestigationSession>(invalid).is_err());
    }
}

#[test]
fn memory_has_exactly_user_and_session_levels_with_omittable_never_nullable_context() {
    strict_record::<MemoryItem>(
        memory_json(39, "session", 3, Some(2)),
        &[
            "memory_id",
            "level",
            "user_id",
            "session_id",
            "kind",
            "content_ref",
            "origin_ref",
            "status",
            "valid_until",
        ],
    );
    strict_record::<MemoryItem>(
        memory_json(38, "user", 3, None),
        &[
            "memory_id",
            "level",
            "user_id",
            "kind",
            "content_ref",
            "origin_ref",
            "status",
            "valid_until",
        ],
    );
    for level in [
        "project",
        "target",
        "client",
        "branch",
        "runtime",
        "organization",
        "User",
        "",
    ] {
        assert!(serde_json::from_value::<MemoryItem>(memory_json(39, level, 3, Some(2))).is_err());
    }
    assert!(serde_json::from_value::<MemoryItem>(memory_json(39, "user", 3, Some(2))).is_err());
    assert!(serde_json::from_value::<MemoryItem>(memory_json(39, "session", 3, None)).is_err());
    for field in ["session_id", "promotion_source_id"] {
        let mut invalid = memory_json(38, "user", 3, None);
        invalid[field] = Value::Null;
        assert!(serde_json::from_value::<MemoryItem>(invalid).is_err());
    }
    let mut self_promoted = promoted_json();
    self_promoted["promotion_source_id"] = json!(id(42));
    assert!(serde_json::from_value::<MemoryItem>(self_promoted).is_err());
    let mut session_promoted = memory_json(39, "session", 3, Some(2));
    session_promoted["promotion_source_id"] = json!(id(38));
    assert!(serde_json::from_value::<MemoryItem>(session_promoted).is_err());
}

#[test]
fn owner_level_session_status_and_expiry_are_prefiltered_before_content_search() {
    let mut expired = memory_json(46, "session", 3, Some(2));
    expired["valid_until"] = json!("2026-11-16T12:00:00Z");
    let mut retired = memory_json(47, "session", 3, Some(2));
    retired["status"] = json!("retired");
    let mut proposed = memory_json(48, "session", 3, Some(2));
    proposed["status"] = json!("proposed");
    let items = vec![
        memory(memory_json(39, "session", 3, Some(2))),
        memory(memory_json(43, "session", 3, Some(99))),
        memory(memory_json(44, "session", 99, Some(2))),
        memory(memory_json(38, "user", 3, None)),
        memory(memory_json(45, "user", 99, None)),
        memory(expired),
        memory(retired),
        memory(proposed),
    ];
    let session_candidates =
        prefilter_memory(&items, id(3), MemoryLevel::Session, Some(id(2)), now()).unwrap();
    let mut searched = Vec::new();
    let matching: Vec<_> = session_candidates
        .iter()
        .filter(|item| {
            let record = serde_json::to_value(item).unwrap();
            searched.push(record["memory_id"].clone());
            record["content_ref"] == json!(id(40))
        })
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(searched, vec![json!(id(39))]);
    let user_candidates = prefilter_memory(&items, id(3), MemoryLevel::User, None, now()).unwrap();
    assert_eq!(user_candidates.len(), 1);
    assert_eq!(
        serde_json::to_value(user_candidates[0]).unwrap()["memory_id"],
        json!(id(38))
    );
    assert!(prefilter_memory(&items, id(3), MemoryLevel::Session, None, now()).is_err());
    assert!(prefilter_memory(&items, id(3), MemoryLevel::User, Some(id(2)), now()).is_err());
    assert!(
        items[1]
            .authorize_access(id(3), MemoryLevel::Session, Some(id(2)), now())
            .is_err()
    );
    assert!(
        items[2]
            .authorize_access(id(3), MemoryLevel::Session, Some(id(2)), now())
            .is_err()
    );
    assert!(
        items[0]
            .authorize_access(id(3), MemoryLevel::User, None, now())
            .is_err()
    );
    items[0]
        .authorize_access(id(3), MemoryLevel::Session, Some(id(2)), now())
        .unwrap();
}

#[test]
fn reviewed_promotion_creates_a_generalized_user_item_with_lineage_without_copying_session_content()
{
    let source = memory(memory_json(39, "session", 3, Some(2)));
    let before = serde_json::to_value(&source).unwrap();
    let promoted = source
        .promote(memory(promoted_json()), &review(), id(3), id(2), now())
        .unwrap();
    assert_eq!(promoted, memory(promoted_json()));
    let promoted = serde_json::to_value(&promoted).unwrap();
    assert_eq!(promoted["promotion_source_id"], before["memory_id"]);
    assert_ne!(promoted["memory_id"], before["memory_id"]);
    assert_ne!(promoted["content_ref"], before["content_ref"]);
    assert_eq!(promoted["origin_ref"], before["origin_ref"]);
    assert_eq!(promoted["status"], "active");
    assert_eq!(promoted["valid_until"], before["valid_until"]);
    assert!(promoted.get("session_id").is_none());
    assert_eq!(serde_json::to_value(&source).unwrap(), before);
}

#[test]
fn promotion_rejects_unreviewed_confidential_conflicting_foreign_stale_or_unlinked_candidates() {
    let source = memory(memory_json(39, "session", 3, Some(2)));
    for field in ["confidential_data_removed", "conflicts_checked"] {
        let mut invalid = review();
        if field == "confidential_data_removed" {
            invalid.confidential_data_removed = false;
        } else {
            invalid.conflicts_checked = false;
        }
        assert!(
            source
                .promote(memory(promoted_json()), &invalid, id(3), id(2), now())
                .is_err()
        );
    }
    let mut foreign_reviewer = review();
    foreign_reviewer.reviewer_user_id = id(99);
    assert!(
        source
            .promote(
                memory(promoted_json()),
                &foreign_reviewer,
                id(3),
                id(2),
                now()
            )
            .is_err()
    );
    let mut wrong_source = review();
    wrong_source.source_memory_id = id(99);
    assert!(
        source
            .promote(memory(promoted_json()), &wrong_source, id(3), id(2), now())
            .is_err()
    );
    let mut future_review = review();
    future_review.reviewed_at = AuditTime::parse("2026-11-17T12:00:00Z").unwrap();
    assert!(
        source
            .promote(memory(promoted_json()), &future_review, id(3), id(2), now())
            .is_err()
    );
    let mut wrong_generalization = review();
    wrong_generalization.generalized_content_ref = id(99);
    assert!(
        source
            .promote(
                memory(promoted_json()),
                &wrong_generalization,
                id(3),
                id(2),
                now()
            )
            .is_err()
    );
    for (field, value) in [
        ("content_ref", json!(id(40))),
        ("user_id", json!(id(99))),
        ("promotion_source_id", json!(id(99))),
        ("valid_until", json!("2026-11-16T11:59:59Z")),
        ("status", json!("proposed")),
    ] {
        let mut candidate = promoted_json();
        candidate[field] = value;
        assert!(
            source
                .promote(memory(candidate), &review(), id(3), id(2), now())
                .is_err(),
            "accepted {field}"
        );
    }
    let mut no_lineage = promoted_json();
    no_lineage
        .as_object_mut()
        .unwrap()
        .remove("promotion_source_id");
    assert!(
        source
            .promote(memory(no_lineage), &review(), id(3), id(2), now())
            .is_err()
    );
    assert!(
        source
            .promote(memory(promoted_json()), &review(), id(99), id(2), now())
            .is_err()
    );
    assert!(
        source
            .promote(memory(promoted_json()), &review(), id(3), id(99), now())
            .is_err()
    );
    let mut expired_source = memory_json(39, "session", 3, Some(2));
    expired_source["valid_until"] = json!("2026-11-16T11:59:59Z");
    assert!(
        memory(expired_source)
            .promote(memory(promoted_json()), &review(), id(3), id(2), now())
            .is_err()
    );
}

#[test]
fn captured_instructions_cannot_become_general_rules_without_an_explicit_user_decision() {
    let mut captured = memory_json(39, "session", 3, Some(2));
    captured["kind"] = json!("history");
    let captured = memory(captured);
    let mut rule = promoted_json();
    rule["kind"] = json!("rule");
    assert!(
        captured
            .promote(memory(rule.clone()), &review(), id(3), id(2), now())
            .is_err()
    );
    let mut decision = review();
    decision.explicit_user_decision = true;
    let approved = captured
        .promote(memory(rule), &decision, id(3), id(2), now())
        .unwrap();
    assert_eq!(serde_json::to_value(approved).unwrap()["kind"], "rule");
    for (field, value) in [
        ("scope", json!(["https://foreign.example/"])),
        ("grant_id", json!(id(99))),
        ("permissions", json!(["active_network", "data_egress"])),
        ("budget", json!(9007199254740991_u64)),
    ] {
        let mut injected = promoted_json();
        injected[field] = value;
        assert!(serde_json::from_value::<MemoryItem>(injected).is_err());
        let mut discovered = assets_json();
        discovered["assets"][0][field] = json!(true);
        assert!(serde_json::from_value::<AssetGraph>(discovered).is_err());
    }
}

#[test]
fn graph_and_memory_metadata_reject_unknown_enums_oversized_text_and_invalid_timestamps() {
    for (field, value) in [
        ("kind", json!("authority_grant")),
        ("status", json!("confirmed")),
        ("valid_until", json!("2026-11-16T12:00:00+01:00")),
        ("origin_ref", json!("not-a-canonical-id")),
    ] {
        let mut invalid = memory_json(39, "session", 3, Some(2));
        invalid[field] = value;
        assert!(serde_json::from_value::<MemoryItem>(invalid).is_err());
    }
    let mut long_goal = session_json();
    long_goal["goal"] = json!("é".repeat(65_537));
    assert!(serde_json::from_value::<InvestigationSession>(long_goal).is_err());
    let mut long_label = investigation_json();
    long_label["nodes"][0]["label"] = json!("é".repeat(65_537));
    assert!(serde_json::from_value::<InvestigationGraph>(long_label).is_err());
    let mut version = workflow_json();
    version["version"] = json!("0.2.0");
    assert!(serde_json::from_value::<WorkflowDefinition>(version).is_err());
    let mut unknown_relation = investigation_json();
    unknown_relation["relations"][0]["kind"] = json!("authorizes");
    assert!(serde_json::from_value::<InvestigationGraph>(unknown_relation).is_err());
}
