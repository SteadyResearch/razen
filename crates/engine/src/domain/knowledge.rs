use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::domain::evidence::{
    EvidenceRef, bounded_text, bounded_vec, check_text, denied, invalid,
};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, EntityId, WireInt, non_null_optional,
};
use crate::protocol::error::{ProofError, ProofResult};

fn unique<T: Eq + Hash>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = HashSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn validate_evidence(references: &[EvidenceRef], required: bool) -> ProofResult<()> {
    if references.len() > 32 || (required && references.is_empty()) {
        return Err(invalid(
            "Evidence references are missing or exceed their limit",
        ));
    }
    for reference in references {
        reference.validate()?;
    }
    Ok(())
}

fn required_evidence<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<EvidenceRef>, D::Error> {
    let references = bounded_vec::<D, EvidenceRef, 32>(deserializer)?;
    validate_evidence(&references, true).map_err(de::Error::custom)?;
    Ok(references)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireInvestigationSession")]
pub struct InvestigationSession {
    pub investigation_id: EntityId,
    pub goal: String,
    pub control_revision: WireInt,
    pub session_id: EntityId,
    pub user_id: EntityId,
    pub branch_refs: Vec<EntityId>,
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInvestigationSession {
    investigation_id: EntityId,
    #[serde(deserialize_with = "bounded_text::<_, 4096>")]
    goal: String,
    control_revision: WireInt,
    session_id: EntityId,
    user_id: EntityId,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    branch_refs: Vec<EntityId>,
    #[serde(deserialize_with = "bounded_vec::<_, _, 32>")]
    evidence_refs: Vec<EvidenceRef>,
}

impl TryFrom<WireInvestigationSession> for InvestigationSession {
    type Error = ProofError;
    fn try_from(wire: WireInvestigationSession) -> ProofResult<Self> {
        let record = Self {
            investigation_id: wire.investigation_id,
            goal: wire.goal,
            control_revision: wire.control_revision,
            session_id: wire.session_id,
            user_id: wire.user_id,
            branch_refs: wire.branch_refs,
            evidence_refs: wire.evidence_refs,
        };
        record.validate()?;
        Ok(record)
    }
}

impl InvestigationSession {
    pub fn validate(&self) -> ProofResult<()> {
        check_text(&self.goal, 4096)?;
        if self.branch_refs.len() > 256 || !unique(self.branch_refs.iter()) {
            return Err(invalid(
                "Session branch references are duplicated or exceed their limit",
            ));
        }
        validate_evidence(&self.evidence_refs, false)
    }

    pub fn authorize_access(&self, user_id: EntityId, session_id: EntityId) -> ProofResult<()> {
        if self.user_id != user_id || self.session_id != session_id {
            return Err(denied());
        }
        self.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Endpoint,
    Service,
    Repository,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub asset_id: EntityId,
    pub kind: AssetKind,
    #[serde(deserialize_with = "bounded_text::<_, 2048>")]
    pub identity: String,
    pub version: CatalogId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetRelationKind {
    Contains,
    DependsOn,
    ConnectsTo,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRelation {
    pub relation_id: EntityId,
    pub from_asset_id: EntityId,
    pub to_asset_id: EntityId,
    pub kind: AssetRelationKind,
    #[serde(deserialize_with = "required_evidence")]
    pub provenance_refs: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireAssetGraph")]
pub struct AssetGraph {
    pub graph_id: EntityId,
    pub project_id: EntityId,
    pub assets: Vec<Asset>,
    pub relations: Vec<AssetRelation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAssetGraph {
    graph_id: EntityId,
    project_id: EntityId,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    assets: Vec<Asset>,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    relations: Vec<AssetRelation>,
}

impl TryFrom<WireAssetGraph> for AssetGraph {
    type Error = ProofError;
    fn try_from(wire: WireAssetGraph) -> ProofResult<Self> {
        let record = Self {
            graph_id: wire.graph_id,
            project_id: wire.project_id,
            assets: wire.assets,
            relations: wire.relations,
        };
        record.validate()?;
        Ok(record)
    }
}

impl AssetGraph {
    pub fn validate(&self) -> ProofResult<()> {
        if self.assets.len() > 256 || self.relations.len() > 256 {
            return Err(invalid("Asset graph exceeds its example limit"));
        }
        let assets: HashSet<_> = self.assets.iter().map(|asset| asset.asset_id).collect();
        if assets.len() != self.assets.len()
            || !unique(self.relations.iter().map(|relation| relation.relation_id))
        {
            return Err(invalid("Duplicate asset graph identities"));
        }
        for asset in &self.assets {
            check_text(&asset.identity, 2048)?;
        }
        for relation in &self.relations {
            if !assets.contains(&relation.from_asset_id) || !assets.contains(&relation.to_asset_id)
            {
                return Err(invalid("Asset relation has a dangling endpoint"));
            }
            validate_evidence(&relation.provenance_refs, true)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationNodeKind {
    Hypothesis,
    Action,
    Observation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireInvestigationNode")]
pub struct InvestigationNode {
    pub node_id: EntityId,
    pub kind: InvestigationNodeKind,
    pub label: String,
    pub asset_refs: Vec<EntityId>,
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInvestigationNode {
    node_id: EntityId,
    kind: InvestigationNodeKind,
    #[serde(deserialize_with = "bounded_text::<_, 4096>")]
    label: String,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    asset_refs: Vec<EntityId>,
    #[serde(deserialize_with = "bounded_vec::<_, _, 32>")]
    evidence_refs: Vec<EvidenceRef>,
}

impl TryFrom<WireInvestigationNode> for InvestigationNode {
    type Error = ProofError;
    fn try_from(wire: WireInvestigationNode) -> ProofResult<Self> {
        let record = Self {
            node_id: wire.node_id,
            kind: wire.kind,
            label: wire.label,
            asset_refs: wire.asset_refs,
            evidence_refs: wire.evidence_refs,
        };
        record.validate()?;
        Ok(record)
    }
}

impl InvestigationNode {
    pub fn validate(&self) -> ProofResult<()> {
        check_text(&self.label, 4096)?;
        if self.asset_refs.len() > 256 || !unique(self.asset_refs.iter()) {
            return Err(invalid(
                "Node asset references are duplicated or exceed their limit",
            ));
        }
        validate_evidence(
            &self.evidence_refs,
            self.kind == InvestigationNodeKind::Observation,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Supports,
    Refutes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub relation_id: EntityId,
    pub from_node_id: EntityId,
    pub to_node_id: EntityId,
    pub kind: RelationKind,
    #[serde(deserialize_with = "required_evidence")]
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireInvestigationGraph")]
pub struct InvestigationGraph {
    pub graph_id: EntityId,
    pub project_id: EntityId,
    pub investigation_id: EntityId,
    pub nodes: Vec<InvestigationNode>,
    pub relations: Vec<Relation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInvestigationGraph {
    graph_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    nodes: Vec<InvestigationNode>,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    relations: Vec<Relation>,
}

impl TryFrom<WireInvestigationGraph> for InvestigationGraph {
    type Error = ProofError;
    fn try_from(wire: WireInvestigationGraph) -> ProofResult<Self> {
        let record = Self {
            graph_id: wire.graph_id,
            project_id: wire.project_id,
            investigation_id: wire.investigation_id,
            nodes: wire.nodes,
            relations: wire.relations,
        };
        record.validate()?;
        Ok(record)
    }
}

impl InvestigationGraph {
    pub fn validate(&self) -> ProofResult<()> {
        if self.nodes.len() > 256 || self.relations.len() > 256 {
            return Err(invalid("Investigation graph exceeds its example limit"));
        }
        let nodes: HashSet<_> = self.nodes.iter().map(|node| node.node_id).collect();
        if nodes.len() != self.nodes.len()
            || !unique(self.relations.iter().map(|relation| relation.relation_id))
        {
            return Err(invalid("Duplicate investigation graph identities"));
        }
        for node in &self.nodes {
            node.validate()?;
        }
        for relation in &self.relations {
            if !nodes.contains(&relation.from_node_id) || !nodes.contains(&relation.to_node_id) {
                return Err(invalid("Investigation relation has a dangling endpoint"));
            }
            validate_evidence(&relation.evidence_refs, true)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireWorkflowStep")]
pub struct WorkflowStep {
    pub step_id: CatalogId,
    pub action_node_id: EntityId,
    pub depends_on: Vec<CatalogId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWorkflowStep {
    step_id: CatalogId,
    action_node_id: EntityId,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    depends_on: Vec<CatalogId>,
}

impl TryFrom<WireWorkflowStep> for WorkflowStep {
    type Error = ProofError;
    fn try_from(wire: WireWorkflowStep) -> ProofResult<Self> {
        let record = Self {
            step_id: wire.step_id,
            action_node_id: wire.action_node_id,
            depends_on: wire.depends_on,
        };
        record.validate()?;
        Ok(record)
    }
}

impl WorkflowStep {
    pub fn validate(&self) -> ProofResult<()> {
        if self.depends_on.len() > 256
            || self.depends_on.contains(&self.step_id)
            || !unique(self.depends_on.iter())
        {
            return Err(invalid(
                "Workflow dependencies are self-referential, duplicated, or oversized",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireWorkflowDefinition")]
pub struct WorkflowDefinition {
    pub workflow_id: EntityId,
    pub project_id: EntityId,
    pub investigation_id: EntityId,
    pub version: ContractVersion,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWorkflowDefinition {
    workflow_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    version: ContractVersion,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    steps: Vec<WorkflowStep>,
}

impl TryFrom<WireWorkflowDefinition> for WorkflowDefinition {
    type Error = ProofError;
    fn try_from(wire: WireWorkflowDefinition) -> ProofResult<Self> {
        let record = Self {
            workflow_id: wire.workflow_id,
            project_id: wire.project_id,
            investigation_id: wire.investigation_id,
            version: wire.version,
            steps: wire.steps,
        };
        record.validate()?;
        Ok(record)
    }
}

impl WorkflowDefinition {
    pub fn validate(&self) -> ProofResult<()> {
        if self.steps.len() > 256 {
            return Err(invalid("Workflow exceeds its example limit"));
        }
        let indices: HashMap<_, _> = self
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| (&step.step_id, index))
            .collect();
        if indices.len() != self.steps.len() {
            return Err(invalid("Workflow step identities are duplicated"));
        }
        let mut dependents = vec![Vec::new(); self.steps.len()];
        let mut remaining = Vec::with_capacity(self.steps.len());
        let mut ready = Vec::new();
        for (index, step) in self.steps.iter().enumerate() {
            step.validate()?;
            remaining.push(step.depends_on.len());
            if step.depends_on.is_empty() {
                ready.push(index);
            }
            for dependency in &step.depends_on {
                let predecessor = indices
                    .get(dependency)
                    .ok_or_else(|| invalid("Workflow dependency is missing"))?;
                dependents[*predecessor].push(index);
            }
        }
        let mut visited = 0usize;
        while let Some(index) = ready.pop() {
            visited += 1;
            for dependent in &dependents[index] {
                remaining[*dependent] -= 1;
                if remaining[*dependent] == 0 {
                    ready.push(*dependent);
                }
            }
        }
        if visited != self.steps.len() {
            return Err(invalid("Workflow dependencies contain a cycle"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEntry {
    pub invocation_id: EntityId,
    pub step_id: CatalogId,
    pub action_node_id: EntityId,
    pub actor_ref: EntityId,
    pub sequence: WireInt,
    #[serde(deserialize_with = "bounded_vec::<_, _, 32>")]
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireTrace")]
pub struct Trace {
    pub trace_id: EntityId,
    pub project_id: EntityId,
    pub investigation_id: EntityId,
    pub session_id: EntityId,
    pub workflow_id: EntityId,
    pub workflow_version: ContractVersion,
    pub entries: Vec<TraceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrace {
    trace_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    session_id: EntityId,
    workflow_id: EntityId,
    workflow_version: ContractVersion,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    entries: Vec<TraceEntry>,
}

impl TryFrom<WireTrace> for Trace {
    type Error = ProofError;
    fn try_from(wire: WireTrace) -> ProofResult<Self> {
        let record = Self {
            trace_id: wire.trace_id,
            project_id: wire.project_id,
            investigation_id: wire.investigation_id,
            session_id: wire.session_id,
            workflow_id: wire.workflow_id,
            workflow_version: wire.workflow_version,
            entries: wire.entries,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Trace {
    pub fn validate(&self) -> ProofResult<()> {
        if self.entries.len() > 256 || !unique(self.entries.iter().map(|entry| entry.invocation_id))
        {
            return Err(invalid(
                "Trace entries are duplicated or exceed their limit",
            ));
        }
        let mut previous = None;
        for entry in &self.entries {
            if previous.is_some_and(|sequence| entry.sequence <= sequence) {
                return Err(invalid(
                    "Trace sequence numbers are not strictly increasing",
                ));
            }
            previous = Some(entry.sequence);
            validate_evidence(&entry.evidence_refs, false)?;
        }
        Ok(())
    }
}

/// Checks links between examples, not permission to execute their described actions.
/// Canonical evidence resolution and effect admission remain separate host operations.
pub fn validate_example_links(
    assets: &AssetGraph,
    investigation: &InvestigationGraph,
    workflow: &WorkflowDefinition,
    trace: &Trace,
    session: &InvestigationSession,
) -> ProofResult<()> {
    assets.validate()?;
    investigation.validate()?;
    workflow.validate()?;
    trace.validate()?;
    session.validate()?;
    if assets.project_id != investigation.project_id
        || assets.project_id != workflow.project_id
        || assets.project_id != trace.project_id
        || investigation.investigation_id != session.investigation_id
        || workflow.investigation_id != session.investigation_id
        || trace.investigation_id != session.investigation_id
        || trace.session_id != session.session_id
        || trace.workflow_id != workflow.workflow_id
        || trace.workflow_version != workflow.version
    {
        return Err(denied());
    }
    let asset_ids: HashSet<_> = assets.assets.iter().map(|asset| asset.asset_id).collect();
    let nodes: HashMap<_, _> = investigation
        .nodes
        .iter()
        .map(|node| (node.node_id, node))
        .collect();
    let steps: HashMap<_, _> = workflow
        .steps
        .iter()
        .map(|step| (&step.step_id, step))
        .collect();
    for node in &investigation.nodes {
        if node
            .asset_refs
            .iter()
            .any(|asset_id| !asset_ids.contains(asset_id))
        {
            return Err(invalid("Investigation node refers to an unknown asset"));
        }
    }
    for step in &workflow.steps {
        if !nodes
            .get(&step.action_node_id)
            .is_some_and(|node| node.kind == InvestigationNodeKind::Action)
        {
            return Err(invalid(
                "Workflow step must reference an investigation action",
            ));
        }
    }
    for entry in &trace.entries {
        if !steps
            .get(&entry.step_id)
            .is_some_and(|step| step.action_node_id == entry.action_node_id)
        {
            return Err(invalid(
                "Trace entry does not match its pinned workflow step",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLevel {
    User,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    Lesson,
    Preference,
    Rule,
    History,
    Decision,
    TargetContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    Proposed,
    Active,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireMemoryItem")]
pub struct MemoryItem {
    pub memory_id: EntityId,
    pub level: MemoryLevel,
    pub user_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<EntityId>,
    pub kind: MemoryKind,
    pub content_ref: EntityId,
    pub origin_ref: EntityId,
    pub status: MemoryStatus,
    pub valid_until: AuditTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotion_source_id: Option<EntityId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMemoryItem {
    memory_id: EntityId,
    level: MemoryLevel,
    user_id: EntityId,
    #[serde(default, deserialize_with = "non_null_optional")]
    session_id: Option<EntityId>,
    kind: MemoryKind,
    content_ref: EntityId,
    origin_ref: EntityId,
    status: MemoryStatus,
    valid_until: AuditTime,
    #[serde(default, deserialize_with = "non_null_optional")]
    promotion_source_id: Option<EntityId>,
}

impl TryFrom<WireMemoryItem> for MemoryItem {
    type Error = ProofError;
    fn try_from(wire: WireMemoryItem) -> ProofResult<Self> {
        let record = Self {
            memory_id: wire.memory_id,
            level: wire.level,
            user_id: wire.user_id,
            session_id: wire.session_id,
            kind: wire.kind,
            content_ref: wire.content_ref,
            origin_ref: wire.origin_ref,
            status: wire.status,
            valid_until: wire.valid_until,
            promotion_source_id: wire.promotion_source_id,
        };
        record.validate()?;
        Ok(record)
    }
}

fn validate_memory_context(level: MemoryLevel, session_id: Option<EntityId>) -> ProofResult<()> {
    if (level == MemoryLevel::Session) != session_id.is_some() {
        return Err(invalid(
            "User memory forbids a session; session memory requires one",
        ));
    }
    Ok(())
}

impl MemoryItem {
    pub fn validate(&self) -> ProofResult<()> {
        validate_memory_context(self.level, self.session_id)?;
        if self.promotion_source_id == Some(self.memory_id)
            || (self.level == MemoryLevel::Session && self.promotion_source_id.is_some())
        {
            return Err(invalid("Memory promotion lineage is invalid"));
        }
        Ok(())
    }

    pub fn authorize_access(
        &self,
        user_id: EntityId,
        level: MemoryLevel,
        session_id: Option<EntityId>,
        now: AuditTime,
    ) -> ProofResult<()> {
        validate_memory_context(level, session_id)?;
        if self.user_id != user_id
            || self.level != level
            || self.session_id != session_id
            || self.status != MemoryStatus::Active
            || self.valid_until <= now
        {
            return Err(denied());
        }
        self.validate()
    }

    /// The host supplies a review after inspecting the separately stored generalized
    /// content. This attestation is deliberately not a deserializable peer payload.
    pub fn promote(
        &self,
        candidate: MemoryItem,
        review: &PromotionReview,
        user_id: EntityId,
        session_id: EntityId,
        now: AuditTime,
    ) -> ProofResult<MemoryItem> {
        self.authorize_access(user_id, MemoryLevel::Session, Some(session_id), now)?;
        candidate.validate()?;
        if candidate.level != MemoryLevel::User
            || candidate.user_id != user_id
            || candidate.status != MemoryStatus::Active
            || candidate.valid_until <= now
            || candidate.valid_until > self.valid_until
            || candidate.memory_id == self.memory_id
            || candidate.promotion_source_id != Some(self.memory_id)
            || candidate.origin_ref != self.origin_ref
            || candidate.content_ref == self.content_ref
            || candidate.content_ref != review.generalized_content_ref
            || review.source_memory_id != self.memory_id
            || review.reviewer_user_id != user_id
            || review.reviewed_at > now
            || review.reviewed_at >= candidate.valid_until
            || !review.confidential_data_removed
            || !review.conflicts_checked
            || !matches!(
                candidate.kind,
                MemoryKind::Lesson | MemoryKind::Preference | MemoryKind::Rule
            )
            || (candidate.kind == MemoryKind::Rule && !review.explicit_user_decision)
        {
            return Err(denied());
        }
        Ok(candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionReview {
    pub source_memory_id: EntityId,
    pub reviewer_user_id: EntityId,
    pub reviewed_at: AuditTime,
    pub generalized_content_ref: EntityId,
    pub confidential_data_removed: bool,
    pub conflicts_checked: bool,
    pub explicit_user_decision: bool,
}

/// An ownership-only example prefilter. Callers may inspect content references only
/// after this returns; it neither searches content nor expands graph relationships.
pub fn prefilter_memory(
    items: &[MemoryItem],
    user_id: EntityId,
    level: MemoryLevel,
    session_id: Option<EntityId>,
    now: AuditTime,
) -> ProofResult<Vec<&MemoryItem>> {
    validate_memory_context(level, session_id)?;
    if items.len() > 256 {
        return Err(invalid("Memory examples exceed their entry limit"));
    }
    let mut selected = Vec::new();
    for item in items {
        item.validate()?;
        if item
            .authorize_access(user_id, level, session_id, now)
            .is_ok()
        {
            selected.push(item);
        }
    }
    Ok(selected)
}
