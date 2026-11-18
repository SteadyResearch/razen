//! Composition root for reviewed fixture proofs, not a general project importer.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Serialize;

use super::admission::{BindingSpec, HostAdmission, PreparedCall, TrustedBinding};
use super::control::{ControlClient, ControlService};
use super::effect_meter::EffectMeter;
use super::profile::LoadedProfile;
use super::registry::Registry;
use crate::adapters::components::ComponentCapacity;
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::{Ledger, RegisteredTool};
use crate::adapters::transport::TransportConfig;
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::authority::{
    ApprovalGrant, Budget, Effect, FixtureProject, IdentityProfile, RetryClass, ScopePolicy,
    ToolDescriptor,
};
use crate::domain::evidence::RedactionStatus;
use crate::domain::execution::{ControlMode, ControlState};
use crate::domain::knowledge::InvestigationSession;
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt,
};
use crate::protocol::contracts::{CanonicalFixtures, ContractRecord};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const VERSION: ContractVersion = ContractVersion::V0_1_0;
// The ledger itself retains at most 4096 invocations. This finite fresh-run
// aggregate is never replenished by reopening a checkpoint or child budget.
const PROOF_RUN_UNITS: u64 = 4096;
const IMPORT_TOOL: &str = "proof.fixture.import";

pub struct ProofHost {
    pub workspace: Arc<OwnedDirectory>,
    pub ledger: Arc<Ledger>,
    pub evidence: Arc<EvidenceStore>,
    pub control: Arc<ControlService>,
    pub admission: Arc<HostAdmission>,
    pub registry: Arc<Registry>,
    pub component_capacity: Arc<ComponentCapacity>,
    pub project: FixtureProject,
    pub scope: ScopePolicy,
    pub identity: IdentityProfile,
    pub session: InvestigationSession,
    pub budget_id: EntityId,
    pub provider_digest: Digest,
    pub bootstrap_invocation_id: EntityId,
    local_tools: Vec<RegisteredTool>,
    control_client: OnceLock<Arc<ControlClient>>,
}

#[derive(Serialize)]
struct ImportRecord {
    contract_examples_sha256: Digest,
    artifacts: WireInt,
    snapshots: WireInt,
}

impl ProofHost {
    /// Only the trusted engine calls this with a reviewed bundle and its measured
    /// executable digest. Never reuse this initializer to open an existing run.
    pub fn create(
        workspace: Arc<OwnedDirectory>,
        profile: &LoadedProfile,
        examples: CanonicalFixtures,
        contract_examples_sha256: Digest,
        provider_digest: Digest,
    ) -> ProofResult<Self> {
        let mut project = None;
        let mut scope = None;
        let mut identity = None;
        let mut session = None;
        let mut evidence_project = None;
        let mut public_bytes = 0_u64;
        let mut artifacts = 0_u64;
        let mut snapshots = 0_u64;
        for document in examples.records() {
            match &document.record {
                ContractRecord::FixtureProject(value) => unique(&mut project, value.clone())?,
                ContractRecord::ScopePolicy(value) => unique(&mut scope, value.clone())?,
                ContractRecord::IdentityProfile(value) => unique(&mut identity, value.clone())?,
                ContractRecord::InvestigationSession(value) => unique(&mut session, value.clone())?,
                ContractRecord::Artifact(value) => {
                    owned_evidence(&mut evidence_project, value.project_id)?;
                    public_bytes = public_bytes
                        .checked_add(value.length_bytes.get())
                        .ok_or_else(budget)?;
                    artifacts += 1;
                }
                ContractRecord::Snapshot(value) => {
                    owned_evidence(&mut evidence_project, value.project_id)?;
                    snapshots += 1;
                }
                // Grants, old budgets/invocations/results and histories remain
                // schema examples. They are never imported as live authority.
                _ => {}
            }
        }
        let project: FixtureProject = project.ok_or_else(invalid)?;
        let scope: ScopePolicy = scope.ok_or_else(invalid)?;
        let identity: IdentityProfile = identity.ok_or_else(invalid)?;
        let mut session: InvestigationSession = session.ok_or_else(invalid)?;
        if scope.scope_policy_id != project.scope_policy_id
            || scope.project_id != project.project_id
            || identity.project_id != project.project_id
            || session.user_id != project.user_id
            || evidence_project != Some(project.project_id)
            || artifacts == 0
            || snapshots == 0
        {
            return Err(invalid());
        }
        session.control_revision = WireInt::ZERO;
        session.goal = "Run reviewed synthetic R0 feasibility proofs only".to_owned();
        let time_us = profile
            .config()
            .component
            .invocation_deadline_ms
            .get()
            .checked_mul(1000)
            .ok_or_else(budget)?;
        let requested = Usage {
            units: one(),
            bytes: profile.config().protocol.invocation_output_limit_bytes,
            cpu_us: WireInt::new(time_us)?,
            elapsed_us: WireInt::new(time_us)?,
        };
        if public_bytes > requested.bytes.get() {
            return Err(budget());
        }
        let import_record = ImportRecord {
            contract_examples_sha256,
            artifacts: WireInt::new(artifacts)?,
            snapshots: WireInt::new(snapshots)?,
        };
        let input = serde_json::to_vec(&import_record).map_err(|_| invalid())?;
        if public_bytes
            .checked_add(input.len() as u64)
            .ok_or_else(budget)?
            > requested.bytes.get()
        {
            return Err(budget());
        }
        let ledger = Arc::new(Ledger::create(&workspace, profile)?);
        ledger.transaction(|tx| {
            tx.insert_project(&project)?;
            tx.insert_scope(&scope)
        })?;
        ledger.insert_identity(&identity)?;
        let local_tools = Registry::builtin_tools(provider_digest, profile)?;
        for tool in &local_tools {
            ledger.insert_tool(tool)?;
        }
        ledger.insert_tool(&super::component_proof::registered_tool(
            provider_digest,
            profile,
        )?)?;
        let importer = RegisteredTool {
            provider_digest,
            descriptor: ToolDescriptor {
                tool_id: CatalogId::parse(IMPORT_TOOL)?,
                version: VERSION,
                input_contract: CatalogId::parse("proof.fixture.import.input")?,
                output_contract: CatalogId::parse("proof.fixture.import.output")?,
                effect: Effect::LocalWrite,
                permissions: vec![CatalogId::parse(IMPORT_TOOL)?],
                limits: requested,
                retry_class: RetryClass::NonRetryable,
            },
        };
        ledger.insert_tool(&importer)?;
        let budget_id = EntityId::new();
        ledger.insert_budget(&Budget {
            budget_id,
            parent_budget_id: None,
            limit: WireInt::new(PROOF_RUN_UNITS)?,
            consumed: WireInt::ZERO,
            reserved: WireInt::ZERO,
            revision: WireInt::ZERO,
        })?;
        let evidence = Arc::new(EvidenceStore::open(Arc::clone(&workspace))?);
        let bootstrap_invocation_id = EntityId::new();
        // Preauthorization input preparation has a real preallocated origin,
        // just like Registry::prepare. No completed operation is invented.
        let instruction = evidence.write_artifact(
            project.project_id,
            CatalogId::parse("proof-instruction")?,
            bootstrap_invocation_id,
            b"Run only reviewed synthetic R0 fixtures; no production traffic.",
            RedactionStatus::Original,
        )?;
        let input_artifact = evidence.write_artifact(
            project.project_id,
            CatalogId::parse("fixture-import-input")?,
            bootstrap_invocation_id,
            &input,
            RedactionStatus::Original,
        )?;
        ledger.insert_control(
            &ControlState {
                investigation_id: session.investigation_id,
                revision: WireInt::ZERO,
                mode: ControlMode::Running,
                admission_open: true,
                instruction_ref: instruction.artifact_id,
            },
            project.project_id,
            scope.revision,
        )?;
        ledger.insert_session(&session, project.project_id)?;
        let control = Arc::new(ControlService::new(
            Arc::clone(&ledger),
            profile,
            session.investigation_id,
        )?);
        let admission = Arc::new(HostAdmission::new(
            Arc::clone(&ledger),
            Arc::clone(&control),
        ));
        let binding = admission.bind(BindingSpec {
            user_id: project.user_id,
            project_id: project.project_id,
            investigation_id: session.investigation_id,
            session_id: session.session_id,
            identity_id: identity.identity_id,
            budget_id,
            provider_digest,
            allowed_tools: vec![importer.descriptor.tool_id.clone()],
            permissions: importer.descriptor.permissions.clone(),
        })?;
        let call = PreparedCall {
            invocation_id: bootstrap_invocation_id,
            call_id: EntityId::new(),
            tool_id: importer.descriptor.tool_id,
            tool_version: VERSION,
            input_ref: input_artifact.artifact_id,
            input_sha256: input_artifact.sha256,
            input_revision: WireInt::ZERO,
            source_control_revision: binding.control_revision(),
            requested,
        };
        insert_approval(&ledger, &binding, &call)?;
        admission.reserve(&binding, &call)?;
        let permit = admission.begin_effect(&binding, bootstrap_invocation_id)?;
        let mut meter = EffectMeter::start();
        meter.dispatched = true;
        let result = (|| {
            admission.recheck_effect(&binding, &permit)?;
            meter.write_pending = true;
            evidence.import_fixtures(&examples, bootstrap_invocation_id)?;
            meter.write_pending = false;
            meter.add_bytes(usize::try_from(public_bytes).map_err(|_| budget())?)?;
            admission.recheck_effect(&binding, &permit)?;
            meter.write_pending = true;
            let artifact = evidence.write_artifact(
                project.project_id,
                CatalogId::parse("fixture-import-result")?,
                bootstrap_invocation_id,
                &input,
                RedactionStatus::Original,
            )?;
            meter.write_pending = false;
            meter.add_bytes(input.len())?;
            Ok(artifact.artifact_id)
        })();
        let usage = match meter.usage() {
            Ok(usage) => usage,
            Err(error) => {
                admission.invalidate_integrity();
                return Err(error.with_invocation(bootstrap_invocation_id));
            }
        };
        let result = match result {
            Ok(_)
                if usage.bytes > requested.bytes
                    || usage.cpu_us > requested.cpu_us
                    || usage.elapsed_us > requested.elapsed_us =>
            {
                Err(budget())
            }
            other => other,
        };
        match result {
            Ok(output) => {
                admission.complete(&binding, permit, usage, Some(output))?;
            }
            Err(error) => {
                if error.code == ErrorCode::OutputInvalid && meter.write_pending {
                    admission.outcome_unknown(
                        &binding,
                        permit,
                        usage,
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "Fixture import persistence requires reconciliation",
                        ),
                    )?;
                } else {
                    admission.fail(&binding, permit, usage, error.clone())?;
                }
                return Err(error.with_invocation(bootstrap_invocation_id));
            }
        }
        let registry = Arc::new(Registry::new(
            Arc::clone(&admission),
            Arc::clone(&evidence),
            examples,
            profile,
        )?);
        Ok(Self {
            workspace,
            ledger,
            evidence,
            control,
            admission,
            registry,
            project,
            scope,
            identity,
            session,
            budget_id,
            provider_digest,
            bootstrap_invocation_id,
            local_tools,
            component_capacity: Arc::new(ComponentCapacity::from_profile(profile)?),
            control_client: OnceLock::new(),
        })
    }

    /// Construct a separate immutable HTTP-enabled SDK registry without changing
    /// the default local-only registry or granting any binding network authority.
    pub fn http_registry(
        &self,
        profile: &LoadedProfile,
        config: TransportConfig,
    ) -> ProofResult<Registry> {
        let tool = super::http_send::registered_tool(self.provider_digest, profile)?;
        match self.ledger.find_tool(&tool.descriptor.tool_id)? {
            Some(existing) if existing != tool => return Err(invalid()),
            Some(_) => {}
            None => self.ledger.insert_tool(&tool)?,
        }
        self.registry.with_transport(profile, config)
    }

    /// The engine/test controller installs its one actual authenticated endpoint.
    pub fn install_control_client(&self, client: ControlClient) -> ProofResult<()> {
        self.control_client.set(Arc::new(client)).map_err(|_| {
            ProofError::new(
                ErrorCode::InvalidInput,
                "The host control endpoint is already installed",
            )
        })
    }

    pub fn control_client(&self) -> ProofResult<Arc<ControlClient>> {
        self.control_client.get().cloned().ok_or_else(|| {
            ProofError::new(
                ErrorCode::ProviderUnavailable,
                "The host control endpoint is not installed",
            )
        })
    }

    pub fn bind_local(&self) -> ProofResult<Arc<TrustedBinding>> {
        self.admission.bind(self.local_spec()).map(Arc::new)
    }

    pub fn local_spec(&self) -> BindingSpec {
        BindingSpec {
            user_id: self.project.user_id,
            project_id: self.project.project_id,
            investigation_id: self.session.investigation_id,
            session_id: self.session.session_id,
            identity_id: self.identity.identity_id,
            budget_id: self.budget_id,
            provider_digest: self.provider_digest,
            allowed_tools: self
                .local_tools
                .iter()
                .map(|tool| tool.descriptor.tool_id.clone())
                .collect(),
            permissions: self
                .local_tools
                .iter()
                .flat_map(|tool| tool.descriptor.permissions.iter().cloned())
                .collect(),
        }
    }

    /// Isolate adversarial fixture control without replacing enclosing control or quota.
    pub fn fork_session(&self) -> ProofResult<Self> {
        let client = self.control_client()?;
        let session = InvestigationSession {
            investigation_id: EntityId::new(),
            goal: "Run an independently controlled R0 fixture session".into(),
            control_revision: WireInt::ZERO,
            session_id: EntityId::new(),
            user_id: self.session.user_id,
            branch_refs: Vec::new(),
            evidence_refs: Vec::new(),
        };
        let parent = self.ledger.read_control(self.session.investigation_id)?;
        self.ledger.insert_control(
            &ControlState {
                investigation_id: session.investigation_id,
                revision: WireInt::ZERO,
                mode: ControlMode::Running,
                admission_open: true,
                instruction_ref: parent.instruction_ref,
            },
            self.project.project_id,
            self.scope.revision,
        )?;
        self.ledger
            .insert_session(&session, self.project.project_id)?;
        self.control.register_existing(session.investigation_id)?;
        Ok(Self {
            workspace: Arc::clone(&self.workspace),
            ledger: Arc::clone(&self.ledger),
            evidence: Arc::clone(&self.evidence),
            control: Arc::clone(&self.control),
            admission: Arc::clone(&self.admission),
            registry: Arc::clone(&self.registry),
            component_capacity: Arc::clone(&self.component_capacity),
            project: self.project.clone(),
            scope: self.scope.clone(),
            identity: self.identity.clone(),
            session,
            budget_id: self.budget_id,
            provider_digest: self.provider_digest,
            bootstrap_invocation_id: self.bootstrap_invocation_id,
            local_tools: self.local_tools.clone(),
            control_client: OnceLock::from(client),
        })
    }

    /// Explicit trusted harness approval of a chosen bounded fixture call. Never
    /// invoke this automatically in response to arbitrary runtime tool requests.
    pub fn approve(&self, binding: &TrustedBinding, call: &PreparedCall) -> ProofResult<EntityId> {
        self.admission.session(binding)?;
        insert_approval(&self.ledger, binding, call)
    }
}

fn insert_approval(
    ledger: &Ledger,
    binding: &TrustedBinding,
    call: &PreparedCall,
) -> ProofResult<EntityId> {
    let grant_id = EntityId::new();
    ledger.insert_grant(&ApprovalGrant {
        grant_id,
        project_id: binding.project_id(),
        tool_id: call.tool_id.clone(),
        tool_version: call.tool_version,
        provider_digest: binding.provider_digest(),
        scope_revision: binding.scope_revision(),
        identity_id: binding.identity_id(),
        bounded_input_sha256: call.input_sha256,
        limits: call.requested,
        expires_at: AuditTime::now().checked_add(Duration::from_secs(60))?,
        revoked: false,
    })?;
    Ok(grant_id)
}

fn unique<T>(slot: &mut Option<T>, value: T) -> ProofResult<()> {
    if slot.replace(value).is_some() {
        return Err(invalid());
    }
    Ok(())
}
fn owned_evidence(project: &mut Option<EntityId>, owner: EntityId) -> ProofResult<()> {
    if *project.get_or_insert(owner) != owner {
        return Err(invalid());
    }
    Ok(())
}
fn one() -> WireInt {
    WireInt::new(1).expect("one is a valid wire integer")
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Proof bootstrap requires one reviewed owned fixture project",
    )
}
fn budget() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Fixture import exceeds the selected finite resource limits",
    )
}
