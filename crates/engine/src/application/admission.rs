//! Host-only authority and durable effect admission. These types are never peer credentials.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::control::ControlService;
use crate::adapters::ledger::{
    Ledger, LedgerTransaction, RegisteredSession, RegisteredTool, StoredInvocation,
};
use crate::domain::authority::{ApprovalGrant, DestinationCheck, ScopePolicy};
use crate::domain::execution::{Checkpoint, ControlMode, Event};
use crate::domain::invocation::{Invocation, InvocationHistory};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult, Retryability};

/// Created by the trusted orchestrator, never decoded from a runtime message.
#[derive(Clone)]
pub struct BindingSpec {
    pub user_id: EntityId,
    pub project_id: EntityId,
    pub investigation_id: EntityId,
    pub session_id: EntityId,
    pub identity_id: EntityId,
    pub budget_id: EntityId,
    pub provider_digest: Digest,
    pub allowed_tools: Vec<CatalogId>,
    pub permissions: Vec<CatalogId>,
}

pub struct TrustedBinding {
    host_id: EntityId,
    binding_id: EntityId,
    spec: BindingSpec,
    root_scope_id: EntityId,
    scope_revision: WireInt,
    control_revision: WireInt,
    enclosing_control_revision: WireInt,
    restriction: Option<ScopePolicy>,
}

impl TrustedBinding {
    pub fn binding_id(&self) -> EntityId {
        self.binding_id
    }
    pub fn actor_ref(&self) -> EntityId {
        self.binding_id
    }
    pub fn user_id(&self) -> EntityId {
        self.spec.user_id
    }
    pub fn project_id(&self) -> EntityId {
        self.spec.project_id
    }
    pub fn investigation_id(&self) -> EntityId {
        self.spec.investigation_id
    }
    pub fn session_id(&self) -> EntityId {
        self.spec.session_id
    }
    pub fn identity_id(&self) -> EntityId {
        self.spec.identity_id
    }
    pub fn budget_id(&self) -> EntityId {
        self.spec.budget_id
    }
    pub fn provider_digest(&self) -> Digest {
        self.spec.provider_digest
    }
    pub fn scope_revision(&self) -> WireInt {
        self.scope_revision
    }
    pub fn control_revision(&self) -> WireInt {
        self.control_revision
    }
    pub fn allowed_tools(&self) -> &[CatalogId] {
        &self.spec.allowed_tools
    }
    pub fn permissions(&self) -> &[CatalogId] {
        &self.spec.permissions
    }
}

/// Exact host-prepared input metadata. No grant or binding revision can be supplied as authority.
pub struct PreparedCall {
    pub invocation_id: EntityId,
    pub call_id: EntityId,
    pub tool_id: CatalogId,
    pub tool_version: ContractVersion,
    pub input_ref: EntityId,
    pub input_sha256: Digest,
    pub input_revision: WireInt,
    pub source_control_revision: WireInt,
    pub requested: Usage,
}

/// A single already-durable sending admission. Not serializable, constructible, or cloneable by peers.
pub struct EffectPermit {
    host_id: EntityId,
    binding_id: EntityId,
    invocation_id: EntityId,
}

impl EffectPermit {
    pub fn invocation_id(&self) -> EntityId {
        self.invocation_id
    }
}

pub struct HostAdmission {
    ledger: Arc<Ledger>,
    control: Arc<ControlService>,
    host_id: EntityId,
    failed: AtomicBool,
}

impl HostAdmission {
    pub fn new(ledger: Arc<Ledger>, control: Arc<ControlService>) -> Self {
        Self {
            ledger,
            control,
            host_id: EntityId::new(),
            failed: AtomicBool::new(false),
        }
    }

    fn healthy(&self) -> ProofResult<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(integrity());
        }
        Ok(())
    }

    /// Shared fail-closed gate for every adapter using this engine admission instance.
    pub fn invalidate_integrity(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }

    pub fn check_integrity(&self) -> ProofResult<()> {
        self.healthy()
    }
    pub(crate) fn enclosing_cancelled(&self) -> bool {
        self.control.enclosing_cancelled()
    }

    fn observe<T>(&self, result: ProofResult<T>) -> ProofResult<T> {
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::IntegrityError)
        {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut LedgerTransaction<'_>) -> ProofResult<T>,
    ) -> ProofResult<T> {
        self.healthy()?;
        self.observe(self.ledger.transaction(|tx| {
            self.healthy()?;
            operation(tx)
        }))
    }

    fn owns(&self, binding: &TrustedBinding) -> ProofResult<()> {
        if binding.host_id != self.host_id {
            return Err(denied());
        }
        Ok(())
    }

    pub fn bind(&self, mut spec: BindingSpec) -> ProofResult<TrustedBinding> {
        validate_sets(&mut spec)?;
        self.transaction(|tx| self.bind_in(tx, spec, None))
    }

    fn bind_in(
        &self,
        tx: &LedgerTransaction<'_>,
        spec: BindingSpec,
        restriction: Option<ScopePolicy>,
    ) -> ProofResult<TrustedBinding> {
        let project = tx.read_project(spec.project_id)?;
        project.validate_owner(spec.user_id)?;
        let session = tx.read_session(spec.session_id)?;
        if session.project_id != spec.project_id
            || session.session.user_id != spec.user_id
            || session.session.investigation_id != spec.investigation_id
        {
            return Err(denied());
        }
        tx.read_identity(spec.identity_id)?
            .validate_project(spec.project_id)?;
        let budget = tx.read_budget(spec.budget_id)?;
        budget.validate()?;
        if restriction.is_none() && budget.parent_budget_id.is_some() {
            return Err(denied());
        }
        let scope = tx.read_scope(project.scope_policy_id)?;
        if scope.project_id != spec.project_id {
            return Err(integrity());
        }
        let control = tx.read_control(spec.investigation_id)?;
        if session.session.control_revision != control.revision {
            return Err(stale());
        }
        if control.mode != ControlMode::Running || !control.admission_open {
            return Err(cancelled());
        }
        let enclosing_control_revision =
            if spec.investigation_id == self.control.enclosing_investigation_id() {
                control.revision
            } else {
                let enclosing = tx.read_control(self.control.enclosing_investigation_id())?;
                if enclosing.mode != ControlMode::Running || !enclosing.admission_open {
                    return Err(cancelled());
                }
                enclosing.revision
            };
        self.control
            .check_admission(spec.investigation_id, control.revision)?;
        for id in &spec.allowed_tools {
            let tool = tx.find_tool(id)?.ok_or_else(unknown_tool)?;
            if tool.provider_digest != spec.provider_digest
                || tool
                    .descriptor
                    .permissions
                    .iter()
                    .any(|permission| !spec.permissions.contains(permission))
            {
                return Err(denied());
            }
        }
        Ok(TrustedBinding {
            host_id: self.host_id,
            binding_id: EntityId::new(),
            spec,
            root_scope_id: project.scope_policy_id,
            scope_revision: scope.revision,
            control_revision: control.revision,
            enclosing_control_revision,
            restriction,
        })
    }

    pub fn bind_child(
        &self,
        parent: &TrustedBinding,
        mut spec: BindingSpec,
        restriction: ScopePolicy,
    ) -> ProofResult<TrustedBinding> {
        self.owns(parent)?;
        validate_sets(&mut spec)?;
        if spec.user_id != parent.user_id()
            || spec.project_id != parent.project_id()
            || spec.investigation_id != parent.investigation_id()
            || spec.session_id != parent.session_id()
            || spec.identity_id != parent.identity_id()
            || spec.provider_digest != parent.provider_digest()
            || spec
                .allowed_tools
                .iter()
                .any(|tool| !parent.allowed_tools().contains(tool))
            || spec
                .permissions
                .iter()
                .any(|permission| !parent.permissions().contains(permission))
        {
            return Err(denied());
        }
        self.transaction(|tx| {
            let root = self.current_context(tx, parent)?;
            if restriction.revision != parent.scope_revision {
                return Err(stale());
            }
            root.validate_child(&restriction)?;
            if let Some(overlay) = &parent.restriction {
                overlay.validate_child(&restriction)?;
            }
            let budget = tx.read_budget(spec.budget_id)?;
            if budget.parent_budget_id != Some(parent.budget_id()) {
                return Err(denied());
            }
            self.bind_in(tx, spec, Some(restriction))
        })
    }

    fn current_context(
        &self,
        tx: &LedgerTransaction<'_>,
        binding: &TrustedBinding,
    ) -> ProofResult<ScopePolicy> {
        self.owns(binding)?;
        let project = tx.read_project(binding.project_id())?;
        project.validate_owner(binding.user_id())?;
        if project.scope_policy_id != binding.root_scope_id {
            return Err(stale());
        }
        let scope = tx.read_scope(binding.root_scope_id)?;
        if scope.project_id != binding.project_id() {
            return Err(integrity());
        }
        if scope.revision != binding.scope_revision {
            return Err(stale());
        }
        let session = tx.read_session(binding.session_id())?;
        if session.project_id != binding.project_id()
            || session.session.user_id != binding.user_id()
            || session.session.investigation_id != binding.investigation_id()
        {
            return Err(denied());
        }
        tx.read_identity(binding.identity_id())?
            .validate_project(binding.project_id())?;
        let control = tx.read_control(binding.investigation_id())?;
        if control.revision != binding.control_revision
            || session.session.control_revision != binding.control_revision
        {
            return Err(stale());
        }
        if control.mode != ControlMode::Running || !control.admission_open {
            return Err(cancelled());
        }
        if binding.investigation_id() != self.control.enclosing_investigation_id() {
            let enclosing = tx.read_control(self.control.enclosing_investigation_id())?;
            if enclosing.mode != ControlMode::Running || !enclosing.admission_open {
                return Err(cancelled());
            }
            if enclosing.revision != binding.enclosing_control_revision {
                return Err(stale());
            }
        }
        self.control
            .check_admission(binding.investigation_id(), binding.control_revision)?;
        if let Some(overlay) = &binding.restriction {
            scope.validate_child(overlay)?;
        }
        tx.read_budget(binding.budget_id())?.validate()?;
        Ok(scope)
    }

    fn tool(
        &self,
        tx: &LedgerTransaction<'_>,
        binding: &TrustedBinding,
        invocation: &Invocation,
        requested: &Usage,
    ) -> ProofResult<RegisteredTool> {
        let tool = tx
            .find_tool(&invocation.tool_id)?
            .ok_or_else(unknown_tool)?;
        if !binding.allowed_tools().contains(&invocation.tool_id)
            || tool.provider_digest != binding.provider_digest()
            || invocation.provider_digest != tool.provider_digest
            || tool
                .descriptor
                .permissions
                .iter()
                .any(|permission| !binding.permissions().contains(permission))
        {
            return Err(denied());
        }
        if tool.descriptor.version != invocation.tool_version {
            return Err(ProofError::new(
                ErrorCode::UnsupportedVersion,
                "Tool version does not match the reviewed descriptor",
            ));
        }
        check_usage(requested, &tool.descriptor.limits)?;
        Ok(tool)
    }

    fn proposed(&self, binding: &TrustedBinding, call: &PreparedCall) -> Invocation {
        Invocation {
            invocation_id: call.invocation_id,
            run_id: self.ledger.run_id(),
            project_id: binding.project_id(),
            investigation_id: binding.investigation_id(),
            session_id: binding.session_id(),
            actor_ref: binding.actor_ref(),
            tool_id: call.tool_id.clone(),
            tool_version: call.tool_version,
            provider_digest: binding.provider_digest(),
            input_ref: call.input_ref,
            input_sha256: call.input_sha256,
            input_revision: call.input_revision,
            control_revision: binding.control_revision,
            scope_revision: binding.scope_revision,
            identity_id: binding.identity_id(),
            grant_id: None,
            budget_id: binding.budget_id(),
            attempt: one(),
            causation_id: call.call_id,
            deduplication_key: dedup(binding, call.call_id),
            state: InvocationState::Proposed,
            usage: Usage::default(),
            output_ref: None,
            error: None,
        }
    }

    pub fn existing_invocation(
        &self,
        binding: &TrustedBinding,
        call_id: EntityId,
    ) -> ProofResult<Option<StoredInvocation>> {
        self.healthy()?;
        self.owns(binding)?;
        self.observe(self.ledger.invocation_for_dedup(&dedup(binding, call_id)))
    }

    pub fn invocation(&self, id: EntityId) -> ProofResult<StoredInvocation> {
        self.healthy()?;
        self.observe(self.ledger.read_invocation(id))
    }

    /// Current owned session data, not a renewed admission or transferable authority.
    pub fn session(&self, binding: &TrustedBinding) -> ProofResult<RegisteredSession> {
        self.owns(binding)?;
        self.transaction(|tx| {
            tx.read_project(binding.project_id())?
                .validate_owner(binding.user_id())?;
            let session = tx.read_session(binding.session_id())?;
            if session.project_id != binding.project_id()
                || session.session.user_id != binding.user_id()
                || session.session.investigation_id != binding.investigation_id()
            {
                return Err(denied());
            }
            Ok(session)
        })
    }

    /// Persist preparatory intent and its evidence origin, without granting authority or quota.
    pub fn propose(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
    ) -> ProofResult<Invocation> {
        self.owns(binding)?;
        self.transaction(|tx| {
            if let Some(existing) = tx.invocation_for_dedup(&dedup(binding, call.call_id))? {
                self.match_call(&existing, call)?;
                return Ok(existing.invocation);
            }
            Ok(self.insert_proposed(tx, binding, call)?.invocation)
        })
    }

    pub fn reserve(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
    ) -> ProofResult<Invocation> {
        self.owns(binding)?;
        let outcome = self.transaction(|tx| {
            let mut stored = match tx.invocation_for_dedup(&dedup(binding, call.call_id))? {
                Some(existing) => {
                    self.match_call(&existing, call)?;
                    if !matches!(
                        existing.invocation.state,
                        InvocationState::Proposed | InvocationState::WaitingApproval
                    ) {
                        return Ok(Ok(existing.invocation));
                    }
                    existing
                }
                None => self.insert_proposed(tx, binding, call)?,
            };
            let policy = (|| {
                self.current_context(tx, binding)?;
                if call.source_control_revision != binding.control_revision {
                    return Err(stale());
                }
                self.tool(tx, binding, &stored.invocation, &call.requested)?;
                self.select_grant(tx, &mut stored.invocation, &call.requested)
            })();
            let grant = match policy {
                Ok(grant) => grant,
                Err(error) if error.code != ErrorCode::IntegrityError => {
                    if stored.invocation.state == InvocationState::WaitingApproval {
                        return Ok(Err(error.with_invocation(stored.invocation.invocation_id)));
                    }
                    let state = if error.code == ErrorCode::ApprovalRequired {
                        InvocationState::WaitingApproval
                    } else {
                        InvocationState::Rejected
                    };
                    return self
                        .reject_in(tx, binding, &mut stored, state, error)
                        .map(Err);
                }
                Err(error) => return Err(error),
            };
            let budget = tx.read_budget(binding.budget_id())?;
            if let Err(error) =
                tx.reserve_budget(budget.budget_id, call.requested.units, budget.revision)
            {
                if error.code == ErrorCode::IntegrityError {
                    return Err(error);
                }
                if stored.invocation.state == InvocationState::WaitingApproval {
                    return Ok(Err(error.with_invocation(stored.invocation.invocation_id)));
                }
                return self
                    .reject_in(tx, binding, &mut stored, InvocationState::Rejected, error)
                    .map(Err);
            }
            let previous = stored.invocation.state;
            stored.invocation.state = InvocationState::Reserved;
            stored.invocation.grant_id = Some(grant.grant_id);
            stored.invocation.error = None;
            stored.reserved_units = call.requested.units;
            self.transition(tx, binding, &mut stored, previous, Some(&grant))?;
            Ok(Ok(stored.invocation))
        })?;
        self.observe(outcome)
    }

    fn select_grant(
        &self,
        tx: &LedgerTransaction<'_>,
        invocation: &mut Invocation,
        requested: &Usage,
    ) -> ProofResult<ApprovalGrant> {
        let now = AuditTime::now();
        let mut exhausted = false;
        let mut selected: Option<ApprovalGrant> = None;
        for grant in tx.matching_grants(invocation)? {
            invocation.grant_id = Some(grant.grant_id);
            let validation = grant.validate_current(invocation, requested, now);
            invocation.grant_id = None;
            match validation {
                Ok(()) => {
                    // Prefer the longest remaining validity among fully valid grants;
                    // never extend a grant or replace it after reservation.
                    if selected
                        .as_ref()
                        .is_none_or(|current| grant.expires_at > current.expires_at)
                    {
                        selected = Some(grant);
                    }
                }
                Err(error) if error.code == ErrorCode::BudgetExhausted => exhausted = true,
                Err(_) => {}
            }
        }
        if let Some(grant) = selected {
            return Ok(grant);
        }
        if exhausted {
            return Err(quota());
        }
        Err(ProofError::new(
            ErrorCode::ApprovalRequired,
            "An explicit current host approval is required",
        ))
    }

    fn insert_proposed(
        &self,
        tx: &mut LedgerTransaction<'_>,
        binding: &TrustedBinding,
        call: &PreparedCall,
    ) -> ProofResult<StoredInvocation> {
        let invocation = self.proposed(binding, call);
        let stored = StoredInvocation {
            history: InvocationHistory::start(&invocation)?,
            invocation,
            reserved_units: WireInt::ZERO,
            requested: call.requested,
            source_control_revision: call.source_control_revision,
        };
        tx.insert_invocation(&stored)?;
        self.audit(tx, binding, &stored)?;
        Ok(stored)
    }

    fn match_call(&self, stored: &StoredInvocation, call: &PreparedCall) -> ProofResult<()> {
        let invocation = &stored.invocation;
        if invocation.tool_id != call.tool_id
            || invocation.tool_version != call.tool_version
            || invocation.input_ref != call.input_ref
            || invocation.input_sha256 != call.input_sha256
            || invocation.input_revision != call.input_revision
            || stored.source_control_revision != call.source_control_revision
            || stored.requested != call.requested
        {
            return Err(ProofError::new(
                ErrorCode::InvalidInput,
                "A call identifier cannot change its prepared input",
            )
            .with_invocation(invocation.invocation_id));
        }
        Ok(())
    }

    fn reject_in(
        &self,
        tx: &mut LedgerTransaction<'_>,
        binding: &TrustedBinding,
        stored: &mut StoredInvocation,
        state: InvocationState,
        error: ProofError,
    ) -> ProofResult<ProofError> {
        let error = error.with_invocation(stored.invocation.invocation_id);
        let previous = stored.invocation.state;
        stored.invocation.state = state;
        stored.invocation.error = Some(error.clone());
        self.transition(tx, binding, stored, previous, None)?;
        Ok(error)
    }

    pub fn record_rejection(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
        error: ProofError,
    ) -> ProofResult<Invocation> {
        self.owns(binding)?;
        self.healthy()?;
        if error.code == ErrorCode::IntegrityError {
            self.invalidate_integrity();
            return Err(error.with_invocation(call.invocation_id));
        }
        validate_error(&error, call.invocation_id)?;
        if matches!(
            error.code,
            ErrorCode::OutcomeUnknown | ErrorCode::ApprovalRequired
        ) {
            return Err(invalid());
        }
        self.transaction(|tx| {
            if let Some(existing) = tx.invocation_for_dedup(&dedup(binding, call.call_id))? {
                self.match_call(&existing, call)?;
                return Ok(existing.invocation);
            }
            let mut stored = self.insert_proposed(tx, binding, call)?;
            self.reject_in(tx, binding, &mut stored, InvocationState::Rejected, error)?;
            Ok(stored.invocation)
        })
    }

    fn invocation_binding(
        &self,
        binding: &TrustedBinding,
        invocation: &Invocation,
    ) -> ProofResult<()> {
        self.owns(binding)?;
        if invocation.run_id != self.ledger.run_id()
            || invocation.actor_ref != binding.actor_ref()
            || invocation.project_id != binding.project_id()
            || invocation.session_id != binding.session_id()
            || invocation.investigation_id != binding.investigation_id()
            || invocation.identity_id != binding.identity_id()
            || invocation.budget_id != binding.budget_id()
            || invocation.provider_digest != binding.provider_digest()
            || invocation.scope_revision != binding.scope_revision
            || invocation.control_revision != binding.control_revision
        {
            return Err(denied());
        }
        Ok(())
    }

    fn current_effect(
        &self,
        tx: &LedgerTransaction<'_>,
        binding: &TrustedBinding,
        stored: &StoredInvocation,
    ) -> ProofResult<(ApprovalGrant, ScopePolicy)> {
        let scope = self.current_context(tx, binding)?;
        let requested = stored.requested;
        self.tool(tx, binding, &stored.invocation, &requested)?;
        let grant = tx.read_grant(stored.invocation.grant_id.ok_or_else(integrity)?)?;
        let now = AuditTime::now();
        grant
            .validate_current(&stored.invocation, &requested, now)
            .inspect_err(|_| {
                eprintln!(
                    r#"{{"component":"approval-recheck","expired":{},"revoked":{}}}"#,
                    now >= grant.expires_at,
                    grant.revoked,
                );
            })?;
        if stored.reserved_units != requested.units {
            return Err(integrity());
        }
        Ok((grant, scope))
    }

    pub fn begin_effect(
        &self,
        binding: &TrustedBinding,
        invocation_id: EntityId,
    ) -> ProofResult<EffectPermit> {
        self.owns(binding)?;
        let outcome = self.transaction(|tx| {
            let mut stored = tx.read_invocation(invocation_id)?;
            self.invocation_binding(binding, &stored.invocation)?;
            if stored.invocation.state != InvocationState::Reserved {
                return Ok(Err(denied().with_invocation(invocation_id)));
            }
            let grant = match self.current_effect(tx, binding, &stored) {
                Ok((grant, _)) => grant,
                Err(error) if error.code != ErrorCode::IntegrityError => {
                    let budget = tx.read_budget(stored.invocation.budget_id)?;
                    tx.settle_budget(
                        budget.budget_id,
                        stored.reserved_units,
                        WireInt::ZERO,
                        budget.revision,
                    )?;
                    stored.reserved_units = WireInt::ZERO;
                    self.reject_in(
                        tx,
                        binding,
                        &mut stored,
                        InvocationState::Cancelled,
                        error.clone(),
                    )?;
                    return Ok(Err(error.with_invocation(invocation_id)));
                }
                Err(error) => return Err(error),
            };
            stored.invocation.state = InvocationState::Sending;
            self.transition(
                tx,
                binding,
                &mut stored,
                InvocationState::Reserved,
                Some(&grant),
            )?;
            Ok(Ok(EffectPermit {
                host_id: self.host_id,
                binding_id: binding.binding_id,
                invocation_id,
            }))
        })?;
        self.observe(outcome)
    }

    fn permitted(
        &self,
        tx: &LedgerTransaction<'_>,
        binding: &TrustedBinding,
        permit: &EffectPermit,
    ) -> ProofResult<StoredInvocation> {
        self.owns(binding)?;
        if permit.host_id != self.host_id || permit.binding_id != binding.binding_id {
            return Err(denied());
        }
        let stored = tx.read_invocation(permit.invocation_id)?;
        self.invocation_binding(binding, &stored.invocation)?;
        if stored.invocation.state != InvocationState::Sending {
            return Err(denied());
        }
        Ok(stored)
    }

    pub fn recheck_effect(
        &self,
        binding: &TrustedBinding,
        permit: &EffectPermit,
    ) -> ProofResult<()> {
        self.transaction(|tx| {
            let stored = self.permitted(tx, binding, permit)?;
            self.current_effect(tx, binding, &stored)?;
            Ok(())
        })
        .map_err(|error| error.with_invocation(permit.invocation_id))
    }

    pub fn authorize_destination(
        &self,
        binding: &TrustedBinding,
        permit: &EffectPermit,
        destination: &DestinationCheck<'_>,
    ) -> ProofResult<()> {
        self.transaction(|tx| {
            let stored = self.permitted(tx, binding, permit)?;
            let (_, scope) = self.current_effect(tx, binding, &stored)?;
            scope.authorize(destination)?;
            if let Some(overlay) = &binding.restriction {
                overlay.authorize(destination)?;
            }
            Ok(())
        })
        .map_err(|error| error.with_invocation(permit.invocation_id))
    }

    pub fn complete(
        &self,
        binding: &TrustedBinding,
        permit: EffectPermit,
        actual: Usage,
        output_ref: Option<EntityId>,
    ) -> ProofResult<Invocation> {
        self.finish(
            binding,
            permit,
            actual,
            InvocationState::Completed,
            output_ref,
            None,
        )
    }

    pub fn fail(
        &self,
        binding: &TrustedBinding,
        permit: EffectPermit,
        actual: Usage,
        error: ProofError,
    ) -> ProofResult<Invocation> {
        if error.code == ErrorCode::IntegrityError {
            self.invalidate_integrity();
            return Err(error.with_invocation(permit.invocation_id));
        }
        if error.code == ErrorCode::OutcomeUnknown || error.retryability == Retryability::Reconcile
        {
            return Err(invalid().with_invocation(permit.invocation_id));
        }
        self.finish(
            binding,
            permit,
            actual,
            InvocationState::Failed,
            None,
            Some(error),
        )
    }

    pub fn outcome_unknown(
        &self,
        binding: &TrustedBinding,
        permit: EffectPermit,
        actual: Usage,
        error: ProofError,
    ) -> ProofResult<Invocation> {
        if error.code != ErrorCode::OutcomeUnknown || error.retryability != Retryability::Reconcile
        {
            return Err(invalid().with_invocation(permit.invocation_id));
        }
        self.finish(
            binding,
            permit,
            actual,
            InvocationState::OutcomeUnknown,
            None,
            Some(error),
        )
    }

    fn finish(
        &self,
        binding: &TrustedBinding,
        permit: EffectPermit,
        actual: Usage,
        state: InvocationState,
        output: Option<EntityId>,
        mut error: Option<ProofError>,
    ) -> ProofResult<Invocation> {
        let id = permit.invocation_id;
        if let Some(error) = &error {
            validate_error(error, id)?;
        }
        self.transaction(|tx| {
            let mut stored = self.permitted(tx, binding, &permit)?;
            let overrun = check_usage(&actual, &stored.requested).err();
            if state == InvocationState::Completed {
                if let Some(error) = overrun {
                    return Err(error);
                }
            } else if state == InvocationState::Failed && overrun.is_some() {
                error = Some(quota());
            }
            if actual.units > stored.reserved_units {
                return Err(quota());
            }
            if state != InvocationState::OutcomeUnknown {
                let budget = tx.read_budget(stored.invocation.budget_id)?;
                tx.settle_budget(
                    budget.budget_id,
                    stored.reserved_units,
                    actual.units,
                    budget.revision,
                )?;
                stored.reserved_units = WireInt::ZERO;
            }
            stored.invocation.state = state;
            stored.invocation.usage = actual;
            stored.invocation.output_ref = output;
            stored.invocation.error = error.map(|error| error.with_invocation(id));
            self.transition(tx, binding, &mut stored, InvocationState::Sending, None)?;
            Ok(stored.invocation)
        })
        .map_err(|error| error.with_invocation(id))
    }

    fn transition(
        &self,
        tx: &mut LedgerTransaction<'_>,
        binding: &TrustedBinding,
        stored: &mut StoredInvocation,
        previous: InvocationState,
        grant: Option<&ApprovalGrant>,
    ) -> ProofResult<()> {
        stored
            .history
            .record(&stored.invocation, grant, AuditTime::now())?;
        tx.update_invocation(stored, previous)?;
        self.audit(tx, binding, stored)
    }

    fn audit(
        &self,
        tx: &mut LedgerTransaction<'_>,
        binding: &TrustedBinding,
        stored: &StoredInvocation,
    ) -> ProofResult<()> {
        let invocation = &stored.invocation;
        let sequence = stored.history.event_sequence();
        let now = AuditTime::now();
        let kind = match invocation.state {
            InvocationState::Proposed => "invocation.proposed",
            InvocationState::Rejected => "invocation.rejected",
            InvocationState::WaitingApproval => "invocation.waiting_approval",
            InvocationState::Reserved => "invocation.reserved",
            InvocationState::Sending => "invocation.sending",
            InvocationState::Completed => "invocation.completed",
            InvocationState::Failed => "invocation.failed",
            InvocationState::OutcomeUnknown => "invocation.outcome_unknown",
            InvocationState::Cancelled => "invocation.cancelled",
        };
        tx.append_event(&Event {
            event_id: EntityId::new(),
            schema_version: ContractVersion::V0_1_0,
            project_id: invocation.project_id,
            aggregate_id: invocation.invocation_id,
            aggregate_sequence: sequence,
            event_type: CatalogId::parse(kind)?,
            timestamp: now,
            correlation_id: invocation.causation_id,
            causation_id: invocation.causation_id,
            control_revision: Some(invocation.control_revision),
            data_refs: vec![invocation.input_ref],
            published: false,
        })?;
        let control = tx.read_control(binding.investigation_id())?;
        let root = tx.read_scope(binding.root_scope_id)?;
        tx.write_checkpoint(&Checkpoint {
            checkpoint_id: EntityId::new(),
            run_id: self.ledger.run_id(),
            schema_version: ContractVersion::V0_1_0,
            control_revision: control.revision,
            scope_revision: root.revision,
            budget_refs: vec![invocation.budget_id],
            invocation_refs: vec![invocation.invocation_id],
            lease_refs: Vec::new(),
            event_cursors: BTreeMap::from([(invocation.invocation_id, sequence)]),
            created_at: now,
        })
    }
}

fn validate_sets(spec: &mut BindingSpec) -> ProofResult<()> {
    if spec.allowed_tools.len() > 256 || spec.permissions.len() > 256 {
        return Err(invalid());
    }
    spec.allowed_tools.sort_unstable();
    spec.permissions.sort_unstable();
    if spec.allowed_tools.windows(2).any(|pair| pair[0] == pair[1])
        || spec.permissions.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_error(error: &ProofError, invocation_id: EntityId) -> ProofResult<()> {
    if error.invocation_id.is_some_and(|id| id != invocation_id)
        || error.message.len() > 256
        || error.diagnostic_refs.len() > 32
        || (error.code == ErrorCode::OutcomeUnknown
            && error.retryability != Retryability::Reconcile)
    {
        return Err(invalid().with_invocation(invocation_id));
    }
    Ok(())
}

fn check_usage(actual: &Usage, maximum: &Usage) -> ProofResult<()> {
    if actual.units > maximum.units
        || actual.bytes > maximum.bytes
        || actual.cpu_us > maximum.cpu_us
        || actual.elapsed_us > maximum.elapsed_us
    {
        return Err(quota());
    }
    Ok(())
}
fn dedup(binding: &TrustedBinding, call_id: EntityId) -> String {
    format!("{}:{call_id}", binding.binding_id)
}
fn one() -> WireInt {
    WireInt::new(1).expect("one is a valid wire integer")
}
fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "Request does not match trusted host authority",
    )
}
fn stale() -> ProofError {
    ProofError::new(
        ErrorCode::StaleSnapshot,
        "Originating host scope or control revision is stale",
    )
}
fn cancelled() -> ProofError {
    ProofError::new(
        ErrorCode::Cancelled,
        "Current investigation does not admit new work",
    )
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Host-prepared request does not match its bounded contract",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Canonical admission state failed integrity checks",
    )
}
fn quota() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Requested or actual resources exceed admitted limits",
    )
}
fn unknown_tool() -> ProofError {
    ProofError::new(
        ErrorCode::UnknownTool,
        "Tool is not in the reviewed host catalog",
    )
}
