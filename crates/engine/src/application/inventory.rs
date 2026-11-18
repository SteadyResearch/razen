//! Record/coverage gate only; immutable evidence and human review are independent gates.
use crate::application::{
    harness::{CaseSelection, CommandStatus, Counts},
    profile::LoadedProfile,
};
use crate::domain::{
    proofs::{
        CaseStatus, PackageStatus, ProofInventory, ProofResult as CaseResult, Run, WorkPackage,
    },
    values::{Digest, EntityId},
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Full inventory, current run/profile, selection, or prerequisite coverage is inconsistent",
    )
}
#[derive(Debug)]
pub struct InventoryEvaluation<'a> {
    pub run_id: EntityId,
    pub profile_sha256: Digest,
    pub counts: Counts,
    pub selected_status: CommandStatus,
    pub full_status: CommandStatus,
    pub package_order: [&'a WorkPackage; 5],
    pub package_statuses: [PackageStatus; 5],
}
/// Returns original borrowed packages; manifest file ordering is not execution ordering.
pub fn topological_packages(inventory: &ProofInventory) -> ProofResult<[&WorkPackage; 5]> {
    let first = inventory.packages().first().ok_or_else(integrity)?;
    if inventory.packages().len() != 5 {
        return Err(integrity());
    }
    let mut ordered = [first; 5];
    let mut count = 0;
    while count < 5 {
        let next = inventory
            .packages()
            .iter()
            .filter(|p| {
                !ordered[..count]
                    .iter()
                    .any(|done| done.package_id == p.package_id)
            })
            .filter(|p| {
                p.requires
                    .iter()
                    .all(|id| ordered[..count].iter().any(|done| done.package_id == *id))
            })
            .min_by(|left, right| left.package_id.cmp(&right.package_id))
            .ok_or_else(integrity)?;
        next.validate()?;
        ordered[count] = next;
        count += 1;
    }
    Ok(ordered)
}
pub fn evaluate<'a>(
    selection: &'a CaseSelection,
    run: &Run,
    results: &[CaseResult],
    profile: &LoadedProfile,
) -> ProofResult<InventoryEvaluation<'a>> {
    selection.validate()?;
    run.validate()?;
    validate_environment(run, profile)?;
    if run.profile_sha256 != profile.sha256()
        || run.profile_id != profile.config().profile_id
        || run.fixture_manifest_sha256 != selection.fixture_manifest_sha256
        || results.len() != selection.inventory.cases().len()
        || results.len() != 35
    {
        return Err(integrity());
    }
    let counts = Counts::from_results(results)?;
    counts.validate()?;
    let order = topological_packages(&selection.inventory)?;
    let mut statuses = [PackageStatus::Passed; 5];
    let mut selected = PackageStatus::Passed;
    for result in results {
        if result.run_id != run.run_id {
            return Err(integrity());
        }
        let case = selection
            .inventory
            .cases()
            .iter()
            .find(|case| case.case_id == result.case_id)
            .ok_or_else(integrity)?;
        let wanted = selection.selected_case_ids.contains(&result.case_id);
        if result.expected != case.expected
            || (!wanted && result.status != CaseStatus::Unexecuted)
            || (result.status == CaseStatus::Passed && result.error.is_some())
        {
            return Err(integrity());
        }
        let index = order
            .iter()
            .position(|package| package.package_id == case.package_id)
            .ok_or_else(integrity)?;
        let status = if result
            .error
            .as_ref()
            .is_some_and(|error| error.code == ErrorCode::Cancelled)
        {
            PackageStatus::Incomplete
        } else {
            match result.status {
                CaseStatus::Passed => PackageStatus::Passed,
                CaseStatus::Failed => PackageStatus::Failed,
                CaseStatus::Blocked => PackageStatus::Blocked,
                CaseStatus::Unexecuted => PackageStatus::Incomplete,
            }
        };
        statuses[index] = statuses[index].max(status);
        if wanted {
            selected = selected.max(status);
        }
    }
    for index in 0..order.len() {
        for prior in 0..index {
            if order[index].requires.contains(&order[prior].package_id) {
                statuses[index] = statuses[index].max(statuses[prior]);
            }
        }
    }
    let mut full = statuses.iter().copied().max().ok_or_else(integrity)?;
    if run.finished_at.is_none() {
        full = full.max(PackageStatus::Incomplete);
        selected = selected.max(PackageStatus::Incomplete);
    }
    Ok(InventoryEvaluation {
        run_id: run.run_id,
        profile_sha256: profile.sha256(),
        counts,
        selected_status: command_status(selected),
        full_status: command_status(full),
        package_order: order,
        package_statuses: statuses,
    })
}
fn command_status(status: PackageStatus) -> CommandStatus {
    match status {
        PackageStatus::Passed => CommandStatus::Passed,
        PackageStatus::Failed => CommandStatus::Failed,
        PackageStatus::Blocked => CommandStatus::Blocked,
        PackageStatus::Incomplete => CommandStatus::Incomplete,
    }
}
pub fn validate_environment(run: &Run, profile: &LoadedProfile) -> ProofResult<()> {
    let observed = &run.environment;
    let selected = profile.config();
    observed.validate()?;
    if run.profile_sha256 != profile.sha256()
        || run.profile_id != selected.profile_id
        || observed.os != selected.host.os
        || observed.os_version != selected.host.os_version
        || observed.arch != selected.host.arch
        || observed.logical_cpus < selected.host.minimum_logical_cpus
        || observed.memory_mib < selected.host.minimum_memory_mib
        || observed.component_target != selected.toolchain.component_target
        || observed.backend != selected.external_runner.backend
        || observed.guest_os != selected.external_runner.guest_os
        || observed.image_digest.as_str() != selected.external_runner.image_digest
        || observed
            .dependency_versions
            .iter()
            .find(|(name, _)| name.as_str() == "rust")
            .map(|(_, version)| version.as_str())
            != Some(selected.toolchain.rust.as_str())
    {
        return Err(integrity());
    }
    if observed.isolation_status == crate::domain::proofs::IsolationStatus::Prepared {
        for (name, version) in [
            ("lima", selected.external_runner.lima_version.as_str()),
            (
                "bubblewrap",
                selected.external_runner.bubblewrap_version.as_str(),
            ),
        ] {
            if observed
                .dependency_versions
                .iter()
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, observed)| observed.as_str())
                != Some(version)
            {
                return Err(integrity());
            }
        }
    }
    Ok(())
}

/// Exact backend observation keys; only packet verification has the frozen selection.
/// Record-only controlled gate probes may intentionally reuse a superset environment.
pub fn validate_selected_environment(
    selection: &CaseSelection,
    run: &Run,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    use crate::adapters::components::supervisor::{
        VARIANTS, WASMTIME_VERSION, WIT_BINDGEN_VERSION,
    };
    use crate::domain::proofs::IsolationStatus;
    validate_environment(run, profile)?;
    let has = |prefix: &str| {
        selection
            .selected_case_ids
            .iter()
            .any(|case| case.as_str().starts_with(prefix))
    };
    let components = has("CMP-");
    let guest = has("RUN-") || has("EXIT-");
    let recovery = has("REC-");
    let transport = has("NET-") || has("EXIT-");
    let observed = &run.environment;
    let fixture_count = 5
        + usize::from(components) * (VARIANTS.len() + 2)
        + usize::from(has("NET-"))
        + usize::from(recovery)
        + 2 * usize::from(guest);
    let binary_count = 2 + usize::from(components) + usize::from(recovery) + 3 * usize::from(guest);
    let version_count =
        1 + 2 * usize::from(components) + 2 * usize::from(guest) + usize::from(transport);
    if observed.fixture_digests.len() != fixture_count
        || observed.fixture_digests.keys().any(|key| {
            let name = key.as_str();
            !matches!(
                name,
                "scenario-manifest"
                    | "contract-scenarios"
                    | "approved-fixtures"
                    | "parser-corpus-manifest"
                    | "pilot-profile"
            ) && !(components
                && (matches!(name, "components" | "component-build-manifest")
                    || VARIANTS.contains(&name)))
                && !(has("NET-") && name == "transport-scenarios")
                && !(recovery && name == "recovery-scenarios")
                && !(guest && matches!(name, "guest-source" | "runtime"))
        })
        || observed.binary_digests.len() != binary_count
        || observed.binary_digests.keys().any(|key| {
            let name = key.as_str();
            !matches!(name, "razen-proof" | "razen-engine")
                && !(components && name == "razen-component-runner")
                && !(recovery && name == "razen-fixture-receiver")
                && !(guest && matches!(name, "guest-supervisor" | "guest-adversary" | "bubblewrap"))
        })
        || observed.dependency_versions.len() != version_count
        || observed.dependency_versions.keys().any(|key| {
            let name = key.as_str();
            name != "rust"
                && !(components && matches!(name, "wasmtime" | "wit-bindgen"))
                && !(guest && matches!(name, "lima" | "bubblewrap"))
                && !(transport && name == "rama")
        })
        || (guest && observed.isolation_status != IsolationStatus::Prepared)
        || (!guest && observed.isolation_status != IsolationStatus::NotRequired)
    {
        return Err(integrity());
    }
    if components
        && [
            ("wasmtime", WASMTIME_VERSION),
            ("wit-bindgen", WIT_BINDGEN_VERSION),
        ]
        .iter()
        .any(|(name, expected)| {
            !observed
                .dependency_versions
                .iter()
                .any(|(key, pin)| key.as_str() == *name && pin.as_str() == *expected)
        })
    {
        return Err(integrity());
    }
    if transport
        && !observed
            .dependency_versions
            .iter()
            .any(|(key, pin)| key.as_str() == "rama" && pin.as_str() == "0.4.0")
    {
        return Err(integrity());
    }
    let zero = Digest::from_sha256([0; 32]);
    if observed
        .fixture_digests
        .values()
        .chain(observed.binary_digests.values())
        .any(|digest| *digest == zero)
        || [
            observed.lockfile_sha256,
            observed.component_lockfile_sha256,
            observed.wit_sha256,
        ]
        .contains(&zero)
        || [
            observed.guest_package_manifest_sha256,
            observed.provisioning_sha256,
            observed.effective_config_sha256,
            observed.seccomp_sha256,
        ]
        .into_iter()
        .flatten()
        .any(|digest| digest == zero)
    {
        return Err(integrity());
    }
    Ok(())
}
