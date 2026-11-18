use razen_engine::adapters::guest::{preflight, transport::SupervisorBinding};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::values::{EntityId, WireInt};
use serde_json::json;
use std::path::Path;

#[path = "support/guest_fixture.rs"]
mod guest_fixture;

fn frame(kind: &str, payload: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"protocol":"razen.proof/0.1.0", "message_id":EntityId::new(), "kind":kind, "payload":payload})).unwrap();
    bytes.push(b'\n');
    bytes
}

fn assert_attempts(report: &serde_json::Value, required: &[&str]) {
    let attempts = report["attempts"]
        .as_array()
        .expect("actual syscall attempts");
    for variant in required {
        for actor in ["parent", "exec_descendant"] {
            let attempt = attempts
                .iter()
                .find(|v| v["variant"] == *variant && v["actor"] == actor)
                .unwrap();
            assert!(attempt["pid"].as_u64().unwrap() > 0);
            assert!(attempt["primitive_attempt_count"].as_u64().unwrap() > 0);
            assert_ne!(attempt["result"], "allowed");
            assert_eq!(attempt["healthy_control"], "completed");
        }
    }
}

#[test]
fn supervisor_transport_never_decodes_runtime_started_or_foreign_invocations() {
    let mut binding = SupervisorBinding::new(
        EntityId::new(),
        EntityId::new(),
        EntityId::new(),
        EntityId::new(),
        WireInt::ZERO,
        2_097_152,
    );
    assert!(binding.accept(&frame("started", json!({"capabilities":["brokered_calls","events","results","usage","cancellation","closure"]})), 1_048_576).is_err());
    assert!(
        binding
            .accept(
                &frame("started", json!({"invocation_id":EntityId::new()})),
                1_048_576
            )
            .is_err()
    );
    assert!(binding.accept(&frame("cancel", json!({"binding_id":EntityId::new(),"invocation_id":EntityId::new(),"lease_id":EntityId::new(),"control_revision":0,"reason":"foreign"})), 1_048_576).is_err());
}

#[test]
fn correlated_current_supervisor_errors_are_valid_but_foreign_errors_and_replays_are_not() {
    let invocation = EntityId::new();
    let request = EntityId::new();
    let mut binding = SupervisorBinding::new(
        EntityId::new(),
        invocation,
        EntityId::new(),
        EntityId::new(),
        WireInt::ZERO,
        2_097_152,
    );
    binding.register_request(request).unwrap();
    let response = |invocation| {
        let mut bytes=serde_json::to_vec(&json!({"protocol":"razen.proof/0.1.0","message_id":EntityId::new(),"correlation_id":request,"kind":"error","payload":{"invocation_id":invocation,"error":{"code":"isolation_unavailable","message":"mandatory boundary unavailable","retryability":"never","diagnostic_refs":[],"invocation_id":invocation}}})).unwrap();
        bytes.push(b'\n');
        bytes
    };
    assert!(
        binding
            .accept(&response(EntityId::new()), 1_048_576)
            .is_err()
    );
    let current = response(invocation);
    assert!(binding.accept(&current, 1_048_576).is_ok());
    assert!(binding.accept(&current, 1_048_576).is_err());
}

#[test]
fn doctor_of_an_unprepared_repository_is_read_only_and_never_adopts_default_lima() {
    let root = guest_fixture::PrivateRoot::new();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let profile = LoadedProfile::load(
        &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
    )
    .unwrap();
    let before = std::fs::read_dir(root.path()).unwrap().count();
    let report = preflight::doctor(root.path(), &profile).unwrap();
    assert!(!report.available);
    assert!(!report.blockers.is_empty());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), before);
}

#[test]
fn normalized_lima_empty_omissions_preserve_the_closed_effective_policy() {
    let profile = LoadedProfile::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
    )
    .unwrap();
    // Lima 2.3.0's actual normalized YAML/JSON omits empty maps and sequences.
    let normalized = json!({
        "vmType":"vz", "arch":"aarch64", "plain":true,
        "cpus":profile.config().external_runner.guest_cpus.get(), "memory":"2GiB",
        "propagateProxyEnv":false,
        "ssh":{"forwardAgent":false,"forwardX11":false,"forwardX11Trusted":false,
            "loadDotSSHPubKeys":false,"overVsock":false},
        "containerd":{"system":false,"user":false},
        "vmOpts":{"vz":{"rosetta":{"enabled":false}}},
        "hostResolver":{"enabled":false}, "user":{"name":"razen-manager"}
    });
    preflight::validate_configuration(&normalized, &profile).unwrap();
    let mut explicit = normalized.clone();
    for field in ["mounts", "portForwards", "networks"] {
        explicit[field] = json!([]);
        for contamination in [
            json!(null),
            json!({}),
            json!(""),
            json!([{"location":"/foreign"}]),
        ] {
            let mut value = normalized.clone();
            value[field] = contamination;
            assert!(
                preflight::validate_configuration(&value, &profile).is_err(),
                "{field} contamination"
            );
        }
    }
    explicit["env"] = json!({});
    preflight::validate_configuration(&explicit, &profile).unwrap();
    for contamination in [
        json!(null),
        json!([]),
        json!(""),
        json!({"HTTP_PROXY":"http://foreign"}),
    ] {
        let mut value = normalized.clone();
        value["env"] = contamination;
        assert!(preflight::validate_configuration(&value, &profile).is_err());
    }
    for (path, field) in [
        ("", "plain"),
        ("", "propagateProxyEnv"),
        ("ssh", "forwardAgent"),
        ("hostResolver", "enabled"),
        ("containerd", "system"),
    ] {
        let mut value = normalized.clone();
        let object = if path.is_empty() {
            value.as_object_mut().unwrap()
        } else {
            value[path].as_object_mut().unwrap()
        };
        object.remove(field);
        assert!(
            preflight::validate_configuration(&value, &profile).is_err(),
            "security flag {path}/{field} may not default"
        );
    }
}

#[test]
fn genuine_prepared_guest_live_validation_accepts_the_generated_private_catalog() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let profile = LoadedProfile::load(
        &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
    )
    .unwrap();
    let record: preflight::PreparedRecord = serde_json::from_slice(
        &std::fs::read(repository.join("target/r0-guest/prepared.json")).unwrap(),
    )
    .unwrap();
    let catalog =
        std::fs::symlink_metadata(record.lima_home.join("_config/networks.yaml")).unwrap();
    assert!(
        catalog.is_file() && !catalog.file_type().is_symlink(),
        "exercise the genuine generated-catalog condition, not an absent catalog"
    );
    let guest = preflight::PreparedGuest::discover(&repository, &profile).unwrap();
    guest.validate_live(&profile).unwrap();
}

#[test]
fn effective_configuration_and_actual_namespace_uid_controller_attestation_are_required() {
    let fixture = guest_fixture::Fixture::new();
    let observation = fixture.execute("RUN-02");
    assert!(
        !observation.report["attestations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for variant in observation.report["contaminations"].as_array().unwrap() {
        assert_eq!(variant["launch_admitted"], false);
        assert!(variant["error"]["code"].is_string());
    }
}

#[test]
fn parent_and_exec_descendant_reads_have_real_denials_and_fresh_snapshot_successors() {
    let fixture = guest_fixture::Fixture::new();
    let observation = fixture.execute("RUN-03");
    assert_attempts(
        &observation.report,
        &[
            "host_canary",
            "manager_canary",
            "other_invocation",
            "credential",
        ],
    );
    guest_fixture::assert_fresh_successors(&observation.report);
}

#[test]
fn all_network_families_have_reachable_controls_and_zero_unauthorized_observer_arrivals() {
    let fixture = guest_fixture::Fixture::new();
    let observation = fixture.execute("RUN-04");
    assert_attempts(
        &observation.report,
        &[
            "ipv4_tcp",
            "ipv6_tcp",
            "ipv4_udp",
            "ipv6_udp",
            "dns",
            "loopback",
            "gateway",
            "target",
            "model",
            "unix",
            "vsock",
            "inherited_fd",
        ],
    );
    for observer in observation.report["observers"].as_array().unwrap() {
        assert!(observer["healthy_arrivals"].as_u64().unwrap() > 0);
        assert_eq!(observer["unauthorized_arrivals"], 0);
    }
    guest_fixture::assert_fresh_successors(&observation.report);
}

#[test]
fn resource_floods_and_escape_attempts_are_attributed_to_real_kernel_or_deadline_failures() {
    let fixture = guest_fixture::Fixture::new();
    let observation = fixture.execute("RUN-05");
    assert_attempts(
        &observation.report,
        &[
            "fork",
            "thread",
            "memory",
            "cpu",
            "tmpfs",
            "output",
            "privilege",
            "namespace",
            "cgroup",
            "descriptor",
        ],
    );
    guest_fixture::assert_fresh_successors(&observation.report);
}

#[path = "support/guest_transport_fixture.rs"]
mod guest_transport_fixture;

#[test]
fn close_seals_every_outbound_api_but_keeps_terminal_drain_and_successor_safe() {
    use razen_engine::protocol::error::ErrorCode;
    let fixture = guest_transport_fixture::Fixture::new();
    let mut old = fixture.launch();
    let lease = old.lease_id;
    let revision = WireInt::new(1).unwrap();
    old.close(lease, revision, "regression closure").unwrap();
    for result in [
        old.close(lease, revision, "repeated closure"),
        old.refresh(lease, revision),
        old.cancel(lease, revision, "late cancellation"),
        old.send_runtime(b"not a runtime envelope\n"),
    ] {
        assert_eq!(
            result.unwrap_err().code,
            ErrorCode::Cancelled,
            "closed transport must reject locally before parsing or contacting the guest"
        );
    }
    let contained = old.terminate(lease, revision).unwrap();
    assert!(contained.empty_cgroup);
    assert!(!contained.vm_force_stopped);
    let journal = old.read_termination_record().unwrap();
    assert_eq!(journal["control_revision"], 1);
    assert_eq!(journal["empty_cgroup"], true);
    assert!(old.containment().unwrap().empty_cgroup);

    let mut successor = fixture.launch();
    assert!(old.refresh(lease, revision).is_err());
    assert!(
        old.cancel(lease, revision, "cannot affect successor")
            .is_err()
    );
    drop(old);
    successor
        .refresh(successor.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(
        successor
            .terminate(successor.lease_id, WireInt::ZERO)
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn failed_close_encoding_preserves_the_current_revision_and_outbound_authority() {
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    let lease = invocation.lease_id;
    let oversized = "x".repeat(1_048_577);
    assert!(
        invocation
            .close(lease, WireInt::new(1).unwrap(), &oversized)
            .is_err()
    );
    invocation
        .refresh(lease, WireInt::ZERO)
        .expect("an unsent close must not advance the binding revision or seal outbound authority");
    invocation
        .close(lease, WireInt::new(1).unwrap(), "valid closure")
        .unwrap();
    assert!(
        invocation
            .terminate(lease, WireInt::new(1).unwrap())
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn cancel_seals_every_outbound_api_without_aborting_native_containment() {
    use razen_engine::protocol::error::ErrorCode;
    let fixture = guest_transport_fixture::Fixture::new();
    let mut old = fixture.launch();
    let lease = old.lease_id;
    let revision = WireInt::new(1).unwrap();
    old.cancel(lease, revision, "regression cancellation")
        .unwrap();
    for result in [
        old.refresh(lease, revision),
        old.cancel(lease, revision, "repeated cancellation"),
        old.close(lease, revision, "late closure"),
        old.send_runtime(b"not a runtime envelope\n"),
    ] {
        assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
    }
    let contained = old.terminate(lease, revision).unwrap();
    assert!(
        contained.empty_cgroup,
        "a locally rejected refresh must not abort the native cancellation journal"
    );
    assert!(!contained.vm_force_stopped);
    let journal = old.read_termination_record().unwrap();
    assert_eq!(journal["control_revision"], 1);
    assert_eq!(journal["empty_cgroup"], true);
    let mut successor = fixture.launch();
    drop(old);
    successor
        .refresh(successor.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(
        successor
            .terminate(successor.lease_id, WireInt::ZERO)
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn failed_cancel_encoding_preserves_revision_and_outbound_authority() {
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    let lease = invocation.lease_id;
    assert!(
        invocation
            .cancel(lease, WireInt::new(1).unwrap(), &"x".repeat(1_048_577))
            .is_err()
    );
    invocation
        .refresh(lease, WireInt::ZERO)
        .expect("an unsent cancellation cannot advance or seal the binding");
    invocation
        .cancel(lease, WireInt::new(1).unwrap(), "valid cancellation")
        .unwrap();
    assert!(
        invocation
            .terminate(lease, WireInt::new(1).unwrap())
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn runtime_schema_failure_does_not_seal_unsent_authority_or_advance_revision() {
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    assert!(
        invocation
            .send_runtime(b"not a runtime envelope\n")
            .is_err()
    );
    invocation
        .refresh(invocation.lease_id, WireInt::ZERO)
        .expect("pure local schema failure has no delivery effect");
    invocation
        .close(
            invocation.lease_id,
            WireInt::new(1).unwrap(),
            "close after unsent runtime input",
        )
        .unwrap();
    let contained = invocation
        .terminate(invocation.lease_id, WireInt::new(1).unwrap())
        .unwrap();
    assert!(contained.empty_cgroup);
    assert!(!contained.vm_force_stopped);
    assert_eq!(
        invocation.read_termination_record().unwrap()["control_revision"],
        1
    );
}

#[test]
fn actual_runtime_management_failure_seals_outbound_but_keeps_containment_and_successors() {
    use razen_engine::protocol::error::ErrorCode;
    use std::time::{Duration, Instant};
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    let lease = invocation.lease_id;
    // Let the actual independent lease terminate the native FIFO while deliberately not
    // polling its terminal reply. The host still has outbound authority before this attempt.
    let started = Instant::now();
    loop {
        if invocation.read_termination_record().is_ok() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "real native lease must publish its authenticated journal"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let runtime_close = frame(
        "close",
        json!({"reason":"delivery to actually terminated native runtime"}),
    );
    let error = invocation.send_runtime(&runtime_close).unwrap_err();
    assert_ne!(
        error.code,
        ErrorCode::Cancelled,
        "the first failure must come from the actual native management delivery, not a local terminal flag"
    );
    for result in [
        invocation.send_runtime(b"not a runtime envelope\n"),
        invocation.refresh(lease, WireInt::ZERO),
        invocation.cancel(
            lease,
            WireInt::new(1).unwrap(),
            "cannot reuse uncertain delivery authority",
        ),
        invocation.close(
            lease,
            WireInt::new(1).unwrap(),
            "cannot reuse uncertain delivery authority",
        ),
    ] {
        assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
    }
    assert_eq!(
        invocation.read_termination_record().unwrap()["control_revision"],
        0
    );
    let contained = invocation.terminate(lease, WireInt::ZERO).unwrap();
    assert!(contained.empty_cgroup);
    assert!(!contained.vm_force_stopped);
    let mut successor = fixture.launch();
    drop(invocation);
    successor
        .refresh(successor.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(
        successor
            .terminate(successor.lease_id, WireInt::ZERO)
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn stop_only_discovery_survives_unavailable_guest_transport_without_authorizing_execution() {
    struct KnownHostsGuard {
        original: std::path::PathBuf,
        held: std::path::PathBuf,
    }
    impl Drop for KnownHostsGuard {
        fn drop(&mut self) {
            assert!(
                matches!(self.original.symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "never overwrite a concurrently replaced trust resource"
            );
            std::fs::rename(&self.held, &self.original)
                .expect("restore only this test's actual owned known-hosts resource");
        }
    }
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    let record: preflight::PreparedRecord = serde_json::from_slice(
        &std::fs::read(fixture.repository.join("target/r0-guest/prepared.json")).unwrap(),
    )
    .unwrap();
    let original = record.lima_home.join("known_hosts");
    let held = record
        .lima_home
        .join(format!("known_hosts-test-owned-{}", EntityId::new()));
    assert!(
        matches!(held.symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    );
    std::fs::rename(&original, &held).unwrap();
    let guard = KnownHostsGuard { original, held };
    assert!(
        preflight::PreparedGuest::discover(&fixture.repository, &fixture.profile).is_err(),
        "normal execution discovery must still require actual authenticated guest inspection"
    );
    let stop = preflight::PreparedGuestStop::discover(&fixture.repository, &fixture.profile)
        .expect("host-authenticated stop discovery must not require the broken guest transport");
    assert!(
        stop.stop_for_run(fixture.run_id).is_err(),
        "stop loading alone cannot bypass a live invocation's exclusive capacity"
    );
    drop(guard);
    fixture.guest.validate_live(&fixture.profile).unwrap();
    let contained = invocation
        .terminate(invocation.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(contained.empty_cgroup);
    assert!(!contained.vm_force_stopped);
}

#[test]
fn run_scoped_stop_cannot_stop_another_runs_independently_recoverable_occupancy() {
    use std::time::{Duration, Instant};
    let fixture = guest_transport_fixture::Fixture::new();
    let mut invocation = fixture.launch();
    let invocation_id = invocation.invocation_id;
    invocation.detach_transport().unwrap();
    let started = Instant::now();
    loop {
        if invocation.read_termination_record().is_ok() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(4));
        std::thread::sleep(Duration::from_millis(10));
    }
    let marker = fixture.repository.join("target/r0-guest/invocation.lock");
    let before = std::fs::read(&marker).unwrap();
    assert!(!before.is_empty());
    assert!(
        fixture.guest.stop_for_run(EntityId::new()).is_err(),
        "even a healthy journal and free flock cannot authorize stopping another run"
    );
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        before,
        "rejected stop must not release another run's occupancy"
    );
    assert!(
        invocation.read_termination_record().is_ok(),
        "rejected stop must leave the owned VM running"
    );
    let mut successor = fixture.launch();
    assert_ne!(invocation_id, successor.invocation_id);
    assert!(
        fixture.guest.stop_for_run(fixture.run_id).is_err(),
        "a live successor's held capacity forbids a concurrent VM stop"
    );
    drop(invocation);
    successor
        .refresh(successor.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(
        successor
            .terminate(successor.lease_id, WireInt::ZERO)
            .unwrap()
            .empty_cgroup
    );
}

#[test]
fn an_unlocked_malformed_occupancy_record_does_not_authorize_a_new_guest_launch() {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    struct OccupancyGuard {
        file: std::fs::File,
        injected: Vec<u8>,
    }
    impl Drop for OccupancyGuard {
        fn drop(&mut self) {
            rustix::fs::flock(
                &self.file,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .expect("regain this test's inactive occupancy lock");
            self.file.seek(SeekFrom::Start(0)).unwrap();
            let mut current = Vec::new();
            self.file.read_to_end(&mut current).unwrap();
            assert_eq!(
                current, self.injected,
                "never erase a foreign or concurrently changed occupancy record"
            );
            self.file.set_len(0).unwrap();
            self.file.sync_all().unwrap();
        }
    }
    let fixture = guest_transport_fixture::Fixture::new();
    let launch = fixture.stage_launch();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(fixture.repository.join("target/r0-guest/invocation.lock"))
        .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut previous = Vec::new();
    file.read_to_end(&mut previous).unwrap();
    assert!(
        previous.is_empty(),
        "test requires genuinely unoccupied prepared capacity; never replace foreign state"
    );
    let injected = b"{interrupted-occupancy-write".to_vec();
    file.write_all(&injected).unwrap();
    file.sync_all().unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock).unwrap();
    let _guard = OccupancyGuard { file, injected };
    let result = fixture.guest.launch(launch, &fixture.profile);
    let rejected = result.is_err();
    if let Ok(mut wrongly_admitted) = result {
        let lease = wrongly_admitted.lease_id;
        wrongly_admitted.terminate(lease, WireInt::ZERO).unwrap();
    }
    assert!(
        rejected,
        "flock availability is not evidence that a persisted unknown invocation is contained"
    );
}

#[test]
fn a_closed_orphan_object_cannot_stop_a_successor_after_independent_cleanup() {
    use std::time::{Duration, Instant};
    let fixture = guest_transport_fixture::Fixture::new();
    let mut old = fixture.launch();
    let invocation = old.invocation_id;
    let lease = old.lease_id;
    old.close(
        lease,
        WireInt::new(1).unwrap(),
        "close before transport loss",
    )
    .unwrap();
    old.detach_transport().unwrap();
    let started = Instant::now();
    loop {
        if let Ok(bytes) = fixture.guest.guest_command(
            &["--termination", &invocation.to_string()],
            None,
            Duration::from_secs(2),
        ) {
            let journal: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(journal["invocation_id"], invocation.to_string());
            assert_eq!(journal["lease_id"], lease.to_string());
            assert_eq!(journal["empty_cgroup"], true);
            assert_eq!(journal["cgroup_populated_after"], 0);
            assert_eq!(journal["descendants_after"], 0);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "independent native keeper must produce actual containment before a successor"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut successor = fixture.launch();
    assert_ne!(old.invocation_id, successor.invocation_id);
    drop(old);
    successor
        .refresh(successor.lease_id, WireInt::ZERO)
        .unwrap();
    let contained = successor
        .terminate(successor.lease_id, WireInt::ZERO)
        .unwrap();
    assert!(
        contained.empty_cgroup,
        "dropping an old owner must not force-stop a successor's VM"
    );
    assert!(!contained.vm_force_stopped);
}
