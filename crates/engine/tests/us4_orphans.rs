use razen_engine::adapters::guest::lifecycle::{LeaseClock, LeaseDecision};
use razen_engine::domain::values::{EntityId, WireInt};
use std::time::{Duration, Instant};
#[path = "support/guest_fixture.rs"]
mod guest_fixture;

#[test]
fn duplicate_refresh_never_extends_guest_monotonic_lease_and_closed_leases_never_revive() {
    let now = Instant::now();
    let lease = EntityId::new();
    let message = EntityId::new();
    let mut clock = LeaseClock::new(
        lease,
        WireInt::ZERO,
        now,
        Duration::from_millis(2000),
        Duration::from_millis(5000),
    )
    .unwrap();
    assert_eq!(
        clock
            .refresh(
                message,
                lease,
                WireInt::ZERO,
                now + Duration::from_millis(500)
            )
            .unwrap(),
        LeaseDecision::Refreshed
    );
    assert_eq!(
        clock
            .refresh(
                message,
                lease,
                WireInt::ZERO,
                now + Duration::from_millis(1900)
            )
            .unwrap(),
        LeaseDecision::Duplicate
    );
    assert!(clock.expired(now + Duration::from_millis(2501)));
    assert!(
        clock
            .refresh(
                EntityId::new(),
                lease,
                WireInt::ZERO,
                now + Duration::from_millis(2501)
            )
            .is_err()
    );
    assert!(
        clock
            .refresh(EntityId::new(), EntityId::new(), WireInt::ZERO, now)
            .is_err()
    );
}

#[test]
fn unique_current_refreshes_cannot_extend_the_original_wall_deadline() {
    let now = Instant::now();
    let lease = EntityId::new();
    let mut clock = LeaseClock::new(
        lease,
        WireInt::ZERO,
        now,
        Duration::from_millis(2000),
        Duration::from_millis(5000),
    )
    .unwrap();
    for elapsed in [1000, 2000, 3000, 4000] {
        assert_eq!(
            clock
                .refresh(
                    EntityId::new(),
                    lease,
                    WireInt::ZERO,
                    now + Duration::from_millis(elapsed)
                )
                .unwrap(),
            LeaseDecision::Refreshed
        );
    }
    assert!(clock.expired(now + Duration::from_millis(5000)));
    assert!(
        clock
            .refresh(
                EntityId::new(),
                lease,
                WireInt::ZERO,
                now + Duration::from_millis(5000)
            )
            .is_err()
    );
}

#[test]
fn host_and_ssh_loss_leave_independent_guest_watchdog_and_actual_empty_cgroup_proofs() {
    let fixture = guest_fixture::Fixture::new();
    let observation = fixture.execute("RUN-08");
    let variants = observation.report["orphan_variants"].as_array().unwrap();
    for required in ["host_sigkill", "ssh_sigkill"] {
        let variant = variants.iter().find(|v| v["variant"] == required).unwrap();
        assert!(variant["killed_pid"].as_u64().unwrap() > 0);
        if required == "host_sigkill" {
            assert_eq!(variant["engine_reaped"], true);
            assert_eq!(
                variant["transport_reaped"], false,
                "launchd adopts the SSH grandchild; never claim a parent waitpid"
            );
            assert_eq!(variant["ssh_exit_observed"], true);
        } else {
            assert_eq!(variant["transport_reaped"], true);
        }
        assert!(variant["guest_manager_pid"].as_u64().unwrap() > 0);
        assert_eq!(variant["lease_refreshes_after_loss"], 0);
        assert_eq!(variant["cgroup_populated_after"], 0);
        assert_eq!(variant["descendants_after"], 0);
        assert!(variant["guest_elapsed_us"].as_u64().unwrap() <= 3_200_000);
        assert_eq!(
            variant["observer_after_cleanup"],
            variant["observer_at_cleanup"]
        );
        assert!(variant["termination_record_sha256"].is_string());
    }
    guest_fixture::assert_fresh_successors(&observation.report);
}
