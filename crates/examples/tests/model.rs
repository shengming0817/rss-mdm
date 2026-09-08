use rss_mdm_examples::fixture::FixtureAuthority;
use rss_mdm_inventory::{coverage, validate};
use rss_observation::{Access, Authority, Batch, Id, Scope};
fn scope() -> Scope {
    serde_json::from_str(r#"{"tenant":"00000000-0000-0000-0000-000000000001","object":"device-1","registration":"reg-1","source":"fixture","dataset":"inventory","epoch":"epoch-1"}"#).unwrap()
}
#[test]
fn explicit_authority_rejects_foreign_scope_and_coverage() {
    let s = scope();
    let a = FixtureAuthority::new(s.clone());
    assert!(
        a.authorize(Access::Submit {
            scope: &s,
            coverage: &coverage()
        })
        .is_ok()
    );
    let other = serde_json::from_str::<Scope>(&s.encode().unwrap().replace("device-1", "device-2"))
        .unwrap();
    assert!(a.authorize(Access::Read { scope: &other }).is_err());
    let wrong = rss_observation::Coverage::new(
        Id::new("wrong").unwrap(),
        Id::new("1").unwrap(),
        Id::new("1").unwrap(),
        Id::new("1").unwrap(),
    );
    assert!(
        a.authorize(Access::Submit {
            scope: &s,
            coverage: &wrong
        })
        .is_err()
    );
}
#[test]
fn operation_and_both_cleanup_failures_remain_visible_without_secrets() {
    use rss_mdm_examples::failure;
    let result: anyhow::Result<()> = failure::finish(
        Err(failure::at("ingest", anyhow::anyhow!("SECRET-primary"))),
        [
            ("projection_close", Err(anyhow::anyhow!("SECRET-cleanup"))),
            ("observation_close", Err(anyhow::anyhow!("SECRET-other"))),
        ],
    );
    let report = failure::report(result.unwrap_err());
    assert_eq!(report["problems"].as_array().unwrap().len(), 3);
    assert_eq!(report["problems"][1]["stage"], "projection_close");
    assert!(!report.to_string().contains("SECRET"));
    assert!(
        failure::report(failure::at("usage", anyhow::anyhow!("bad")))["hint"]
            .as_str()
            .unwrap()
            .contains("ingest-fixture FILE")
    );
}
#[test]
fn committed_fixture_uses_public_batch_encoding() {
    let batch = Batch::decode(include_bytes!("../../../fixtures/snapshot.json")).unwrap();
    validate(&batch).unwrap();
}

#[test]
fn signal_errors_are_distinct_and_redacted_with_cleanup() {
    use rss_mdm_examples::failure;
    let cancelled = failure::report(failure::signal(Ok(())));
    assert_eq!(cancelled["problems"][0]["stage"], "cancelled");
    assert_eq!(cancelled["problems"][0]["kind"], "Cancelled");
    let result: anyhow::Result<()> = failure::finish(
        Err(failure::signal(Err(std::io::Error::other(
            "SECRET listener",
        )))),
        [("close", Err(anyhow::anyhow!("SECRET cleanup")))],
    );
    let report = failure::report(result.unwrap_err());
    assert_eq!(report["problems"][0]["stage"], "signal");
    assert_eq!(report["problems"][0]["kind"], "SignalUnavailable");
    assert_eq!(report["problems"].as_array().unwrap().len(), 2);
    assert!(!report.to_string().contains("SECRET"));
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "Test chooses one anchor; all advances use the injected source"
)]
fn shared_clock_derives_observation_projection_and_deadlines() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };
    let anchor = Instant::now();
    let ticks = Arc::new(AtomicU64::new(0));
    let input = ticks.clone();
    let clock = rss_mdm_examples::Clock::new(move || {
        anchor + Duration::from_secs(input.load(Ordering::SeqCst))
    });
    let cloned = clock.clone();
    ticks.store(90, Ordering::SeqCst);
    assert_eq!(
        rss_observation::Clock::now(&cloned),
        anchor + Duration::from_secs(90)
    );
    assert_eq!(rss_projection::Timer::now(&clock), Duration::from_secs(90));
    assert_eq!(
        clock.cutoff(rss_mdm_examples::BUDGET),
        Duration::from_secs(120)
    );
    assert_eq!(
        clock.deadline(),
        rss_request_context::Deadline::at(anchor + Duration::from_secs(120))
    );
}
