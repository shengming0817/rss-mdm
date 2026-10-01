use super::*;
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn projection_and_tenant_scopes() -> Result<()> {
    let a = app(scope(1, "d1")).await?;
    let cancel = CancellationToken::new();
    let first = batch("first", 0, Body::Snapshot(facts("Model-A")));
    assert!(matches!(
        a.ingest(first.clone()).await?,
        ReceiveOutcome::Accepted(_)
    ));
    assert!(
        inspect(&a, "first").await?["assets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(inspect(&a, "first").await?["projection"], "not_projected");
    assert_eq!(a.project(&cancel).await?["applied"], 1);
    let original = inspect(&a, "first").await?;
    assert_eq!(original["projection"], "projected");
    assert_eq!(original["assets"].as_array().unwrap().len(), 2);
    assert!(matches!(
        a.ingest(first.clone()).await?,
        ReceiveOutcome::Replay(_)
    ));
    assert!(
        a.ingest(batch("first", 0, Body::Snapshot(facts("Conflict"))))
            .await
            .is_err()
    );
    assert_eq!(a.project(&cancel).await?["applied"], 0);
    assert_eq!(inspect(&a, "first").await?, original);
    for (i, body) in [
        Body::Partial(facts("partial")),
        Body::Failed {
            code: Id::new("collection-failed")?,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("incomplete-{i}");
        a.ingest(batch(&id, i as u64 + 1, body)).await?;
        assert_eq!(a.project(&cancel).await?["applied"], 1);
        let view = inspect(&a, &id).await?;
        assert!(!view["receipt"].is_null());
        assert_eq!(view["projection"], "projected");
        assert!(
            view["assets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["fact"]["state"]["value"]["value"] == "partial")
        );
        assert_ne!(view["checkpoint"], original["checkpoint"]);
    }
    a.ingest(batch("full", 3, Body::Snapshot(facts("Model-B"))))
        .await?;
    a.project(&cancel).await?;
    a.ingest(batch(
        "delta",
        4,
        Body::Delta {
            baseline: Id::new("full")?,
            previous: 3,
            changes: vec![Change::delete(Id::new("device.os.version")?)],
        },
    ))
    .await?;
    a.project(&cancel).await?;
    assert_eq!(
        inspect(&a, "delta").await?["assets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["fact"]["state"]["kind"] == "known")
            .count(),
        1
    );
    let other = app(scope(2, "d1")).await?;
    other
        .ingest(batch("first", 0, Body::Snapshot(facts("Tenant-B"))))
        .await?;
    other.project(&cancel).await?;
    let sibling = app(scope(1, "d2")).await?;
    sibling
        .ingest(batch("sibling-first", 0, Body::Snapshot(facts("Sibling"))))
        .await?;
    assert_eq!(
        inspect(&sibling, "sibling-first").await?["projection"],
        "not_projected"
    );
    sibling.project(&cancel).await?;
    a.ingest(batch("empty", 5, Body::Snapshot(vec![]))).await?;
    a.project(&cancel).await?;
    assert!(
        inspect(&a, "empty").await?["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["fact"]["state"]["kind"] == "deleted" && !a["fact"]["lastKnown"].is_null())
    );
    assert_eq!(
        inspect(&other, "first").await?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        inspect(&sibling, "sibling-first").await?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    other.close().await?;
    sibling.close().await?;
    a.close().await?;
    Ok(())
}
// Test producer deliberately exercises product projection validation independently
// of ingest's own validation. It grants exactly one scope, never arbitrary tenants.
struct JournalFixture(Scope);
impl rss_observation::Authority for JournalFixture {
    fn authorize(&self, access: rss_observation::Access<'_>) -> Result<(), rss_observation::Error> {
        let allowed = match access {
            rss_observation::Access::Activate { scope }
            | rss_observation::Access::Submit { scope, .. } => scope == &self.0,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
#[allow(
    clippy::disallowed_methods,
    reason = "Real PG poison fixture timestamp must track server wall time"
)]
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn unregistered_dataset_and_poison_are_rejected() -> Result<()> {
    let a = app(scope(4, "validation")).await?;
    let s = scope(4, "not-inventory");
    let s: Scope = serde_json::from_str(
        &s.encode()?
            .replace("\"dataset\":\"inventory\"", "\"dataset\":\"other\""),
    )?;
    let producer = JournalFixture(s.clone());
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&producer, s.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    a.observation
        .receive(
            &VerifiedBatch::verify(
                &producer,
                s,
                batch("other", 0, Body::Snapshot(facts("Other"))),
            )?,
            a.clock.deadline(),
        )
        .await?;
    let cancel = CancellationToken::new();
    assert!(
        a.project(&cancel).await.is_err(),
        "unregistered dataset was accepted"
    );
    a.close().await?;
    let a = app(scope(1, "validation")).await?;
    let s = scope(1, "validation");
    let producer = JournalFixture(s.clone());
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&producer, s.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    let bad = rss_observation::Coverage::new(
        Id::new("device-basics")?,
        Id::new("2")?,
        Id::new("model-os")?,
        Id::new("unknown")?,
    );
    let b = Batch::new(
        Id::new("poison")?,
        0,
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
        bad,
        Body::Snapshot(facts("Invalid")),
    )?;
    a.observation
        .receive(&VerifiedBatch::verify(&producer, s, b)?, a.clock.deadline())
        .await?;
    let before = inspect(&a, "poison").await?;
    assert!(a.project(&cancel).await.is_err());
    assert_eq!(inspect(&a, "poison").await?, before);
    a.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn invocation_horizon() -> Result<()> {
    let a = std::sync::Arc::new(app(scope(6, "window")).await?);
    for sequence in 0..257 {
        a.ingest(batch(
            &format!("window-{sequence}"),
            sequence,
            Body::Snapshot(facts("Window")),
        ))
        .await?;
    }
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    let admin = storage::pool(&url("MDM_ADMIN_URL")?).await?;
    sqlx::raw_sql("CREATE FUNCTION mdm.window_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.batch_id='window-0' THEN PERFORM pg_advisory_xact_lock(2346002); PERFORM pg_sleep(0.3); END IF; RETURN NEW; END $$; CREATE TRIGGER window_pause AFTER INSERT ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.window_pause();").execute(&owner).await?;
    let worker_app = a.clone();
    let worker = tokio::spawn(async move { worker_app.project(&CancellationToken::new()).await });
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=2346002 AND granted)").fetch_one(&admin).await?;
            if staged {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    a.ingest(batch(
        "window-later",
        257,
        Body::Snapshot(facts("NextInvocation")),
    ))
    .await?;
    let first = tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert_eq!(first["applied"], 257);
    assert_eq!(first["position"], first["through"]);
    assert_eq!(a.project(&CancellationToken::new()).await?["applied"], 1);
    sqlx::raw_sql("DROP TRIGGER window_pause ON mdm.inventory; DROP FUNCTION mdm.window_pause();")
        .execute(&owner)
        .await?;
    a.close().await?;
    storage::close_pool(&owner).await?;
    storage::close_pool(&admin).await?;
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "Real PG scenario composition root chooses a monotonic clock"
)]
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn empty_and_delete() -> Result<()> {
    let a = app(scope(7, "empty")).await?;
    let cancel = CancellationToken::new();
    assert_eq!(inspect(&a, "missing").await?["projection"], "not_projected");
    a.ingest(batch("empty", 0, Body::Snapshot(vec![]))).await?;
    let before = inspect(&a, "empty").await?;
    assert_eq!(before["projection"], "not_projected");
    a.project(&cancel).await?;
    let after = inspect(&a, "empty").await?;
    assert!(before["assets"].as_array().unwrap().is_empty());
    assert_eq!(after["assets"].as_array().unwrap().len(), 2);
    assert!(
        after["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["fact"]["state"]["kind"] == "deleted" && v["fact"]["lastKnown"].is_null())
    );
    assert_eq!(after["projection"], "projected");
    a.ingest(batch("populated", 1, Body::Snapshot(facts("Delete"))))
        .await?;
    a.project(&cancel).await?;
    a.ingest(batch(
        "delete",
        2,
        Body::Delta {
            baseline: Id::new("populated")?,
            previous: 1,
            changes: vec![
                Change::delete(Id::new("device.model")?),
                Change::delete(Id::new("device.os.version")?),
            ],
        },
    ))
    .await?;
    assert_eq!(inspect(&a, "delete").await?["projection"], "not_projected");
    a.project(&cancel).await?;
    let view = inspect(&a, "delete").await?;
    assert!(
        view["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["fact"]["state"]["kind"] == "deleted" && !a["fact"]["lastKnown"].is_null())
    );
    assert_eq!(view["projection"], "projected");
    a.close().await?;
    Ok(())
}
