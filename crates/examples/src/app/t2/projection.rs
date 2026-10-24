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
    known(&original, &scope(1, "d1"), "first", "Model-A");
    assert!(matches!(
        a.ingest(first.clone()).await?,
        ReceiveOutcome::Replay(_)
    ));
    let conflict = a
        .ingest(batch("first", 0, Body::Snapshot(facts("Conflict"))))
        .await
        .unwrap_err();
    assert_eq!(conflict.to_string(), "collection result conflict");
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
    known(
        &inspect(&other, "first").await?,
        &scope(2, "d1"),
        "first",
        "Tenant-B",
    );
    known(
        &inspect(&sibling, "sibling-first").await?,
        &scope(1, "d2"),
        "sibling-first",
        "Sibling",
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
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn missing_collection_and_corrupt_result_preserve_projection() -> Result<()> {
    let stream = scope(1, "validation");
    let a = app(stream.clone()).await?;
    let cancel = CancellationToken::new();
    a.ingest(batch("control", 0, Body::Snapshot(facts("Control"))))
        .await?;
    a.project(&cancel).await?;
    known(
        &inspect(&a, "control").await?,
        &stream,
        "control",
        "Control",
    );
    use sqlx::Connection;
    let mut owner = sqlx::PgConnection::connect_with(&url("MDM_OWNER_URL")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(stream.tenant().to_string())
        .execute(&mut owner)
        .await?;
    for (sequence, id) in [(1, "missing-definition"), (2, "corrupt-result")] {
        a.ingest(batch(id, sequence, Body::Snapshot(facts("Recovered"))))
            .await?;
        let before = inspect(&a, id).await?;
        assert_eq!(before["projection"], "not_projected");
        let saved: String = if sequence == 1 {
            sqlx::query_scalar("DELETE FROM mdm.collection_definitions d WHERE tenant_id=$1::uuid AND dataset='inventory' AND source='agent.builtin' RETURNING to_jsonb(d)::text")
                .bind(stream.tenant().to_string()).fetch_one(&mut owner).await?
        } else {
            let digest: String = sqlx::query_scalar(
                "SELECT digest FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2",
            )
            .bind(stream.tenant().to_string())
            .bind(id)
            .fetch_one(&mut owner)
            .await?;
            let changed = sqlx::query("UPDATE mdm.collection_results SET digest=repeat('0',64) WHERE tenant_id=$1::uuid AND run=$2")
                .bind(stream.tenant().to_string()).bind(id).execute(&mut owner).await?;
            assert_eq!(changed.rows_affected(), 1);
            digest
        };
        let rejected = a.project(&cancel).await;
        // Restore precisely the damaged source material; retry the original received batch.
        if sequence == 1 {
            sqlx::query("INSERT INTO mdm.collection_definitions SELECT * FROM jsonb_populate_record(NULL::mdm.collection_definitions,$1::jsonb)")
                .bind(saved).execute(&mut owner).await?;
        } else {
            sqlx::query(
                "UPDATE mdm.collection_results SET digest=$3 WHERE tenant_id=$1::uuid AND run=$2",
            )
            .bind(stream.tenant().to_string())
            .bind(id)
            .bind(saved)
            .execute(&mut owner)
            .await?;
        }
        assert_eq!(
            rejected
                .unwrap_err()
                .downcast_ref::<rss_projection::Error>()
                .unwrap()
                .kind(),
            rss_projection::ErrorKind::Rejected
        );
        assert_eq!(inspect(&a, id).await?, before);
        assert_eq!(a.project(&cancel).await?["applied"], 1);
        let recovered = inspect(&a, id).await?;
        assert_eq!(recovered["projection"], "projected");
        known(&recovered, &stream, id, "Recovered");
    }
    owner.close().await?;
    a.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn invocation_horizon() -> Result<()> {
    let a = std::sync::Arc::new(app(scope(6, "window")).await?);
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect_with(&storage::collection_options()?).await?;
    let stream = scope(6, "window");
    let authority = FixtureAuthority::new(stream.clone());
    let definition = crate::fixture::definition();
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&authority, stream.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(stream.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, stream.tenant(), &definition)
        .await?;
    let mut prepared = Vec::new();
    for sequence in 0..257 {
        let batch = batch(
            &format!("window-{sequence}"),
            sequence,
            Body::Snapshot(facts("Window")),
        );
        let progress = model::CollectionProgress::reported(
            definition.clone(),
            batch.body(),
            batch.observed_at_seconds(),
        )?;
        let sealed = rss_mdm_inventory_postgres::seal_collection_in(
            &mut tx,
            rss_mdm_inventory_postgres::CollectionCompletion {
                scope: &stream,
                run: batch.id().as_str(),
                sequence,
                observed_at: batch.observed_at_seconds(),
                progress: &progress,
            },
        )
        .await?;
        prepared.push(VerifiedBatch::verify(&authority, stream.clone(), sealed)?);
    }
    tx.commit().await?;
    let mut journal = sqlx::PgConnection::connect_with(&storage::options()?).await?;
    let mut tx = journal.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(stream.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    let (state, policy): (String, String) =
        sqlx::query_as("SELECT state,policy FROM rss_observation.lock_stream($1)")
            .bind(stream.encode()?)
            .fetch_one(&mut *tx)
            .await?;
    let mut state = rss_observation::State::decode(&state)?;
    let policy = rss_observation::Policy::decode(&policy)?;
    let received: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    for input in prepared {
        let batch = input.batch();
        let decision = state.advance(batch, received as u64, &policy)?;
        sqlx::query(
            "SELECT rss_observation.commit_batch($1,$2,$3::numeric,$4,$5,$6,$7,$8,$9::numeric,$10)",
        )
        .bind(stream.encode()?)
        .bind(batch.id().as_str())
        .bind(batch.sequence().to_string())
        .bind(batch.encode())
        .bind(input.fingerprint().as_slice())
        .bind(received)
        .bind(policy.encode()?)
        .bind(decision.encode()?)
        .bind(state.revision().to_string())
        .bind(decision.outcome().is_applicable())
        .execute(&mut *tx)
        .await?;
        state = decision.state().clone();
    }
    tx.commit().await?;
    journal.close().await?;
    connection.close().await?;
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
    assert_eq!(
        inspect(&a, "window-later").await?["projection"],
        "not_projected"
    );
    assert_eq!(a.project(&CancellationToken::new()).await?["applied"], 1);
    known(
        &inspect(&a, "window-later").await?,
        &stream,
        "window-later",
        "NextInvocation",
    );
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
    a.ingest(batch("empty-after-value", 2, Body::Snapshot(vec![])))
        .await?;
    a.project(&cancel).await?;
    let emptied = inspect(&a, "empty-after-value").await?;
    for (key, value) in [("device.model", "Delete"), ("device.os.version", "1")] {
        let fact = &fields(&emptied)[key]["fact"];
        assert_eq!(fact["state"]["kind"], "deleted");
        assert_eq!(
            fact["lastKnown"]["value"],
            serde_json::json!({"kind":"string","value":value})
        );
        assert_eq!(fact["lastKnown"]["evidence"]["snapshotId"], "populated");
    }
    a.ingest(batch("populated-again", 3, Body::Snapshot(facts("Delete"))))
        .await?;
    a.project(&cancel).await?;
    a.ingest(batch(
        "delete",
        4,
        Body::Delta {
            baseline: Id::new("populated-again")?,
            previous: 3,
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
    assert_eq!(view["assets"].as_array().unwrap().len(), 2);
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

#[tokio::test]
#[ignore = "MODULE=inventory.projection: real PostgreSQL"]
async fn narrower_snapshot_preserves_unselected_fields_in_the_same_source_scope() -> Result<()> {
    use sqlx::Connection;
    let s = scope(1, "narrow-template");
    let a = app(s.clone()).await?;
    let producer = JournalFixture(s.clone());
    a.observation
        .activate(
            &rss_observation::LifecycleGrant::verify(&producer, s.clone())?,
            None,
            &rss_observation::Policy::new(86400, 3600, 3600)?,
            a.clock.deadline(),
        )
        .await?;
    let base = crate::fixture::definition();
    let narrow = model::CollectionDefinition::new(base.dataset(), "narrow-v1", base.source(), {
        let scope = rss_mdm_inventory::CollectionScope::Device;
        let fields: Vec<rss_mdm_inventory::FieldDefinition> =
            vec![base.field(model::builtin::MODEL)?.clone()];
        fields
            .into_iter()
            .map(|definition| rss_mdm_inventory::CollectionField {
                definition,
                scope: scope.clone(),
            })
            .collect()
    })?;
    let mut c = sqlx::PgConnection::connect_with(&storage::collection_options()?).await?;
    let mut wide_os = None;
    for (sequence, (id, definition, values)) in [
        ("wide", &base, facts("first")),
        ("narrow", &narrow, vec![facts("second").remove(0)]),
        ("empty-narrow", &narrow, vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        let at = batch(id, sequence as u64, Body::Snapshot(vec![])).observed_at_seconds();
        let progress =
            model::CollectionProgress::reported(definition.clone(), &Body::Snapshot(values), at)?;
        let mut tx = c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(s.tenant().to_string())
            .execute(&mut *tx)
            .await?;
        rss_mdm_inventory_postgres::register_collection_in(&mut tx, s.tenant(), definition).await?;
        let reference = rss_mdm_inventory_postgres::seal_collection_in(
            &mut tx,
            rss_mdm_inventory_postgres::CollectionCompletion {
                scope: &s,
                run: id,
                sequence: sequence as u64,
                observed_at: at,
                progress: &progress,
            },
        )
        .await?;
        tx.commit().await?;
        a.observation
            .receive(
                &VerifiedBatch::verify(&producer, s.clone(), reference)?,
                a.clock.deadline(),
            )
            .await?;
        a.project(&CancellationToken::new()).await?;
        let view = inspect(&a, id).await?;
        let map = fields(&view);
        if id == "wide" {
            wide_os = Some(map["device.os.version"].clone());
        } else {
            assert_eq!(Some(map["device.os.version"]), wide_os.as_ref());
        }
        assert_eq!(
            map["device.os.version"]["fact"]["state"]["value"],
            serde_json::json!({"kind":"string","value":"1"})
        );
        assert_eq!(
            map["device.os.version"]["fact"]["evidence"]["snapshotId"],
            "wide"
        );
        assert_eq!(map["device.os.version"]["scope"], s.encode()?);
        if id == "narrow" {
            assert_eq!(
                map["device.model"]["fact"]["state"]["value"],
                serde_json::json!({"kind":"string","value":"second"})
            );
        }
    }
    let view = inspect(&a, "empty-narrow").await?;
    assert_eq!(
        fields(&view)["device.model"]["fact"]["lastKnown"]["value"],
        serde_json::json!({"kind":"string","value":"second"})
    );
    let assets = view["assets"].as_array().unwrap();
    assert!(
        assets
            .iter()
            .any(|v| v["field"] == "device.os.version" && v["fact"]["state"]["kind"] == "known")
    );
    assert!(
        assets
            .iter()
            .any(|v| v["field"] == "device.model" && v["fact"]["state"]["kind"] == "deleted")
    );
    c.close().await?;
    a.close().await?;
    Ok(())
}
