use super::*;

fn input(tenant: Uuid) -> Create {
    Create {
        database: config::Database {
            host: "localhost".into(),
            port: 5432,
            name: "fixture".into(),
            user: "mdm_owner".into(),
            password_file: "fixture-password".into(),
            ca_file: "fixture-ca".into(),
        },
        installation: Installation {
            instance_id: crate::test_support::identity::INSTANCE.into(),
            target: [1; 16],
            lineage: [2; 16],
            audit_mode: migration::AuditMode::Plain,
        },
        tenant_id: tenant.to_string(),
        initial_epoch: 1,
        operation_id: Uuid::new_v4(),
        name: None,
        notes: None,
    }
}
#[test]
fn registration_requires_canonical_tenant_positive_epoch_and_operation() {
    let mut request = input(Uuid::from_u128(0xab));
    assert!(validate(&request.mutation()).is_ok());
    request.tenant_id = request.tenant_id.to_uppercase();
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.tenant_id = Uuid::nil().to_string();
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.tenant_id = Uuid::new_v4().to_string();
    request.initial_epoch = 0;
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.initial_epoch = 1;
    request.name = Some("界".repeat(128));
    request.notes = Some("界".repeat(2048));
    assert!(validate(&request.mutation()).is_ok());
    request.name = Some("界".repeat(129));
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.name = Some("\u{2003}\t".into());
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.name = None;
    request.notes = Some("界".repeat(2049));
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
    request.notes = None;
    request.operation_id = Uuid::nil();
    assert_eq!(validate(&request.mutation()), Err(Reason::Invalid));
}

async fn counts(conn: &mut PgConnection, tenant: &str) -> anyhow::Result<(i64, i64, i64, i64)> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant)
        .execute(&mut *conn)
        .await?;
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM public.mdm_tenants WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_access.agent_enrollment_settings WHERE tenant_id=$1::uuid),(SELECT count(*) FROM public.mdm_tenant_operations WHERE tenant_id=$1::uuid)")
        .bind(tenant).fetch_one(conn).await?)
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: real atomic registration and epoch binding"]
async fn registration_replay_and_binding_preserve_existing_tenants() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = owner().await?;
    let mut runtime = profile("mdm_access", "access-fixture").await?;
    let a = input(Uuid::new_v4());
    let b = input(Uuid::new_v4());
    let a_receipt = create_on(&mut conn, &a).await?;
    let b_receipt = create_on(&mut conn, &b).await?;
    ensure!(create_on(&mut conn, &b).await? == b_receipt);
    ensure!(counts(&mut conn, &a.tenant_id).await? == (1, 1, 1, 1));
    ensure!(counts(&mut conn, &b.tenant_id).await? == (1, 1, 1, 1));
    // Actual tenant creation must seed the same current field definition used by native collection.
    let builtin = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.apple.installed_applications")
        .unwrap();
    let seeded: serde_json::Value = sqlx::query_scalar(
        "SELECT definition FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=$2 AND version=1"
    ).bind(&b.tenant_id).bind(builtin.key.as_str()).fetch_one(&mut conn).await?;
    ensure!(
        seeded == serde_json::to_value(&builtin)?,
        "tenant seed differs from current applications definition"
    );
    // This assertion protects the default enrollment grant duration, not all settings.
    let settings =
        rss_mdm_registration_service::agent::settings::read_on(&mut conn, &b.tenant_id).await?;
    ensure!(
        settings.revision == 1
            && settings.values.grant_seconds
                == rss_mdm_registration_service::agent::settings::Values::default().grant_seconds
    );
    claim_use(&mut runtime, &b.installation, &b.tenant_id, 1).await?;
    ensure!(matches!(
        claim_use(&mut runtime, &b.installation, &b.tenant_id, 2).await,
        Err(Error::Configuration(ConfigIssue::IdentityConfiguration))
    ));
    let mut collision = input(Uuid::parse_str(&b.tenant_id)?);
    ensure!(create_on(&mut conn, &collision).await == Err(Reason::Conflict));
    collision.operation_id = b.operation_id;
    collision.initial_epoch = 2;
    ensure!(create_on(&mut conn, &collision).await == Err(Reason::Conflict));
    for field in ["instance_id", "target", "lineage", "audit_mode"] {
        let mut changed = input(Uuid::new_v4());
        match field {
            "instance_id" => changed.installation.instance_id = Uuid::new_v4().to_string(),
            "target" => changed.installation.target = [3; 16],
            "lineage" => changed.installation.lineage = [4; 16],
            _ => changed.installation.audit_mode = migration::AuditMode::Ledger,
        }
        ensure!(create_on(&mut conn, &changed).await == Err(Reason::Binding));
        ensure!(counts(&mut conn, &changed.tenant_id).await? == (0, 0, 0, 0));
    }
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&a.tenant_id)
        .execute(&mut conn)
        .await?;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(&a.tenant_id)
    .execute(&mut conn)
    .await?;
    migration::migrate_on(&mut conn, &a.installation).await?;
    // The CLI closes its migration connection; this fixture retains it for assertions.
    sqlx::query("SELECT pg_advisory_unlock(2346)")
        .execute(&mut conn)
        .await?;
    ensure!(create_on(&mut conn, &a).await? == a_receipt);
    ensure!(matches!(
        claim_use(&mut runtime, &a.installation, &a.tenant_id, 1).await,
        Err(Error::Configuration(ConfigIssue::IdentityConfiguration))
    ));
    claim_use(&mut runtime, &a.installation, &a.tenant_id, 2).await?;
    runtime.close().await?;
    conn.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: transactional rollback, deferred commit error and cross-connection replay"]
async fn failed_registration_rolls_back_and_receipts_replay_across_connections()
-> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = owner().await?;
    let request = input(Uuid::new_v4());
    sqlx::raw_sql("CREATE FUNCTION public.fail_registration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$; CREATE TRIGGER registration_failure BEFORE INSERT ON public.mdm_tenant_operations FOR EACH ROW EXECUTE FUNCTION public.fail_registration()").execute(&mut conn).await?;
    ensure!(create_on(&mut conn, &request).await == Err(Reason::Storage));
    ensure!(counts(&mut conn, &request.tenant_id).await? == (0, 0, 0, 0));
    sqlx::raw_sql("DROP TRIGGER registration_failure ON public.mdm_tenant_operations; CREATE CONSTRAINT TRIGGER registration_failure AFTER INSERT ON public.mdm_tenant_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fail_registration()").execute(&mut conn).await?;
    ensure!(create_on(&mut conn, &request).await == Err(Reason::CommitUnknown));
    conn.close().await?;
    let mut reopened = owner().await?;
    ensure!(
        receipt_on(&mut reopened, request.operation_id)
            .await?
            .is_none()
    );
    ensure!(counts(&mut reopened, &request.tenant_id).await? == (0, 0, 0, 0));
    sqlx::raw_sql("DROP TRIGGER registration_failure ON public.mdm_tenant_operations; DROP FUNCTION public.fail_registration()").execute(&mut reopened).await?;
    // The caller loses the success reply; a new connection recovers only from persisted evidence.
    let committed = create_on(&mut reopened, &request).await?;
    reopened.close().await?;
    let mut recovery = owner().await?;
    ensure!(
        receipt_on(&mut recovery, request.operation_id)
            .await?
            .unwrap()
            .0
            == committed
    );
    ensure!(create_on(&mut recovery, &request).await? == committed);
    recovery.close().await?;
    Ok(())
}
async fn wait_for_waiters(
    observer: &mut PgConnection,
    key: i64,
    minimum: i64,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objid=$1::oid AND NOT granted")
                .bind(key).fetch_one(&mut *observer).await?;
            if waiting >= minimum { break; }
            tokio::task::yield_now().await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}
async fn release_waiters(holder: &mut PgConnection) -> anyhow::Result<()> {
    wait_for_waiters(holder, 2346, 2).await?;
    sqlx::query("SELECT pg_advisory_unlock(2346)")
        .execute(holder)
        .await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: simultaneous registration processes share installation lock"]
async fn concurrent_registration_replays_once_and_respects_last_slot() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut holder = owner().await?;
    let mut one = owner().await?;
    let mut two = owner().await?;
    for conn in [&mut one, &mut two] {
        sqlx::query("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(conn)
            .await?;
    }
    let same = input(Uuid::new_v4());
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut holder)
        .await?;
    let (a, b, released) = tokio::join!(
        create_on(&mut one, &same),
        create_on(&mut two, &same),
        release_waiters(&mut holder)
    );
    released?;
    ensure!(a? == b?);
    ensure!(counts(&mut holder, &same.tenant_id).await? == (1, 1, 1, 1));
    // A compact cardinality fixture leaves exactly one free slot; it does not run 1024 hosts.
    let occupied: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mdm_tenants WHERE NOT deleted AND tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation)")
        .fetch_one(&mut holder).await?;
    ensure!(occupied < TENANT_LIMIT);
    sqlx::query("INSERT INTO public.mdm_tenants(tenant_id,initial_epoch) SELECT gen_random_uuid(),1 FROM generate_series(1,$1)")
        .bind(TENANT_LIMIT - occupied - 1).execute(&mut holder).await?;
    let left = input(Uuid::new_v4());
    let right = input(Uuid::new_v4());
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut holder)
        .await?;
    let (a, b, released) = tokio::join!(
        create_on(&mut one, &left),
        create_on(&mut two, &right),
        release_waiters(&mut holder)
    );
    released?;
    ensure!(matches!(
        (&a, &b),
        (Ok(_), Err(Reason::Capacity)) | (Err(Reason::Capacity), Ok(_))
    ));
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_tenants")
            .fetch_one(&mut holder)
            .await?
            == TENANT_LIMIT + 1
    );
    let rejected = if a.is_err() { &left } else { &right };
    ensure!(counts(&mut holder, &rejected.tenant_id).await? == (0, 0, 0, 0));
    let remove = Mutation {
        action: Action::Delete,
        initial_epoch: None,
        expected_revision: Some(1),
        operation_id: Uuid::new_v4(),
        ..same.mutation()
    };
    mutate_on(&mut holder, &remove).await?;
    create_on(&mut holder, rejected).await?;
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_tenants WHERE NOT deleted")
            .fetch_one(&mut holder)
            .await?
            == TENANT_LIMIT + 1
    );
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_tenants")
            .fetch_one(&mut holder)
            .await?
            == TENANT_LIMIT + 2
    );
    one.close().await?;
    two.close().await?;
    holder.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: receipt query waits for the preceding commit"]
async fn operation_query_waits_for_commit_with_repeatable_read_default() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut gate = owner().await?;
    sqlx::raw_sql("CREATE FUNCTION public.hold_registration_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2655); RETURN NEW; END $$; REVOKE ALL ON FUNCTION public.hold_registration_commit() FROM PUBLIC; CREATE CONSTRAINT TRIGGER registration_commit_gate AFTER INSERT ON public.mdm_tenant_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.hold_registration_commit()")
        .execute(&mut gate).await?;
    sqlx::query("SELECT pg_advisory_lock(2655)")
        .execute(&mut gate)
        .await?;
    let mut writer = owner().await?;
    let mut reader = owner().await?;
    let mut observer = owner().await?;
    sqlx::query("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut reader)
        .await?;
    let request = input(Uuid::new_v4());
    let (written, queried, released) = tokio::join!(
        create_on(&mut writer, &request),
        async {
            // The deferred trigger proves the writer holds the registration lock at commit.
            wait_for_waiters(&mut observer, 2655, 1).await?;
            Ok::<_, anyhow::Error>(
                query_on(&mut reader, &request.installation, request.operation_id).await?,
            )
        },
        async {
            // Release only once the actual query is blocked behind that writer.
            wait_for_waiters(&mut gate, 2346, 1).await?;
            sqlx::query("SELECT pg_advisory_unlock(2655)")
                .execute(&mut gate)
                .await?;
            Ok::<_, anyhow::Error>(())
        }
    );
    released?;
    ensure!(queried? == Some(written?));
    ensure!(
        sqlx::query_scalar::<_, String>("SHOW default_transaction_isolation")
            .fetch_one(&mut reader)
            .await?
            == "repeatable read"
    );
    writer.close().await?;
    reader.close().await?;
    observer.close().await?;
    gate.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: actual SQL profiles and tenant RLS"]
async fn runtime_profiles_read_only_the_selected_tenant_and_cannot_register() -> anyhow::Result<()>
{
    use anyhow::ensure;
    use std::str::FromStr;
    let mut conn = owner().await?;
    let a = input(Uuid::new_v4());
    let b = input(Uuid::new_v4());
    create_on(&mut conn, &a).await?;
    create_on(&mut conn, &b).await?;
    for (role, password) in [
        ("mdm_access", "access-fixture"),
        ("mdm_identity_runtime", "identity-runtime-fixture"),
        ("mdm_identity_maintenance", "identity-maintenance-fixture"),
    ] {
        let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
            .username(role)
            .password(password)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?);
        let mut runtime = PgConnection::connect_with(&options).await?;
        claim_use(&mut runtime, &a.installation, &a.tenant_id, 1).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(&a.tenant_id)
            .execute(&mut runtime)
            .await?;
        for (tenant, expected) in [
            (&a.tenant_id, vec![a.tenant_id.clone()]),
            (&b.tenant_id, vec![b.tenant_id.clone()]),
            (&String::new(), vec![]),
        ] {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
                .bind(tenant)
                .execute(&mut runtime)
                .await?;
            let visible: Vec<String> = sqlx::query_scalar(
                "SELECT tenant_id::text FROM public.mdm_tenants ORDER BY tenant_id",
            )
            .fetch_all(&mut runtime)
            .await?;
            ensure!(visible == expected);
        }
        ensure!(create_on(&mut runtime, &input(Uuid::new_v4())).await == Err(Reason::Forbidden));
        let denied = sqlx::query("DELETE FROM public.mdm_tenants")
            .execute(&mut runtime)
            .await
            .unwrap_err();
        ensure!(
            denied
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("42501")
        );
        let alive: Vec<String> = sqlx::query_scalar("SELECT tenant_id::text FROM public.mdm_tenants WHERE tenant_id=ANY($1::uuid[]) AND NOT deleted ORDER BY tenant_id")
            .bind(vec![Uuid::parse_str(&a.tenant_id)?, Uuid::parse_str(&b.tenant_id)?]).fetch_all(&mut conn).await?;
        let mut expected = vec![a.tenant_id.clone(), b.tenant_id.clone()];
        expected.sort();
        ensure!(alive == expected);
        runtime.close().await?;
    }
    conn.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=installation.registry: CRUD snapshots, revisions, tombstones and first use"]
async fn crud_replays_original_snapshots_and_never_reuses_deleted_ids() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = owner().await?;
    let a = input(Uuid::new_v4());
    let original = create_on(&mut conn, &a).await?;
    let mut edit = Mutation {
        action: Action::Update,
        initial_epoch: None,
        expected_revision: Some(1),
        name: Some("租户"),
        notes: Some("说明"),
        operation_id: Uuid::new_v4(),
        ..a.mutation()
    };
    edit.operation_id = original.operation_id;
    ensure!(
        mutate_on(&mut conn, &edit)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::Conflict)
    );
    edit.operation_id = Uuid::new_v4();
    let edited = mutate_on(&mut conn, &edit).await?;
    ensure!(edited.tenant().revision == 2 && edited.tenant().name.as_deref() == Some("租户"));
    ensure!(mutate_on(&mut conn, &edit).await? == edited);
    edit.operation_id = Uuid::new_v4();
    ensure!(
        mutate_on(&mut conn, &edit)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::Conflict)
    );
    edit.expected_revision = Some(2);
    let same_value = mutate_on(&mut conn, &edit).await?;
    ensure!(same_value.tenant().revision == 3);
    edit.expected_revision = Some(3);
    edit.operation_id = Uuid::new_v4();
    edit.name = None;
    edit.notes = None;
    let cleared = mutate_on(&mut conn, &edit).await?;
    ensure!(cleared.tenant().name.is_none() && cleared.tenant().notes.is_none());
    let removed = Mutation {
        action: Action::Delete,
        expected_revision: Some(4),
        operation_id: Uuid::new_v4(),
        ..edit
    };
    let deleted = mutate_on(&mut conn, &removed).await?;
    ensure!(deleted.tenant().revision == 5 && !deleted.tenant().deletable);
    ensure!(mutate_on(&mut conn, &removed).await? == deleted);
    let fresh_delete = Mutation {
        operation_id: Uuid::new_v4(),
        ..removed
    };
    ensure!(
        mutate_on(&mut conn, &fresh_delete)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::NotFound)
    );
    let fresh_update = Mutation {
        action: Action::Update,
        operation_id: Uuid::new_v4(),
        ..fresh_delete
    };
    ensure!(
        mutate_on(&mut conn, &fresh_update)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::NotFound)
    );
    let mut tx = operator_transaction(&mut conn, &a.installation).await?;
    ensure!(tenant_on(&mut tx, &a.tenant_id, false).await == Err(Reason::NotFound));
    tx.rollback().await?;
    ensure!(create_on(&mut conn, &a).await? == original);
    let mut reuse = input(Uuid::parse_str(&a.tenant_id)?);
    ensure!(create_on(&mut conn, &reuse).await == Err(Reason::Conflict));
    reuse.tenant_id = Uuid::new_v4().to_string();
    reuse.operation_id = original.operation_id;
    ensure!(create_on(&mut conn, &reuse).await == Err(Reason::Conflict));
    ensure!(query_on(&mut conn, &a.installation, removed.operation_id).await? == Some(deleted));
    ensure!(counts(&mut conn, &a.tenant_id).await? == (1, 1, 1, 5));
    let mut runtime = profile("mdm_access", "access-fixture").await?;
    ensure!(matches!(
        claim_use(&mut runtime, &a.installation, &a.tenant_id, 1).await,
        Err(Error::Configuration(ConfigIssue::IdentityConfiguration))
    ));
    let b = input(Uuid::new_v4());
    create_on(&mut conn, &b).await?;
    ensure!(matches!(
        claim_use(&mut runtime, &b.installation, &b.tenant_id, 2).await,
        Err(Error::Configuration(ConfigIssue::IdentityConfiguration))
    ));
    let mut tx = operator_transaction(&mut conn, &b.installation).await?;
    ensure!(tenant_on(&mut tx, &b.tenant_id, false).await?.deletable);
    tx.rollback().await?;
    claim_use(&mut runtime, &b.installation, &b.tenant_id, 1).await?;
    let delete_b = Mutation {
        action: Action::Delete,
        initial_epoch: None,
        expected_revision: Some(1),
        operation_id: Uuid::new_v4(),
        ..b.mutation()
    };
    ensure!(
        mutate_on(&mut conn, &delete_b)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::InUse)
    );
    let edit_b = Mutation {
        action: Action::Update,
        name: Some("still live"),
        ..delete_b
    };
    ensure!(mutate_on(&mut conn, &edit_b).await?.tenant().revision == 2);
    sqlx::query("UPDATE public.mdm_tenants SET revision=$2 WHERE tenant_id=$1::uuid")
        .bind(&b.tenant_id)
        .bind(i64::MAX)
        .execute(&mut conn)
        .await?;
    let overflow = Mutation {
        operation_id: Uuid::new_v4(),
        expected_revision: Some(i64::MAX),
        ..edit_b
    };
    ensure!(
        mutate_on(&mut conn, &overflow)
            .await
            .map_err(|error| error.reason)
            == Err(Reason::Conflict)
    );
    runtime.close().await?;
    conn.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: receipt failures roll back update and deletion"]
async fn receipt_failure_never_partially_changes_metadata_or_deletes() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = owner().await?;
    let a = input(Uuid::new_v4());
    let original = create_on(&mut conn, &a).await?;
    sqlx::raw_sql("CREATE FUNCTION public.fail_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; REVOKE ALL ON FUNCTION public.fail_operation() FROM PUBLIC; CREATE TRIGGER operation_failure BEFORE INSERT ON public.mdm_tenant_operations FOR EACH ROW EXECUTE FUNCTION public.fail_operation()").execute(&mut conn).await?;
    let mut retry = None;
    for action in [Action::Update, Action::Delete] {
        let change = Mutation {
            action,
            initial_epoch: None,
            expected_revision: Some(1),
            operation_id: Uuid::new_v4(),
            name: if action == Action::Update {
                Some("changed")
            } else {
                None
            },
            ..a.mutation()
        };
        ensure!(
            mutate_on(&mut conn, &change)
                .await
                .map_err(|error| error.reason)
                == Err(Reason::Storage)
        );
        ensure!(receipt_on(&mut conn, change.operation_id).await?.is_none());
        let mut tx = operator_transaction(&mut conn, &a.installation).await?;
        ensure!(tenant_on(&mut tx, &a.tenant_id, false).await? == *original.tenant());
        tx.rollback().await?;
        retry = Some(change);
    }
    sqlx::raw_sql("DROP TRIGGER operation_failure ON public.mdm_tenant_operations; DROP FUNCTION public.fail_operation()").execute(&mut conn).await?;
    let change = retry.unwrap();
    let recovered = mutate_on(&mut conn, &change).await?;
    ensure!(recovered.operation_id == change.operation_id && recovered.action == Action::Delete);
    conn.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: first-use claims and deletion serialize"]
async fn first_use_commit_blocks_a_concurrent_delete_without_bumping_revision() -> anyhow::Result<()>
{
    use anyhow::ensure;
    let mut observer = owner().await?;
    let a = input(Uuid::new_v4());
    create_on(&mut observer, &a).await?;
    let mut runtime = profile("mdm_identity_maintenance", "identity-maintenance-fixture").await?;
    let mut writer = owner().await?;
    let mut tx = runtime.begin().await?;
    let claimed: bool =
        sqlx::query_scalar("SELECT public.claim_tenant_use($1::uuid,1,$2::uuid,$3,$4,'plain')")
            .bind(&a.tenant_id)
            .bind(&a.installation.instance_id)
            .bind(&a.installation.target[..])
            .bind(&a.installation.lineage[..])
            .fetch_one(&mut *tx)
            .await?;
    ensure!(claimed);
    let delete = Mutation {
        action: Action::Delete,
        initial_epoch: None,
        expected_revision: Some(1),
        operation_id: Uuid::new_v4(),
        ..a.mutation()
    };
    let (deleted, committed) = tokio::join!(mutate_on(&mut writer, &delete), async {
        wait_for_waiters(&mut observer, 2346, 1).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    });
    committed?;
    ensure!(deleted.map_err(|error| error.reason) == Err(Reason::InUse));
    let mut tx = operator_transaction(&mut observer, &a.installation).await?;
    let tenant = tenant_on(&mut tx, &a.tenant_id, false).await?;
    ensure!(tenant.revision == 1 && !tenant.deletable);
    tx.rollback().await?;
    let b = input(Uuid::new_v4());
    create_on(&mut observer, &b).await?;
    let mut gate = owner().await?;
    sqlx::raw_sql("CREATE FUNCTION public.hold_delete_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2655); RETURN NEW; END $$; REVOKE ALL ON FUNCTION public.hold_delete_commit() FROM PUBLIC; CREATE CONSTRAINT TRIGGER delete_commit_gate AFTER INSERT ON public.mdm_tenant_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.hold_delete_commit()").execute(&mut gate).await?;
    sqlx::query("SELECT pg_advisory_lock(2655)")
        .execute(&mut gate)
        .await?;
    let remove = Mutation {
        action: Action::Delete,
        initial_epoch: None,
        expected_revision: Some(1),
        operation_id: Uuid::new_v4(),
        ..b.mutation()
    };
    let (deleted, claimed, released) = tokio::join!(
        mutate_on(&mut writer, &remove),
        async {
            wait_for_waiters(&mut observer, 2655, 1).await?;
            Ok::<_, anyhow::Error>(claim_use(&mut runtime, &b.installation, &b.tenant_id, 1).await)
        },
        async {
            wait_for_waiters(&mut gate, 2346, 1).await?;
            sqlx::query("SELECT pg_advisory_unlock(2655)")
                .execute(&mut gate)
                .await?;
            Ok::<_, anyhow::Error>(())
        }
    );
    released?;
    ensure!(deleted?.action == Action::Delete);
    ensure!(matches!(
        claimed?,
        Err(Error::Configuration(ConfigIssue::IdentityConfiguration))
    ));
    let state: (bool, bool) =
        sqlx::query_as("SELECT deleted,used FROM public.mdm_tenants WHERE tenant_id=$1::uuid")
            .bind(&b.tenant_id)
            .fetch_one(&mut observer)
            .await?;
    ensure!(state == (true, false));
    gate.close().await?;
    runtime.close().await?;
    writer.close().await?;
    observer.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.registry: capability admission rejects definition and ACL drift"]
async fn first_use_profile_rejects_public_execution_and_function_drift() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut owner = owner().await?;
    let mut runtime = profile("mdm_access", "access-fixture").await?;
    verify_read_profile(&mut runtime).await?;
    let original: String = sqlx::query_scalar("SELECT pg_get_functiondef('public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text)'::regprocedure)").fetch_one(&mut owner).await?;
    sqlx::query("GRANT EXECUTE ON FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) TO PUBLIC").execute(&mut owner).await?;
    ensure!(matches!(
        verify_read_profile(&mut runtime).await,
        Err(Error::Unavailable(Failure::AccessAdmission))
    ));
    sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) FROM PUBLIC; ALTER FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) SET search_path=public,pg_temp").execute(&mut owner).await?;
    ensure!(matches!(
        verify_read_profile(&mut runtime).await,
        Err(Error::Unavailable(Failure::AccessAdmission))
    ));
    sqlx::query("ALTER FUNCTION public.claim_tenant_use(uuid,bigint,uuid,bytea,bytea,text) SET search_path=pg_catalog,pg_temp").execute(&mut owner).await?;
    verify_read_profile(&mut runtime).await?;
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION public.claim_tenant_use(tenant uuid,expected_epoch bigint,instance uuid,expected_target bytea,expected_lineage bytea,expected_audit_mode text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN RETURN true; END $$").execute(&mut owner).await?;
    ensure!(matches!(
        verify_read_profile(&mut runtime).await,
        Err(Error::Unavailable(Failure::AccessAdmission))
    ));
    sqlx::raw_sql(sqlx::AssertSqlSafe(original))
        .execute(&mut owner)
        .await?;
    verify_read_profile(&mut runtime).await?;
    runtime.close().await?;
    owner.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=installation.registry: competing metadata edits use optimistic revisions"]
async fn concurrent_updates_with_one_revision_commit_only_once() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut holder = owner().await?;
    let a = input(Uuid::new_v4());
    create_on(&mut holder, &a).await?;
    let mut one = owner().await?;
    let mut two = owner().await?;
    let left = Mutation {
        action: Action::Update,
        initial_epoch: None,
        expected_revision: Some(1),
        operation_id: Uuid::new_v4(),
        name: Some("left"),
        ..a.mutation()
    };
    let right = Mutation {
        operation_id: Uuid::new_v4(),
        name: Some("right"),
        ..left
    };
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut holder)
        .await?;
    let (l, r, released) = tokio::join!(
        mutate_on(&mut one, &left),
        mutate_on(&mut two, &right),
        release_waiters(&mut holder)
    );
    released?;
    ensure!(matches!(
        (
            &l.as_ref().map_err(|error| error.reason),
            &r.as_ref().map_err(|error| error.reason)
        ),
        (Ok(_), Err(Reason::Conflict)) | (Err(Reason::Conflict), Ok(_))
    ));
    let mut tx = operator_transaction(&mut holder, &a.installation).await?;
    let (success, rejected) = if let Ok(receipt) = &l {
        (receipt, right.operation_id)
    } else {
        (r.as_ref().unwrap(), left.operation_id)
    };
    let final_tenant = tenant_on(&mut tx, &a.tenant_id, false).await?;
    ensure!(final_tenant.revision == 2 && final_tenant.name == success.tenant().name);
    tx.rollback().await?;
    ensure!(receipt_on(&mut holder, rejected).await?.is_none());
    ensure!(counts(&mut holder, &a.tenant_id).await? == (1, 1, 1, 2));
    one.close().await?;
    two.close().await?;
    holder.close().await?;
    Ok(())
}
