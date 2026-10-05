use super::*;

fn input(tenant: Uuid) -> Register {
    Register {
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
    }
}
#[test]
fn registration_requires_canonical_tenant_positive_epoch_and_operation() {
    let mut request = input(Uuid::from_u128(0xab));
    assert!(validate(&request).is_ok());
    request.tenant_id = request.tenant_id.to_uppercase();
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.tenant_id = Uuid::nil().to_string();
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.tenant_id = Uuid::new_v4().to_string();
    request.initial_epoch = 0;
    assert_eq!(validate(&request), Err(Reason::Invalid));
    request.initial_epoch = 1;
    request.operation_id = Uuid::nil();
    assert_eq!(validate(&request), Err(Reason::Invalid));
}

async fn owner() -> anyhow::Result<PgConnection> {
    use std::str::FromStr;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    Ok(PgConnection::connect_with(&options).await?)
}
async fn installed() -> anyhow::Result<PgConnection> {
    let request = input(Uuid::new_v4());
    let mut conn = owner().await?;
    // This carrier starts with the module's empty, disposable database.
    migration::migrate_on(&mut conn, &request.installation).await?;
    sqlx::query("SELECT pg_advisory_unlock(2346)")
        .execute(&mut conn)
        .await?;
    Ok(conn)
}
async fn counts(conn: &mut PgConnection, tenant: &str) -> anyhow::Result<(i64, i64, i64, i64)> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(tenant)
        .execute(&mut *conn)
        .await?;
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM public.mdm_tenants WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_access.agent_enrollment_settings WHERE tenant_id=$1::uuid),(SELECT count(*) FROM public.mdm_tenant_registrations WHERE tenant_id=$1::uuid)")
        .bind(tenant).fetch_one(conn).await?)
}
#[tokio::test]
#[ignore = "MODULE=installation.migration: real atomic registration and epoch binding"]
async fn registration_replay_and_binding_preserve_existing_tenants() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = installed().await?;
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_tenants")
            .fetch_one(&mut conn)
            .await?
            == 0
    );
    let mut runtime = profile("mdm_access", "access-fixture").await?;
    let a = input(Uuid::new_v4());
    let b = input(Uuid::new_v4());
    let a_receipt = register_on(&mut conn, &a).await?;
    let b_receipt = register_on(&mut conn, &b).await?;
    ensure!(register_on(&mut conn, &b).await? == b_receipt);
    ensure!(counts(&mut conn, &a.tenant_id).await? == (1, 1, 1, 1));
    ensure!(counts(&mut conn, &b.tenant_id).await? == (1, 1, 1, 1));
    let settings =
        rss_mdm_registration_service::agent::settings::read_on(&mut conn, &b.tenant_id).await?;
    ensure!(
        settings.revision == 1
            && settings.values.grant_seconds
                == rss_mdm_registration_service::agent::settings::Values::default().grant_seconds
    );
    verify_binding(&mut runtime, &b.installation, &b.tenant_id, 1).await?;
    ensure!(
        verify_binding(&mut runtime, &b.installation, &b.tenant_id, 2)
            .await
            .is_err()
    );
    let mut collision = input(Uuid::parse_str(&b.tenant_id)?);
    ensure!(register_on(&mut conn, &collision).await == Err(Reason::Conflict));
    collision.operation_id = b.operation_id;
    collision.initial_epoch = 2;
    ensure!(register_on(&mut conn, &collision).await == Err(Reason::Conflict));
    for field in ["instance_id", "target", "lineage", "audit_mode"] {
        let mut changed = input(Uuid::new_v4());
        match field {
            "instance_id" => changed.installation.instance_id = Uuid::new_v4().to_string(),
            "target" => changed.installation.target = [3; 16],
            "lineage" => changed.installation.lineage = [4; 16],
            _ => changed.installation.audit_mode = migration::AuditMode::Ledger,
        }
        ensure!(register_on(&mut conn, &changed).await == Err(Reason::Binding));
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
    ensure!(register_on(&mut conn, &a).await? == a_receipt);
    ensure!(
        verify_binding(&mut runtime, &a.installation, &a.tenant_id, 1)
            .await
            .is_err()
    );
    verify_binding(&mut runtime, &a.installation, &a.tenant_id, 2).await?;
    runtime.close().await?;
    conn.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.migration: transactional rollback and uncertain commit recovery"]
async fn failed_registration_rolls_back_and_receipts_recover_uncertain_results()
-> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = installed().await?;
    let request = input(Uuid::new_v4());
    sqlx::raw_sql("CREATE FUNCTION public.fail_registration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$; CREATE TRIGGER registration_failure BEFORE INSERT ON public.mdm_tenant_registrations FOR EACH ROW EXECUTE FUNCTION public.fail_registration()").execute(&mut conn).await?;
    ensure!(register_on(&mut conn, &request).await == Err(Reason::Storage));
    ensure!(counts(&mut conn, &request.tenant_id).await? == (0, 0, 0, 0));
    sqlx::raw_sql("DROP TRIGGER registration_failure ON public.mdm_tenant_registrations; CREATE CONSTRAINT TRIGGER registration_failure AFTER INSERT ON public.mdm_tenant_registrations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fail_registration()").execute(&mut conn).await?;
    ensure!(register_on(&mut conn, &request).await == Err(Reason::CommitUnknown));
    conn.close().await?;
    let mut reopened = owner().await?;
    ensure!(
        receipt_on(&mut reopened, request.operation_id)
            .await?
            .is_none()
    );
    ensure!(counts(&mut reopened, &request.tenant_id).await? == (0, 0, 0, 0));
    sqlx::raw_sql("DROP TRIGGER registration_failure ON public.mdm_tenant_registrations; DROP FUNCTION public.fail_registration()").execute(&mut reopened).await?;
    // The caller loses the success reply; a new connection recovers only from persisted evidence.
    let committed = register_on(&mut reopened, &request).await?;
    reopened.close().await?;
    let mut recovery = owner().await?;
    ensure!(
        receipt_on(&mut recovery, request.operation_id)
            .await?
            .unwrap()
            .0
            == committed
    );
    ensure!(register_on(&mut recovery, &request).await? == committed);
    recovery.close().await?;
    Ok(())
}
async fn release_waiters(holder: &mut PgConnection) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objid=2346 AND NOT granted").fetch_one(&mut *holder).await?;
            if waiting >= 2 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    sqlx::query("SELECT pg_advisory_unlock(2346)")
        .execute(holder)
        .await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.migration: simultaneous registration processes share installation lock"]
async fn concurrent_registration_replays_once_and_respects_last_slot() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut holder = installed().await?;
    let mut one = owner().await?;
    let mut two = owner().await?;
    let same = input(Uuid::new_v4());
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut holder)
        .await?;
    let (a, b, released) = tokio::join!(
        register_on(&mut one, &same),
        register_on(&mut two, &same),
        release_waiters(&mut holder)
    );
    released?;
    ensure!(a? == b?);
    ensure!(counts(&mut holder, &same.tenant_id).await? == (1, 1, 1, 1));
    // A compact cardinality fixture leaves exactly one free slot; it does not run 1024 hosts.
    sqlx::raw_sql(
        "INSERT INTO public.mdm_tenants SELECT md5(n::text)::uuid,1 FROM generate_series(1,1022) n",
    )
    .execute(&mut holder)
    .await?;
    let left = input(Uuid::new_v4());
    let right = input(Uuid::new_v4());
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut holder)
        .await?;
    let (a, b, released) = tokio::join!(
        register_on(&mut one, &left),
        register_on(&mut two, &right),
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
            == TENANT_LIMIT
    );
    let rejected = if a.is_err() { &left } else { &right };
    ensure!(counts(&mut holder, &rejected.tenant_id).await? == (0, 0, 0, 0));
    one.close().await?;
    two.close().await?;
    holder.close().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.migration: actual SQL profiles and tenant RLS"]
async fn runtime_profiles_read_only_the_selected_tenant_and_cannot_register() -> anyhow::Result<()>
{
    use anyhow::ensure;
    use std::str::FromStr;
    let mut conn = installed().await?;
    let a = input(Uuid::new_v4());
    let b = input(Uuid::new_v4());
    register_on(&mut conn, &a).await?;
    register_on(&mut conn, &b).await?;
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
        verify_binding(&mut runtime, &a.installation, &a.tenant_id, 1).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(&a.tenant_id)
            .execute(&mut runtime)
            .await?;
        ensure!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_tenants")
                .fetch_one(&mut runtime)
                .await?
                == 1
        );
        ensure!(register_on(&mut runtime, &input(Uuid::new_v4())).await == Err(Reason::Forbidden));
        ensure!(
            sqlx::query("DELETE FROM public.mdm_tenants")
                .execute(&mut runtime)
                .await
                .is_err()
        );
        runtime.close().await?;
    }
    conn.close().await?;
    Ok(())
}

async fn profile(role: &str, password: &str) -> anyhow::Result<PgConnection> {
    use std::str::FromStr;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .username(role)
        .password(password)
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    Ok(PgConnection::connect_with(&options).await?)
}
