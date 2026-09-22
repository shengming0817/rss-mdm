use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

#[tokio::test]
#[ignore = "make t2: fresh installation and rejected ledger in a disposable database"]
async fn fresh_installation_replay_and_mismatch_rejection() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .database("mdm_installation")
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        instance_id: crate::identity_fixture::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec!["11111111-1111-4111-8111-111111111111".into()],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    let candidate = units();
    migrate_units(&mut owner, &installation, &candidate[..candidate.len() - 1]).await?;
    // A real previous ledger is installed; tenant RLS must not hide active work from upgrade.
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    owner.execute("INSERT INTO rss_device_command.authorities VALUES('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',1,1); INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint) VALUES('11111111-1111-4111-8111-111111111111','upgrade-evidence','22222222-2222-4222-8222-222222222222',1,1,decode(repeat('00',32),'hex'),1000,1,'mdm.commands.v1','upgrade-evidence',decode(repeat('00',32),'hex'))").await?;
    owner
        .execute("SELECT set_config('rss.tenant_id','',false)")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM public.mdm_migrations WHERE name='windows-configuration-v1')").fetch_one(&mut owner).await?);
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    owner.execute("UPDATE rss_device_command.commands SET status='cancelled',terminal_at=2 WHERE command_id='upgrade-evidence'").await?;
    owner.execute(include_str!("legacy-fixture.sql")).await?;
    let historical: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM mdm_commands.attempts a")
            .fetch_one(&mut owner)
            .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM public.mdm_migrations WHERE name='windows-configuration-v1')").fetch_one(&mut owner).await?);
    owner.execute("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE domain='mdm.commands.v1'").await?;
    // Terminal commands and settled Outbox still cannot allow old live response replay.
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM public.mdm_migrations WHERE name='windows-configuration-v1')").fetch_one(&mut owner).await?);
    owner.execute("UPDATE mdm_access.management_sessions SET expires_at=clock_timestamp()-interval '1 second'").await?;

    owner
        .execute("SELECT set_config('rss.tenant_id','',false)")
        .await?;
    migrate_on(&mut owner, &installation).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM rss_device_command.commands WHERE command_id='upgrade-evidence'"
        )
        .fetch_one(&mut owner)
        .await?
            == "cancelled"
    );

    ensure!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT to_jsonb(a) FROM mdm_commands.attempt_history a"
        )
        .fetch_one(&mut owner)
        .await?
            == historical
    );
    let converted:(String,String,String)=sqlx::query_as("SELECT request->'task'->>'kind',request->'task'->>'expectedValue',approval->>'permission' FROM mdm_commands.operations WHERE id='33333333-3333-4333-8333-333333333333'").fetch_one(&mut owner).await?;
    ensure!(
        converted
            == (
                "state_verify".into(),
                "Historical Model".into(),
                "state_verify".into()
            )
    );
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mdm_commands.attempts")
            .fetch_one(&mut owner)
            .await?
            == 0
    );
    let before: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(before.len() == units().len() && before.iter().all(|r| r.2));
    migrate_on(&mut owner, &installation).await?;
    for field in ["instance_id", "target", "tenants"] {
        let mut changed = installation.configuration();
        changed[field] = match field {
            "instance_id" => serde_json::json!("55555555-5555-4555-8555-555555555555"),
            "target" => serde_json::json!(vec![3; 16]),
            _ => serde_json::json!(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
        };
        let changed: Installation = serde_json::from_value(changed)?;
        ensure!(migrate_on(&mut owner, &changed).await.is_err());
    }
    for (grant, revoke) in [
        (
            "GRANT DELETE ON identity_authority.accounts TO mdm_identity_runtime",
            "REVOKE DELETE ON identity_authority.accounts FROM mdm_identity_runtime",
        ),
        (
            "GRANT SELECT ON identity_authority.sessions TO mdm_identity_maintenance",
            "REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_maintenance",
        ),
    ] {
        sqlx::raw_sql(grant).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        sqlx::raw_sql(revoke).execute(&mut owner).await?;
    }
    migrate_on(&mut owner, &installation).await?;
    owner.execute("CREATE TABLE public.installation_evidence(value text); INSERT INTO public.installation_evidence VALUES('preserve')").await?;
    for statement in [
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='transactional-messaging-v1'",
        "UPDATE public.mdm_migrations SET complete=false WHERE name='transactional-messaging-v1'",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        ensure!(
            sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
                .fetch_one(&mut owner)
                .await?
                == "preserve"
        );
        // Only this disposable test repairs its injected damage; the installer never does.
        let original = before
            .iter()
            .find(|r| r.0 == "transactional-messaging-v1")
            .unwrap();
        sqlx::query("UPDATE public.mdm_migrations SET digest=$1,complete=true WHERE name=$2")
            .bind(&original.1)
            .bind(&original.0)
            .execute(&mut owner)
            .await?;
    }
    // An otherwise complete pre-assets ledger must not regain prefix-upgrade support.
    owner.execute("DELETE FROM public.mdm_migrations WHERE name IN ('inventory-v2','assets-management-v1')").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 - 2
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
            .fetch_one(&mut owner)
            .await?
            == "preserve"
    );
    for (name, digest, complete) in &before {
        if name == "inventory-v2" || name == "assets-management-v1" {
            sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,$3)")
                .bind(name)
                .bind(digest)
                .bind(complete)
                .execute(&mut owner)
                .await?;
        }
    }
    owner.execute("INSERT INTO public.mdm_migrations VALUES('unrecognized-installation',repeat('a',64),true)").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 + 1
    );
    owner.close().await?;
    Ok(())
}
