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
    // This is the exact a83f7876 39-unit baseline, not an arbitrary prefix.
    migrate_units(&mut owner, &installation, &candidate[..39]).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    owner.execute(include_str!("agent-v1-fixture.sql")).await?;
    owner
        .execute("SELECT set_config('rss.tenant_id','',false)")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM public.mdm_migrations WHERE name='agent-v2')"
        )
        .fetch_one(&mut owner)
        .await?
    );
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    owner
        .execute("UPDATE mdm_access.registrations SET state='revoked' WHERE channel='agent'")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    owner
        .execute("UPDATE mdm_access.credentials SET state='revoked' WHERE channel='agent'")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    owner
        .execute("UPDATE mdm_access.collection_runs SET delivery_pending=false")
        .await?;
    // No inferred conversion of incomplete legacy Script declarations.
    owner.execute("INSERT INTO mdm_resource.immutable VALUES(current_setting('rss.tenant_id')::uuid,'old-script','version','v1',convert_to('[1,0,0,0,1]','UTF8'),decode(repeat('00',32),'hex'))").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    owner
        .execute("DELETE FROM mdm_resource.immutable WHERE owner='old-script'")
        .await?;
    let historical: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM mdm_access.collection_runs r")
            .fetch_one(&mut owner)
            .await?;
    owner
        .execute("SELECT set_config('rss.tenant_id','',false)")
        .await?;
    migrate_on(&mut owner, &installation).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT to_jsonb(r) FROM mdm_access.collection_runs r"
        )
        .fetch_one(&mut owner)
        .await?
            == historical
    );
    ensure!(
        sqlx::query_scalar::<_, i16>("SELECT wire_version FROM mdm_access.agent_bindings")
            .fetch_one(&mut owner)
            .await?
            == 1
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT state FROM mdm_access.credentials")
            .fetch_one(&mut owner)
            .await?
            == "revoked"
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

#[test]
fn task_upgrade_accepts_only_the_exact_named_baseline_or_complete_current_ledger() {
    let current = units();
    let ledger = |items: &[(&str, &str)]| {
        items
            .iter()
            .map(|(name, sql)| (name.to_string(), format!("{:x}", Sha256::digest(sql)), true))
            .collect::<Vec<_>>()
    };
    assert!(accepted_ledger(&[], &current));
    assert!(accepted_ledger(&ledger(&current), &current));
    assert!(!accepted_ledger(&ledger(&current[..38]), &current));
    let baseline: serde_json::Value =
        serde_json::from_str(include_str!("baseline-a83f7876.json")).unwrap();
    let baseline = baseline["units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|unit| {
            (
                unit["name"].as_str().unwrap().to_owned(),
                unit["sha256"].as_str().unwrap().to_owned(),
                true,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(baseline.len(), 39);
    assert!(accepted_ledger(&baseline, &current));
    let mut altered = baseline.clone();
    altered[0].1 = "0".repeat(64);
    assert!(!accepted_ledger(&altered, &current));
    let mut duplicate = baseline;
    duplicate[0] = duplicate[1].clone();
    assert!(!accepted_ledger(&duplicate, &current));
}
