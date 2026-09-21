use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

#[test]
fn completed_prefix_can_upgrade_but_holes_and_damage_cannot() {
    let current = [
        ("one", "SELECT 1"),
        ("two", "SELECT 2"),
        ("three", "SELECT 3"),
    ];
    let row = |i: usize| {
        (
            current[i].0.to_owned(),
            format!("{:x}", Sha256::digest(current[i].1)),
            true,
        )
    };
    assert!(validate_history(&[], &current).is_ok());
    assert!(validate_history(&[row(0), row(1)], &current).is_ok());
    assert!(validate_history(&[row(1), row(0)], &current).is_ok());
    assert!(validate_history(&[row(0), row(2)], &current).is_err());
    assert!(validate_history(&[("foreign".into(), row(0).1, true)], &current).is_err());
    let mut damaged = row(0);
    damaged.2 = false;
    assert!(validate_history(&[damaged], &current).is_err());
    let mut damaged = row(0);
    damaged.1 = "wrong".into();
    assert!(validate_history(&[damaged], &current).is_err());
}

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
    migrate_units(&mut owner, &installation, &units()[..24]).await?;
    let baseline: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mdm_migrations WHERE complete")
            .fetch_one(&mut owner)
            .await?;
    ensure!(baseline == 24);
    sqlx::raw_sql("BEGIN; SET LOCAL rss.tenant_id='11111111-1111-4111-8111-111111111111'; INSERT INTO mdm_access.devices VALUES('11111111-1111-4111-8111-111111111111','upgrade-preserved'); COMMIT;").execute(&mut owner).await?;
    let mut wrong = Installation {
        instance_id: "55555555-5555-4555-8555-555555555555".into(),
        ..Installation {
            instance_id: installation.instance_id.clone(),
            target: installation.target,
            lineage: installation.lineage,
            epoch: installation.epoch,
            tenants: installation.tenants.clone(),
        }
    };
    ensure!(migrate_on(&mut owner, &wrong).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, bool>("SELECT to_regnamespace('mdm_commands') IS NULL")
            .fetch_one(&mut owner)
            .await?
    );
    wrong.instance_id = installation.instance_id.clone();
    migrate_on(&mut owner, &installation).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&installation.tenants[0])
        .execute(&mut owner)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mdm_access.devices WHERE id='upgrade-preserved'"
        )
        .fetch_one(&mut owner)
        .await?
            == 1
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
