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
    let mut owner = PgConnection::connect_with(&options).await?;
    migrate_on(&mut owner).await?;
    let before: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(before.len() == units().len() && before.iter().all(|r| r.2));
    migrate_on(&mut owner).await?;
    owner.execute("CREATE TABLE public.installation_evidence(value text); INSERT INTO public.installation_evidence VALUES('preserve')").await?;
    for statement in [
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='transactional-messaging-v1'",
        "UPDATE public.mdm_migrations SET complete=false WHERE name='transactional-messaging-v1'",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner).await.is_err());
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
    ensure!(migrate_on(&mut owner).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 + 1
    );
    owner.close().await?;
    Ok(())
}
