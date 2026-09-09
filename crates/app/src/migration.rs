//! Product owns ordered installation; component SQL remains with its owner.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row, postgres::PgConnectOptions};
use std::time::Duration;
const BUDGET: Duration = Duration::from_secs(30);
fn finish<T>(primary: Result<T>, cleanup: [(&str, Result<()>); 1]) -> Result<T> {
    let mut failure = None;
    for (_, result) in cleanup {
        if let Err(error) = result {
            failure = Some(error);
        }
    }
    match (primary, failure) {
        (Ok(value), None) => Ok(value),
        (Err(error), _) => Err(error),
        (_, Some(error)) => Err(error),
    }
}
pub async fn migrate(options: &PgConnectOptions) -> Result<()> {
    let mut conn = tokio::time::timeout(BUDGET, PgConnection::connect_with(options)).await??;
    let result = migrate_on(&mut conn).await;
    let closed = tokio::time::timeout(BUDGET, conn.close()).await;
    finish(
        result,
        [(
            "migration_close",
            match closed {
                Ok(result) => result.map_err(Into::into),
                Err(error) => Err(error.into()),
            },
        )],
    )
}
async fn migrate_on(conn: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='30s'; SELECT pg_advisory_lock(2346); CREATE TABLE IF NOT EXISTS public.mdm_migrations(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false);").execute(&mut *conn).await?;
    for (name, sql) in [
        ("observation-v2", rss_observation_postgres::MIGRATION_SQL),
        ("projection-v3", rss_projection_postgres::MIGRATION_SQL),
        ("inventory-v1", rss_mdm_inventory_postgres::MIGRATION_SQL),
        (
            "inventory-api-reader-v1",
            rss_mdm_inventory_postgres::READER_MIGRATION_SQL,
        ),
    ] {
        let digest = format!("{:x}", Sha256::digest(sql));
        let old = sqlx::query("SELECT digest,complete FROM public.mdm_migrations WHERE name=$1")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
        if let Some(row) = old {
            ensure!(
                row.try_get::<String, _>("digest")? == digest
                    && row.try_get::<bool, _>("complete")?,
                "migration {name} changed or interrupted; restore/recreate the dedicated database before retry"
            );
            continue;
        }
        // Component scripts own transaction statements. Persist intent before invoking them;
        // an interrupted installation cannot be silently adopted on the next invocation.
        sqlx::query("INSERT INTO public.mdm_migrations(name,digest) VALUES($1,$2)")
            .bind(name)
            .bind(digest)
            .execute(&mut *conn)
            .await?;
        sqlx::raw_sql(sql).execute(&mut *conn).await?;
        sqlx::query("UPDATE public.mdm_migrations SET complete=true WHERE name=$1")
            .bind(name)
            .execute(&mut *conn)
            .await?;
    }
    Ok(()) // session advisory lock released by explicit connection close
}
