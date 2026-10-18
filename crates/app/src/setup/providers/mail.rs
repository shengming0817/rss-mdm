//! 固定 SMTP 资格执行器；地址及 TLS 名字只来自受保护部署输入。
use crate::setup::{Error, Result, installation::Input, local::Journal};
use rss_mdm_mail_service::{store, transport};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection};
use std::{net::SocketAddr, path::PathBuf};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub hostname: String,
    pub address: SocketAddr,
    pub tls: transport::Tls,
    pub ca_file: PathBuf,
}
async fn scope(c: &mut PgConnection, tenant: Uuid) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
pub async fn reconcile(input: &Input, c: &mut PgConnection) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    if input.mail_profiles.iter().any(|p| !ids.insert(&p.id)) {
        return Err(Error::Input);
    }
    let hosts:Vec<(Uuid,String)>=sqlx::query_as("SELECT tenant_id,receipt->'result'->>'hostId' FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'phase'='enabled' ORDER BY operation_id").fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
    for (tenant, host) in hosts {
        let host = Uuid::parse_str(&host).map_err(|_| Error::Corrupt)?;
        let journal = Journal::open(&input.directory.join(format!("rss-mdm-{}", host.simple())))?;
        let runtime: crate::config::Config = journal
            .load("requested-runtime.json")?
            .ok_or(Error::Corrupt)?;
        let key = runtime.native_protector().map_err(|_| Error::Corrupt)?;
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        scope(&mut tx, tenant).await?;
        // 前一执行器退出时 DATA 可能已被接受；不能自动重投原 Message-ID。
        sqlx::query("UPDATE mdm_mail.versions SET state='unknown',failure_reason='submission_unknown' WHERE tenant_id=$1 AND state='submitting'").bind(tenant).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
        let pending:Option<(Uuid,String)>=sqlx::query_as("SELECT v.operation_id,v.profile FROM mdm_mail.versions v JOIN mdm_mail.heads h USING(tenant_id,revision) WHERE v.tenant_id=$1 AND state IN('pending','failed') AND (attempted_at IS NULL OR attempted_at<extract(epoch FROM clock_timestamp())-60)").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
        let Some((operation, id)) = pending else {
            tx.commit().await.map_err(|_| Error::Storage)?;
            continue;
        };
        let Some(profile) = input.mail_profiles.iter().find(|p| p.id == id) else {
            sqlx::query("UPDATE mdm_mail.versions SET state='failed',failure_reason='profile_unavailable',attempted_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(operation).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
            continue;
        };
        let endpoint = transport::Endpoint {
            hostname: profile.hostname.clone(),
            address: profile.address,
            tls: profile.tls.clone(),
            ca_pem: crate::config::read(&profile.ca_file, 1024 * 1024, false)
                .map_err(|_| Error::Input)?
                .to_vec(),
        };
        let material = store::pending(&mut tx, &tenant.to_string(), operation, &key, &endpoint)
            .await
            .map_err(|_| Error::Conflict)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
        let result = transport::test(
            &endpoint,
            &material.credentials,
            &material.sender,
            &material.recipient,
            operation,
            now,
            || async {
                let mut tx = c
                    .begin()
                    .await
                    .map_err(|_| rss_mdm_mail_service::Error::Storage)?;
                scope(&mut tx, tenant)
                    .await
                    .map_err(|_| rss_mdm_mail_service::Error::Storage)?;
                store::submitting(&mut tx, &tenant.to_string(), operation).await?;
                tx.commit()
                    .await
                    .map_err(|_| rss_mdm_mail_service::Error::Unknown)
            },
        )
        .await;
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        scope(&mut tx, tenant).await?;
        store::finish(
            &mut tx,
            &tenant.to_string(),
            operation,
            match result {
                Ok(()) => store::Outcome::Accepted,
                Err(rss_mdm_mail_service::Error::Rejected) => store::Outcome::Rejected,
                Err(_) => store::Outcome::Unavailable,
            },
        )
        .await
        .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/setup/mail.rs"]
mod tests;
