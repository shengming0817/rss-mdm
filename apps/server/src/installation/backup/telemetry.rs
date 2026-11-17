//! Quiesced telemetry databases and native ClickHouse archives join the installation manifest.
//! ref: Timescale logical-backup; ClickHouse BACKUP/RESTORE to a configured local disk.
use super::*;
use crate::installation::providers::telemetry::{Request as StorageRequest, clickhouse};
use crate::telemetry::Storage;
use std::collections::BTreeSet;
fn coordinate(database: &crate::config::Database) -> (String, u16, String) {
    (database.host.clone(), database.port, database.name.clone())
}
fn target(journal: &Journal, index: usize) -> Result<Journal> {
    Journal::open(&journal.path(&format!("telemetry-{index}"))?)
}
fn configured(runtime: &Value) -> Result<Vec<crate::telemetry::Config>> {
    serde_json::from_value(runtime["telemetry"].clone()).map_err(|_| Error::Corrupt)
}
pub(super) fn validate(frozen: &Frozen) -> Result<()> {
    if frozen.request.telemetry.len() > 64 {
        return Err(Error::Input);
    }
    let mut supplied = BTreeSet::new();
    let primary = administrator(&frozen.request.installation)?;
    for profile in &frozen.request.telemetry {
        profile.validate()?;
        let database = profile.configuration.database();
        if coordinate(database) == coordinate(&primary)
            || coordinate(database) != coordinate(&profile.administrator)
            || !supplied.insert(profile.configuration.resource_id)
        {
            return Err(Error::Input);
        }
        if let Some(ch) = &profile.clickhouse
            && (!ch.backup_directory.is_absolute() || ch.server_configuration_files.is_empty())
        {
            return Err(Error::Input);
        }
    }
    let mut required = BTreeSet::new();
    {
        for config in configured(&frozen.runtime)? {
            let key = config.resource_id;
            if !required.insert(key) {
                return Err(Error::Conflict);
            }
            let profile = frozen
                .request
                .telemetry
                .iter()
                .find(|p| p.configuration.resource_id == key)
                .ok_or(Error::Input)?;
            if config.configuration_binding().map_err(|_| Error::Corrupt)?
                != profile
                    .configuration
                    .configuration_binding()
                    .map_err(|_| Error::Input)?
                || config.database().user != profile.configuration.database().user
            {
                return Err(Error::Conflict);
            }
        }
    }
    if required != supplied {
        return Err(Error::Input);
    }
    Ok(())
}
fn ch_user(value: &str) -> Result<String> {
    crate::telemetry::identifier(value).map_err(|_| Error::Input)?;
    Ok(format!("`{value}`"))
}
async fn ch_fence(profile: &StorageRequest, enable: bool) -> Result<()> {
    let Storage::ClickHouse {
        writer,
        maintenance,
        ..
    } = &profile.configuration.backend
    else {
        return Ok(());
    };
    for table in ["raw", "summaries"] {
        let (verb, direction) = if enable {
            ("REVOKE", "FROM")
        } else {
            ("GRANT", "TO")
        };
        clickhouse::execute(
            profile,
            &format!("backup-{verb}-writer-{table}"),
            &format!(
                "{verb} INSERT ON rss_ts_ch.{table} {direction} {}",
                ch_user(&writer.user)?
            ),
        )
        .await?;
        clickhouse::execute(
            profile,
            &format!("backup-{verb}-maintenance-{table}"),
            &format!(
                "{verb} ALTER DELETE ON rss_ts_ch.{table} {direction} {}",
                ch_user(&maintenance.user)?
            ),
        )
        .await?;
    }
    if enable {
        let sql = format!(
            "SELECT count() FROM system.processes WHERE user IN ('{}','{}') FORMAT TabSeparated",
            writer.user, maintenance.user
        );
        if clickhouse::execute(profile, "backup-drain", &sql)
            .await?
            .trim()
            != "0"
        {
            return Err(Error::Busy);
        }
        if clickhouse::execute(profile,"backup-mutations","SELECT count() FROM system.mutations WHERE database='rss_ts_ch' AND NOT is_done FORMAT TabSeparated").await?.trim()!="0" {return Err(Error::Busy);}
    }
    Ok(())
}
pub(super) async fn fence(frozen: &Frozen, journal: &Journal) -> Result<()> {
    validate(frozen)?;
    for (index, profile) in frozen.request.telemetry.iter().enumerate() {
        let storage = target(journal, index)?;
        recovery_administrator(&profile.administrator).await?;
        let mut c = sqlx::PgConnection::connect_with(
            &profile.administrator.options().map_err(|_| Error::Input)?,
        )
        .await
        .map_err(|_| Error::Storage)?;
        if let Some(ch) = &profile.clickhouse {
            let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles r CROSS JOIN public.mdm_telemetry_installation i WHERE r.rolname=$1 AND NOT r.rolsuper AND NOT r.rolbypassrls AND shobj_description(r.oid,'pg_authid')='rss-mdm-telemetry:'||i.id::text)")
                .bind(&ch.guard.user).fetch_one(&mut c).await.map_err(|_| Error::Storage)?;
            if !owned {
                return Err(Error::Conflict);
            }
        }
        ch_fence(profile, true).await?;
        connection_fence(&mut c, &storage, true).await?;
        if let Some(ch) = &profile.clickhouse {
            // ClickHouse retains read-only PostgreSQL engine connections after its
            // writers stop. Fence reconnects first, then drain only this installation's
            // guard login; all other clients still fail the stopped-writer check.
            let drained: Vec<bool> = sqlx::query_scalar("SELECT pg_terminate_backend(pid,1000) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND pid<>pg_backend_pid() AND backend_type='client backend'")
                .bind(&ch.guard.user).fetch_all(&mut c).await.map_err(|_| Error::Storage)?;
            if drained.iter().any(|done| !done) {
                return Err(Error::Busy);
            }
        }
        no_writers(&mut c).await?;
        c.close().await.map_err(|_| Error::Storage)?;
    }
    Ok(())
}
pub(super) async fn capture(frozen: &Frozen, journal: &Journal) -> Result<()> {
    if !journal
        .load::<bool>("telemetry-preflight.json")?
        .unwrap_or(false)
    {
        admit(frozen, &administrator(&frozen.request.installation)?).await?;
        journal.save("telemetry-preflight.json", &true)?;
    }
    fence(frozen, journal).await?;
    for (index, profile) in frozen.request.telemetry.iter().enumerate() {
        let storage = target(journal, index)?;
        let mut c = sqlx::PgConnection::connect_with(
            &profile.administrator.options().map_err(|_| Error::Input)?,
        )
        .await
        .map_err(|_| Error::Storage)?;
        no_writers(&mut c).await?;
        let identity: (Uuid, Vec<u8>) =
            sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
                .fetch_one(&mut c)
                .await
                .map_err(|_| Error::Corrupt)?;
        use sha2::Digest;
        let expected = sha2::Sha256::digest(
            serde_json::to_vec(&serde_json::to_value(profile).map_err(|_| Error::Input)?)
                .map_err(|_| Error::Input)?,
        )
        .to_vec();
        if identity.1 != expected {
            return Err(Error::Conflict);
        }
        storage.save("installation.json", &identity)?;
        c.close().await.map_err(|_| Error::Storage)?;
        archive::capture(
            &storage,
            &profile.administrator.archive().map_err(|_| Error::Input)?,
        )
        .await?;
        snapshot_tree::capture(&storage, "provisioning", &profile.directory)?;
        if let Some(ch) = &profile.clickhouse {
            let id = Uuid::new_v5(
                &frozen.request.operation_id,
                format!("telemetry-{index}").as_bytes(),
            );
            let relative = format!("{id}/snapshot.zip");
            if !storage
                .load::<bool>("clickhouse-backup.json")?
                .unwrap_or(false)
            {
                let state = native_state(profile, id).await?;
                match state.as_str() {
                    "BACKUP_CREATED" => {}
                    "" => {
                        let statement = format!(
                            "BACKUP TABLE rss_ts_ch.installation,TABLE rss_ts_ch.raw,TABLE rss_ts_ch.summaries TO Disk('mdm_backup','{relative}') SETTINGS id='{id}'"
                        );
                        clickhouse::execute(profile, &format!("backup-{id}"), &statement).await?;
                        if native_state(profile, id).await? != "BACKUP_CREATED" {
                            return Err(Error::Storage);
                        }
                    }
                    "CREATING_BACKUP" => return Err(Error::Busy),
                    _ => return Err(Error::Storage),
                }
                storage.save("clickhouse-backup.json", &true)?;
            }
            snapshot_tree::capture(
                &storage,
                "clickhouse",
                &ch.backup_directory.join(id.to_string()),
            )?;
        }
    }
    Ok(())
}
async fn native_state(profile: &StorageRequest, id: Uuid) -> Result<String> {
    let live = clickhouse::execute(
        profile,
        &format!("native-status-{id}"),
        &format!("SELECT toString(status) FROM system.backups WHERE id='{id}' FORMAT TabSeparated"),
    )
    .await?;
    if !live.trim().is_empty() {
        return Ok(live.trim().to_owned());
    }
    // system.backups is process-local. A completed original operation can still be
    // established from the server's durable backup log after a restart. Never infer
    // success from table presence or generate another operation identity.
    // ref: ClickHouse v25.8.12.129-lts src/Interpreters/BackupLog.cpp.
    if clickhouse::execute(
        profile,
        "native-log-present",
        "EXISTS TABLE system.backup_log FORMAT TabSeparated",
    )
    .await?
    .trim()
        != "1"
    {
        return Ok(String::new());
    }
    let recorded = clickhouse::execute(profile, &format!("native-log-{id}"),
        &format!("SELECT toString(status) FROM system.backup_log WHERE id='{id}' ORDER BY event_time_microseconds DESC LIMIT 1 FORMAT TabSeparated")).await?;
    Ok(recorded.trim().to_owned())
}
pub(super) async fn release(frozen: &Frozen, journal: &Journal) -> Result<()> {
    let result = release_inner(frozen, journal).await;
    if result.is_err() {
        let _ = fence(frozen, journal).await;
    }
    result
}
async fn release_inner(frozen: &Frozen, journal: &Journal) -> Result<()> {
    for (index, profile) in frozen.request.telemetry.iter().enumerate() {
        let storage = target(journal, index)?;
        ch_fence(profile, false).await?;
        let mut c = sqlx::PgConnection::connect_with(
            &profile.administrator.options().map_err(|_| Error::Input)?,
        )
        .await
        .map_err(|_| Error::Storage)?;
        connection_fence(&mut c, &storage, false).await?;
        c.close().await.map_err(|_| Error::Storage)?;
    }
    Ok(())
}
pub(super) async fn restore(input: &Restore, frozen: &Frozen, journal: &Journal) -> Result<()> {
    validate(frozen)?;
    for (index, profile) in frozen.request.telemetry.iter().enumerate() {
        restore_profile(input, frozen, journal, index, profile).await?;
    }
    Ok(())
}
async fn restore_profile(
    input: &Restore,
    frozen: &Frozen,
    journal: &Journal,
    index: usize,
    profile: &StorageRequest,
) -> Result<()> {
    let storage = target(journal, index)?;
    recovery_administrator(&profile.administrator).await?;
    snapshot_tree::restore(&storage, "provisioning")?;
    let expected: (Uuid, Vec<u8>) = storage.load("installation.json")?.ok_or(Error::Corrupt)?;
    crate::installation::providers::telemetry::restore_roles(profile, expected.0).await?;
    let mut c = sqlx::PgConnection::connect_with(
        &profile.administrator.options().map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    no_writers(&mut c).await?;
    reserve_restore(&mut c, input.operation_id, &input.backup_manifest_sha256).await?;
    connection_fence(&mut c, &storage, true).await?;
    restore_postgres_data(&mut c, profile, &storage).await?;
    let expected: (Uuid, Vec<u8>) = storage.load("installation.json")?.ok_or(Error::Corrupt)?;
    let actual: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    if actual != expected {
        return Err(Error::Conflict);
    }
    let control_instance = if profile.clickhouse.is_some() {
        Some(
            sqlx::query_scalar::<_, String>("SELECT id::text FROM rss_ts_ch.installation")
                .fetch_one(&mut c)
                .await
                .map_err(|_| Error::Storage)?,
        )
    } else {
        None
    };
    c.close().await.map_err(|_| Error::Storage)?;
    if let Some(instance) = control_instance {
        restore_clickhouse(input, frozen, index, profile, &storage, &instance).await?;
    }
    Ok(())
}

async fn restore_postgres_data(
    c: &mut sqlx::PgConnection,
    profile: &StorageRequest,
    storage: &Journal,
) -> Result<()> {
    let restored: bool =
        sqlx::query_scalar("SELECT to_regclass('public.mdm_telemetry_installation') IS NOT NULL")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    let timescale = matches!(
        profile.configuration.backend,
        Storage::TimescaleShared { .. } | Storage::TimescaleDedicated { .. }
    );
    if !restored {
        if timescale {
            sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS timescaledb WITH VERSION '2.30.2'; SELECT public.timescaledb_pre_restore()").execute(&mut *c).await.map_err(|_|Error::Storage)?;
        }
        archive::restore_database(
            storage,
            &profile.administrator.archive().map_err(|_| Error::Input)?,
        )
        .await?;
    }
    if timescale {
        sqlx::query("SELECT public.timescaledb_post_restore()")
            .execute(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    }
    Ok(())
}

async fn restore_clickhouse(
    input: &Restore,
    frozen: &Frozen,
    index: usize,
    profile: &StorageRequest,
    storage: &Journal,
    instance: &str,
) -> Result<()> {
    snapshot_tree::restore(storage, "clickhouse")?;
    let backup = Uuid::new_v5(
        &frozen.request.operation_id,
        format!("telemetry-{index}").as_bytes(),
    );
    let restore = Uuid::new_v5(&input.operation_id, format!("telemetry-{index}").as_bytes());
    if storage
        .load::<Uuid>("clickhouse-restored.json")?
        .is_some_and(|id| id != restore)
    {
        return Err(Error::Conflict);
    }
    if storage.load::<Uuid>("clickhouse-restored.json")?.is_none() {
        match native_state(profile, restore).await?.as_str() {
            "RESTORED" => {}
            "RESTORING" => return Err(Error::Busy),
            "" => {
                if clickhouse::execute(profile,"restore-empty","SELECT count() FROM system.tables WHERE database='rss_ts_ch' FORMAT TabSeparated").await?.trim()!="0" {return Err(Error::Conflict);}
                clickhouse::execute(
                    profile,
                    "restore-database",
                    "CREATE DATABASE IF NOT EXISTS rss_ts_ch ENGINE=Atomic",
                )
                .await?;
                clickhouse::execute(profile,&format!("restore-{restore}"),&format!("RESTORE TABLE rss_ts_ch.installation,TABLE rss_ts_ch.raw,TABLE rss_ts_ch.summaries FROM Disk('mdm_backup','{backup}/snapshot.zip') SETTINGS id='{restore}'")).await?;
                if native_state(profile, restore).await? != "RESTORED" {
                    return Err(Error::Storage);
                }
            }
            _ => return Err(Error::Storage),
        }
        storage.save("clickhouse-restored.json", &restore)?;
    }
    if clickhouse::execute(
        profile,
        "restore-identity",
        "SELECT id FROM rss_ts_ch.installation FORMAT TabSeparated",
    )
    .await?
    .trim()
        != instance
    {
        return Err(Error::Conflict);
    }
    let statements =
        rss_timeseries_clickhouse::installation_sql(instance).map_err(|_| Error::Corrupt)?;
    for (index, sql) in statements
        .iter()
        .enumerate()
        .filter(|(_, sql)| sql.contains("ENGINE=PostgreSQL("))
    {
        clickhouse::execute(
            profile,
            &format!("restore-guard-{index}"),
            &sql.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1),
        )
        .await?;
    }
    clickhouse::provision_users(profile, false).await?;
    ch_fence(profile, true).await?;
    qualify_readers(
        frozen,
        &profile.configuration,
        &input.administrator,
        ReaderOperation::Restore(profile),
    )
    .await
}
enum ReaderOperation<'a> {
    Restore(&'a StorageRequest),
    Admit(&'a rss_timeseries_clickhouse::ChOwner<rss_mdm_telemetry_service::backend::SystemClock>),
}
fn deadline() -> Result<rss_request_context::Deadline> {
    rss_request_context::Deadline::from_timeout(
        &rss_mdm_telemetry_service::backend::SystemClock,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| Error::Storage)
}
async fn qualify_readers(
    frozen: &Frozen,
    physical: &crate::telemetry::Config,
    admin: &crate::config::Database,
    operation: ReaderOperation<'_>,
) -> Result<()> {
    let config: crate::config::Config =
        serde_json::from_value(frozen.runtime.clone()).map_err(|_| Error::Corrupt)?;
    let key = config.native_protector().map_err(|_| Error::Corrupt)?;
    let binding = physical
        .configuration_binding()
        .map_err(|_| Error::Corrupt)?;
    let mut c = sqlx::PgConnection::connect_with(&admin.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    for id in &frozen.tenants {
        let tenant =
            rss_request_context::TenantId::parse(&id.to_string()).map_err(|_| Error::Corrupt)?;
        let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
        let row = rss_mdm_telemetry_service::selection::load(&mut tx, tenant)
            .await
            .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(|_| Error::Storage)?;
        if let Some(row) = row.filter(|row| row.resource_id == Some(physical.resource_id)) {
            if row.binding != binding {
                return Err(Error::Conflict);
            }
            let reader = row
                .reader(&key, tenant)
                .map_err(|_| Error::Corrupt)?
                .ok_or(Error::Corrupt)?;
            match operation {
                ReaderOperation::Restore(profile) => {
                    clickhouse::provision_reader(profile, tenant, &reader, None).await?
                }
                ReaderOperation::Admit(owner) if reader.password.is_some() => {
                    reader
                        .bind(owner, tenant, row.revision, deadline()?)
                        .await
                        .map_err(|_| Error::Corrupt)?;
                }
                ReaderOperation::Admit(_) => {}
            }
        }
    }
    c.close().await.map_err(|_| Error::Storage)
}
pub(super) async fn admit(frozen: &Frozen, admin: &crate::config::Database) -> Result<()> {
    for config in configured(&frozen.runtime)? {
        let backend = config.open_backend().await.map_err(|_| Error::Corrupt)?;
        let qualified = match &backend {
            rss_mdm_telemetry_service::backend::Backend::ClickHouse(owner) => {
                qualify_readers(frozen, &config, admin, ReaderOperation::Admit(owner)).await
            }
            _ => Ok(()),
        };
        backend
            .close(deadline()?)
            .await
            .map_err(|_| Error::Storage)?;
        qualified?;
    }
    Ok(())
}
