//! The product's bounded installation executor; hosts compose capability-owned units.
//! ref: sqlx v0.9.0 sqlx-core/src/migrate/migrator.rs.
//! No application, business capability, Identity authority or channel is owned here.
pub mod access_admission;
pub mod catalog;
#[cfg(unix)]
pub mod files;
mod profile;
pub use profile::StorageProfile;
mod ledger;
pub use ledger::{accepted_ledger, resumable_ledger, transaction_body};

use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Postgres, Transaction, postgres::PgConnectOptions};
use std::{future::Future, pin::Pin, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, thiserror::Error)]
#[error("installation {unit}: {phase} (cleanup_failed={cleanup_failed})")]
pub struct Error {
    unit: &'static str,
    phase: &'static str,
    cleanup_failed: bool,
}
impl Error {
    pub const fn unit(&self) -> &'static str {
        self.unit
    }
    pub const fn phase(&self) -> &'static str {
        self.phase
    }
    pub const fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }
    pub const fn at(unit: &'static str, phase: &'static str) -> Self {
        Self {
            unit,
            phase,
            cleanup_failed: false,
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type Unit = (&'static str, &'static str);
pub type Receipt = (String, String, bool);

/// Host-selected coordinates, fixed before any schema or receipt can be written.
pub struct Binding {
    profile: StorageProfile,
    instance: Uuid,
    target: [u8; 16],
    lineage: [u8; 16],
    configuration: String,
}
impl Binding {
    pub fn new(
        profile: StorageProfile,
        instance: Uuid,
        target: [u8; 16],
        lineage: [u8; 16],
        configuration: String,
    ) -> Result<Self> {
        if instance.is_nil()
            || target == [0; 16]
            || lineage == [0; 16]
            || configuration.is_empty()
            || configuration.len() > 4096
        {
            return Err(Error::at(
                "installation",
                "invalid installation coordinates",
            ));
        }
        Ok(Self {
            profile,
            instance,
            target,
            lineage,
            configuration,
        })
    }
    pub const fn profile(&self) -> StorageProfile {
        self.profile
    }
    pub const fn instance(&self) -> Uuid {
        self.instance
    }
}

/// Host adaptations borrow the executor's actual transaction and never settle it.
/// The host alone decides Identity/Audit installation and enabled owner units.
pub trait Host: Sync {
    fn check_existing<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        receipts: &'a [Receipt],
    ) -> Pending<'a, ()>;
    fn apply<'a>(
        &'a self,
        transaction: &'a mut Transaction<'_, Postgres>,
        unit: Unit,
    ) -> Pending<'a, ()>;
    fn verify<'a>(&'a self, connection: &'a mut PgConnection) -> Pending<'a, ()>;
}

pub fn manifest(units: &[Unit]) -> serde_json::Value {
    serde_json::json!({"units":units.iter().map(|(name, sql)| serde_json::json!({"name":name,"sha256":format!("{:x}", Sha256::digest(sql))})).collect::<Vec<_>>()})
}

/// Own the connection, including its session lock, through bounded close on every exit.
pub async fn install(
    options: &PgConnectOptions,
    binding: &Binding,
    units: &[Unit],
    host: &impl Host,
) -> Result<()> {
    if units.is_empty()
        || units
            .iter()
            .map(|u| u.0)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != units.len()
    {
        return Err(Error::at(
            "installation",
            "empty or duplicate installation units",
        ));
    }
    let mut connection =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(options))
            .await
            .map_err(|_| Error::at("installation", "connection deadline"))?
            .map_err(|_| Error::at("installation", "connection unavailable"))?;
    let primary = tokio::time::timeout(
        Duration::from_secs(60),
        install_on(&mut connection, binding, units, host),
    )
    .await
    .map_err(|_| Error::at("installation", "deadline; result unknown"))
    .and_then(|r| r);
    let clean = matches!(
        tokio::time::timeout(Duration::from_secs(5), connection.close()).await,
        Ok(Ok(()))
    );
    match primary {
        Err(mut error) => {
            error.cleanup_failed |= !clean;
            Err(error)
        }
        Ok(()) if clean => Ok(()),
        Ok(()) => Err(Error::at("installation", "connection close failed")),
    }
}

pub async fn owner_admitted(
    connection: &mut PgConnection,
    profile: StorageProfile,
) -> Result<bool> {
    sqlx::query_scalar("SELECT current_user=$1 AND session_user=$1 AND has_database_privilege(current_user,current_database(),'CREATE') AND has_schema_privilege(current_user,'public','CREATE') AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))")
        .bind(profile.owner()).fetch_one(connection).await.map_err(|_| Error::at("installation", "owner probe unavailable"))
}

async fn install_on(
    connection: &mut PgConnection,
    binding: &Binding,
    units: &[Unit],
    host: &impl Host,
) -> Result<()> {
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='10s';")
        .execute(&mut *connection)
        .await
        .map_err(|_| Error::at("installation", "session setup"))?;
    if !owner_admitted(connection, binding.profile).await? {
        return Err(Error::at("installation", "owner admission rejected"));
    }
    // Both products coordinate installation of the same public components.
    sqlx::query("SELECT pg_advisory_lock(2346)")
        .execute(&mut *connection)
        .await
        .map_err(|_| Error::at("installation", "installation lock"))?;
    let sql = binding.profile.statements();
    execute_schema(
        connection,
        "installation",
        sql.initialize,
        "ledger initialization",
    )
    .await?;
    let receipts = read_receipts(connection, binding.profile)
        .await
        .map_err(|_| Error::at("installation", "ledger read"))?;
    if !resumable_ledger(&receipts, units) {
        return Err(Error::at(
            "installation",
            "existing ledger differs or is incomplete",
        ));
    }
    let exists: bool = sqlx::query_scalar(sql.progress_exists)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| Error::at("installation", "progress read"))?;
    if !receipts.is_empty() && !exists {
        return Err(Error::at(
            "installation",
            "unrecognized resumable installation source",
        ));
    }
    execute_schema(
        connection,
        "installation",
        sql.initialize_progress,
        "progress storage",
    )
    .await?;
    let digest = format!("{:x}", Sha256::digest(manifest(units).to_string()));
    sqlx::query(sql.reserve)
        .bind(binding.instance)
        .bind(binding.target.as_slice())
        .bind(binding.lineage.as_slice())
        .bind(&binding.configuration)
        .bind(&digest)
        .execute(&mut *connection)
        .await
        .map_err(|_| Error::at("installation", "progress reservation"))?;
    let matched: bool = sqlx::query_scalar(sql.matches)
        .bind(binding.instance)
        .bind(binding.target.as_slice())
        .bind(binding.lineage.as_slice())
        .bind(&binding.configuration)
        .bind(&digest)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| Error::at("installation", "progress read"))?;
    if !matched {
        return Err(Error::at(
            "installation",
            "installation binding or manifest differs",
        ));
    }
    host.check_existing(connection, &receipts).await?;
    for &unit in &units[receipts.len()..] {
        let (name, body) = unit;
        let mut tx = connection
            .begin()
            .await
            .map_err(|_| Error::at(name, "begin"))?;
        let applied = async {
            host.apply(&mut tx, unit).await?;
            sqlx::query(sql.record)
                .bind(name)
                .bind(format!("{:x}", Sha256::digest(body)))
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::at(name, "recording completion"))?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(mut error) = applied {
            error.cleanup_failed |= tx.rollback().await.is_err();
            return Err(error);
        }
        tx.commit()
            .await
            .map_err(|_| Error::at(name, "commit acknowledgement unknown"))?;
    }
    host.verify(connection).await
}

pub async fn read_receipts(
    connection: &mut PgConnection,
    profile: StorageProfile,
) -> std::result::Result<Vec<Receipt>, sqlx::Error> {
    sqlx::query_as(profile.statements().read)
        .fetch_all(connection)
        .await
}

/// Verify the immutable installation identity and configuration without modifying storage.
pub async fn verify_binding(
    connection: &mut PgConnection,
    binding: &Binding,
    units: &[Unit],
) -> std::result::Result<(), sqlx::Error> {
    let matched: bool = sqlx::query_scalar(binding.profile.statements().matches)
        .bind(binding.instance)
        .bind(binding.target.as_slice())
        .bind(binding.lineage.as_slice())
        .bind(&binding.configuration)
        .bind(format!("{:x}", Sha256::digest(manifest(units).to_string())))
        .fetch_one(connection)
        .await?;
    if matched {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol("installation binding differs".into()))
    }
}

pub async fn verify_manifest(
    connection: &mut PgConnection,
    profile: StorageProfile,
    units: &[Unit],
) -> std::result::Result<(), sqlx::Error> {
    let installed = read_receipts(connection, profile).await?;
    if installed.is_empty() || !accepted_ledger(&installed, units) {
        return Err(sqlx::Error::Protocol(
            "installation units do not match candidate".into(),
        ));
    }
    Ok(())
}

pub async fn execute_schema(
    connection: &mut PgConnection,
    unit: &'static str,
    sql: &'static str,
    phase: &'static str,
) -> Result<()> {
    for body in transaction_body(sql)? {
        sqlx::raw_sql(body)
            .execute(&mut *connection)
            .await
            .map_err(|_| Error::at(unit, phase))?;
    }
    Ok(())
}

#[cfg(unix)]
pub mod maintenance;
