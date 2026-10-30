//! Explicit current-format storage installation; runtime never performs DDL or repairs.
//! ref: RSS c0de5fc crates/timeseries-postgres/src/profile.rs; PostgreSQL 17 CREATE ROLE.
use crate::setup::{Error, Result, local::Journal};
use crate::{
    config::Database,
    telemetry::{Config, Credential, Storage},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row};
use std::path::PathBuf;
use uuid::Uuid;
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Partition {
    pub start_micros: i64,
    pub end_micros: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClickHouse {
    /// Host-mounted root of the fixed ClickHouse mdm_backup disk.
    #[serde(rename = "backup_directory")]
    pub backup_directory: PathBuf,
    /// Original mounted server configuration, named collection and libpq trust materials.
    #[serde(rename = "server_configuration_files")]
    pub server_configuration_files: Vec<PathBuf>,
    pub installer: Credential,
    /// Must match the externally installed rss_ts_ch_guard named collection.
    pub guard: Credential,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub operation_id: Uuid,
    pub directory: PathBuf,
    pub tenant: String,
    pub configuration: Config,
    /// Already created empty database, accessed only by the deployment operator.
    pub administrator: Database,
    pub owner: String,
    pub partitions: Vec<Partition>,
    pub clickhouse: Option<ClickHouse>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub installation_id: Uuid,
    pub admitted: bool,
}
fn identifier(value: &str) -> Result<String> {
    crate::telemetry::identifier(value).map_err(|_| Error::Input)
}
async fn sql(c: &mut PgConnection, text: &str) -> Result<()> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(text))
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
fn same_database(a: &Database, b: &Database) -> bool {
    a.host == b.host && a.port == b.port && a.name == b.name
}
impl Request {
    pub(in crate::setup) fn validate(&self) -> Result<rss_request_context::TenantId> {
        let tenant =
            rss_request_context::TenantId::parse(&self.tenant).map_err(|_| Error::Input)?;
        self.configuration
            .validate(tenant)
            .map_err(|_| Error::Input)?;
        identifier(&self.owner)?;
        identifier(&self.configuration.database().user)?;
        if self.operation_id.is_nil()
            || !same_database(&self.administrator, self.configuration.database())
            || self.owner == self.configuration.database().user
            || self.partitions.len() > 32
        {
            return Err(Error::Input);
        }
        if matches!(self.configuration.backend, Storage::ClickHouse { .. })
            != self.clickhouse.is_some()
        {
            return Err(Error::Input);
        }
        if matches!(self.configuration.backend, Storage::Postgres { .. }) {
            if self.partitions.is_empty() {
                return Err(Error::Input);
            }
            for p in &self.partitions {
                if p.start_micros < 0 || p.end_micros <= p.start_micros {
                    return Err(Error::Input);
                }
            }
        } else if !self.partitions.is_empty() {
            return Err(Error::Input);
        }
        if let Storage::TimescaleDedicated {
            maintenance_owner,
            maintenance,
            ..
        } = &self.configuration.backend
        {
            if maintenance_owner != &self.owner || maintenance.user == self.owner {
                return Err(Error::Input);
            }
            identifier(&maintenance.user)?;
        }
        if let Some(ch) = &self.clickhouse {
            identifier(&ch.guard.user)?;
        }
        if let Some(ch) = &self.clickhouse
            && (ch.guard.user != "ch_guard"
                || !ch.backup_directory.is_absolute()
                || ch.server_configuration_files.is_empty()
                || ch.server_configuration_files.len() > 16
                || ch.guard.user == self.owner
                || ch.guard.user == self.configuration.database().user)
        {
            return Err(Error::Input);
        }
        Ok(tenant)
    }
}
/// Install once, recover the original transaction identity, then admit the actual runtime roles.
pub async fn prepare(input: Request) -> Result<Receipt> {
    tokio::time::timeout(std::time::Duration::from_secs(180), prepare_inner(input))
        .await
        .map_err(|_| Error::Storage)?
}
async fn prepare_inner(input: Request) -> Result<Receipt> {
    let tenant = input.validate()?;
    let journal = Journal::open(&input.directory)?;
    let frozen = serde_json::to_value(&input).map_err(|_| Error::Input)?;
    if let Some(old) = journal.load::<serde_json::Value>("request.json")? {
        if old != frozen {
            return Err(Error::Conflict);
        }
    } else {
        journal.save("request.json", &frozen)?;
    }
    let binding = Sha256::digest(serde_json::to_vec(&frozen).map_err(|_| Error::Input)?).to_vec();
    let identity = match journal.load::<Uuid>("identity.json")? {
        Some(id) => id,
        None => {
            let id = Uuid::new_v4();
            journal.save("identity.json", &id)?;
            id
        }
    };
    if input.clickhouse.is_some() {
        clickhouse::check_version(&input).await?;
    }
    install_postgres(&input, identity, &binding).await?;
    if input.clickhouse.is_some() {
        clickhouse::install(&input, &journal).await?;
    }
    let store = input
        .configuration
        .open_backend(tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let deadline = rss_request_context::Deadline::from_timeout(
        &rss_mdm_telemetry_service::backend::SystemClock,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| Error::Storage)?;
    store.close(deadline).await.map_err(|_| Error::Storage)?;
    let receipt = Receipt {
        operation_id: input.operation_id,
        installation_id: identity,
        admitted: true,
    };
    journal.save("receipt.json", &receipt)?;
    Ok(receipt)
}
async fn role(c: &mut PgConnection, name: &str, password: Option<&str>, tag: &str) -> Result<()> {
    let quoted = identifier(name)?;
    let old=sqlx::query("SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,shobj_description(oid,'pg_authid') AS marker FROM pg_roles WHERE rolname=$1")
        .bind(name).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
    if let Some(old) = old {
        if old
            .try_get::<bool, _>("rolcanlogin")
            .map_err(|_| Error::Storage)?
            != password.is_some()
            || [
                "rolsuper",
                "rolbypassrls",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
            ]
            .iter()
            .any(|key| old.try_get::<bool, _>(*key).unwrap_or(true))
            || old
                .try_get::<Option<String>, _>("marker")
                .map_err(|_| Error::Storage)?
                .as_deref()
                != Some(tag)
        {
            return Err(Error::Conflict);
        }
    } else {
        sql(
        c,
        &format!(
            "CREATE ROLE {quoted} {} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION",
            if password.is_some() {
                "LOGIN"
            } else {
                "NOLOGIN"
            }
        ),
    )
    .await?;
    }
    sqlx::query("SELECT set_config('mdm.telemetry.role',$1,true),set_config('mdm.telemetry.marker',$2,true),set_config('mdm.telemetry.password',$3,true)")
        .bind(name).bind(tag).bind(password.unwrap_or("")).execute(&mut *c).await.map_err(|_|Error::Storage)?;
    sql(c,"DO $$ BEGIN EXECUTE format('COMMENT ON ROLE %I IS %L',current_setting('mdm.telemetry.role'),current_setting('mdm.telemetry.marker')); IF current_setting('mdm.telemetry.password')<>'' THEN EXECUTE format('ALTER ROLE %I PASSWORD %L',current_setting('mdm.telemetry.role'),current_setting('mdm.telemetry.password')); END IF; END $$").await
}
async fn install_postgres(input: &Request, identity: Uuid, binding: &[u8]) -> Result<()> {
    let mut c =
        PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sql(&mut tx,"SET LOCAL statement_timeout='60s';SET LOCAL lock_timeout='6s'; SELECT pg_advisory_xact_lock(2815,1)").await?;
    admit_postgres_server(&mut tx, input).await?;
    if !installation_replayed(&mut tx, identity, binding).await? {
        install_new_postgres(&mut tx, input, identity, binding).await?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)
}

async fn install_new_postgres(
    c: &mut PgConnection,
    input: &Request,
    identity: Uuid,
    binding: &[u8],
) -> Result<()> {
    // A fresh installation may use an empty database (including provider extensions),
    // but must never adopt unrelated user data. Replay was checked before this point.
    let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN('r','p','v','m','S','f') AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_namespace'::regclass AND d.objid=n.oid AND d.deptype='e') AND NOT (n.nspname='public' AND c.relname='mdm_telemetry_installation') AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e'))")
        .fetch_one(&mut *c).await.map_err(|_| Error::Storage)?;
    if occupied {
        return Err(Error::Conflict);
    }
    install_roles(&mut *c, input, identity).await?;
    let runtime = input.configuration.database();
    sql(
        &mut *c,
        &format!(
            "GRANT CREATE ON DATABASE {} TO {}; SET LOCAL ROLE {}",
            identifier(&runtime.name)?,
            identifier(&input.owner)?,
            identifier(&input.owner)?
        ),
    )
    .await?;
    install_objects(&mut *c, input).await?;
    grant_runtime(&mut *c, input).await?;
    sql(&mut *c, "RESET ROLE").await?;
    sql(
        &mut *c,
        &format!(
            "GRANT SELECT(id) ON public.mdm_telemetry_installation TO {}",
            identifier(&input.configuration.database().user)?
        ),
    )
    .await?;
    sqlx::query("INSERT INTO public.mdm_telemetry_installation VALUES($1,$2)")
        .bind(identity)
        .bind(binding)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}

async fn installation_replayed(
    c: &mut PgConnection,
    identity: Uuid,
    binding: &[u8],
) -> Result<bool> {
    sql(&mut *c,"CREATE TABLE IF NOT EXISTS public.mdm_telemetry_installation(id uuid PRIMARY KEY,binding bytea NOT NULL CHECK(octet_length(binding)=32)); REVOKE ALL ON public.mdm_telemetry_installation FROM PUBLIC").await?;
    let previous: Vec<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if previous.is_empty() {
        return Ok(false);
    }
    if previous != vec![(identity, binding.to_vec())] {
        return Err(Error::Conflict);
    }
    Ok(true)
}

async fn admit_postgres_server(c: &mut PgConnection, input: &Request) -> Result<()> {
    let version: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::int/10000")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    let admin: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if version != 17 || !admin {
        return Err(Error::Input);
    }
    if matches!(
        input.configuration.backend,
        Storage::TimescaleShared { .. } | Storage::TimescaleDedicated { .. }
    ) {
        let version: Option<String> =
            sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname='timescaledb'")
                .fetch_optional(&mut *c)
                .await
                .map_err(|_| Error::Storage)?;
        if version.as_deref() != Some("2.30.2") {
            return Err(Error::Input);
        }
    }
    Ok(())
}

async fn install_roles(c: &mut PgConnection, input: &Request, identity: Uuid) -> Result<()> {
    let tag = format!("rss-mdm-telemetry:{identity}");
    role(&mut *c, &input.owner, None, &tag).await?;
    let runtime = input.configuration.database();
    let password = crate::config::secret(&runtime.password_file).map_err(|_| Error::Input)?;
    role(&mut *c, &runtime.user, Some(&password), &tag).await?;
    if let Storage::TimescaleDedicated { maintenance, .. } = &input.configuration.backend {
        let password =
            crate::config::secret(&maintenance.password_file).map_err(|_| Error::Input)?;
        role(&mut *c, &maintenance.user, Some(&password), &tag).await?;
        sql(
            &mut *c,
            &format!(
                "GRANT {} TO {} WITH INHERIT FALSE, SET TRUE",
                identifier(&input.owner)?,
                identifier(&maintenance.user)?
            ),
        )
        .await?;
    }
    if let Some(ch) = &input.clickhouse {
        let password = crate::config::secret(&ch.guard.password_file).map_err(|_| Error::Input)?;
        role(&mut *c, &ch.guard.user, Some(&password), &tag).await?;
    }
    Ok(())
}
async fn install_objects(c: &mut PgConnection, input: &Request) -> Result<()> {
    let source = match input
        .configuration
        .profile(rss_request_context::TenantId::parse(&input.tenant).map_err(|_| Error::Input)?)
        .map_err(|_| Error::Input)?
    {
        Some(profile) => profile.installation_sql().map_err(|_| Error::Input)?,
        None => rss_timeseries_clickhouse::CONTROL_SQL.to_owned(),
    };
    for body in crate::migration::transaction_body(&source).map_err(|_| Error::Input)? {
        if !body.trim().is_empty() {
            sql(&mut *c, body).await?;
        }
    }
    for partition in &input.partitions {
        sqlx::query("SELECT rss_timeseries.create_partition($1,$2)")
            .bind(partition.start_micros)
            .bind(partition.end_micros)
            .execute(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    }
    Ok(())
}
async fn grant_runtime(c: &mut PgConnection, input: &Request) -> Result<()> {
    let runtime = identifier(&input.configuration.database().user)?;
    if let Some(ch) = &input.clickhouse {
        let guard = identifier(&ch.guard.user)?;
        sql(&mut *c,&format!("GRANT USAGE ON SCHEMA rss_ts_ch TO {runtime},{guard}; GRANT SELECT ON rss_ts_ch.installation TO {runtime}; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_ts_ch.namespaces,rss_ts_ch.definitions,rss_ts_ch.streams,rss_ts_ch.batches,rss_ts_ch.identities,rss_ts_ch.attempts,rss_ts_ch.fences,rss_ts_ch.plans,rss_ts_ch.summaries,rss_ts_ch.ranges TO {runtime}; GRANT SELECT ON rss_ts_ch.active_attempts,rss_ts_ch.guard_identity TO {guard}")).await?;
    } else {
        sql(&mut *c,&format!("GRANT USAGE ON SCHEMA rss_timeseries TO {runtime}; GRANT SELECT ON ALL TABLES IN SCHEMA rss_timeseries TO {runtime}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_timeseries TO {runtime}")).await?;
        let privileged = if matches!(input.configuration.backend, Storage::Postgres { .. }) {
            "create_partition(bigint,bigint)"
        } else {
            "integer_now()"
        };
        sql(
            &mut *c,
            &format!("REVOKE EXECUTE ON FUNCTION rss_timeseries.{privileged} FROM {runtime}"),
        )
        .await?;
        if matches!(
            input.configuration.backend,
            Storage::TimescaleDedicated { .. }
        ) {
            sql(
                &mut *c,
                &format!(
                    "REVOKE EXECUTE ON FUNCTION rss_timeseries.project_gauge() FROM {runtime}"
                ),
            )
            .await?;
        }
    }
    Ok(())
}
pub(in crate::setup) mod clickhouse;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhysicalAction {
    PreparePartitions {
        partitions: Vec<Partition>,
    },
    ConvertChunks {
        start_micros: i64,
        end_micros: i64,
        max_chunks: std::num::NonZeroU32,
        columnstore: bool,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhysicalRequest {
    pub installation: Request,
    pub operation_id: Uuid,
    pub action: PhysicalAction,
}
/// Physical changes require the original journal; chunk conversion additionally requires stopped writers.
pub async fn maintain(input: PhysicalRequest) -> Result<serde_json::Value> {
    tokio::time::timeout(std::time::Duration::from_secs(180), maintain_inner(input))
        .await
        .map_err(|_| Error::Storage)?
}
async fn maintain_inner(input: PhysicalRequest) -> Result<serde_json::Value> {
    let tenant = input.installation.validate()?;
    if input.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let journal = Journal::open(&input.installation.directory)?;
    let original: serde_json::Value = journal.load("request.json")?.ok_or(Error::Corrupt)?;
    if original != serde_json::to_value(&input.installation).map_err(|_| Error::Input)? {
        return Err(Error::Conflict);
    }
    let installation: Receipt = journal.load("receipt.json")?.ok_or(Error::Corrupt)?;
    if !installation.admitted {
        return Err(Error::Conflict);
    }
    let name = format!("physical-{}.json", input.operation_id);
    let request = serde_json::to_value(&input).map_err(|_| Error::Input)?;
    if let Some(old) = journal.load::<serde_json::Value>(&name)? {
        if old != request {
            return Err(Error::Conflict);
        }
    } else {
        journal.save(&name, &request)?;
    }
    let mut connection = PgConnection::connect_with(
        &input
            .installation
            .administrator
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let actual: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
            .fetch_one(&mut connection)
            .await
            .map_err(|_| Error::Storage)?;
    let expected =
        Sha256::digest(serde_json::to_vec(&original).map_err(|_| Error::Input)?).to_vec();
    if actual != (installation.installation_id, expected) {
        return Err(Error::Conflict);
    }
    if matches!(input.action, PhysicalAction::ConvertChunks { .. }) {
        let writers:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'").fetch_one(&mut connection).await.map_err(|_|Error::Storage)?;
        if writers != 0 {
            return Err(Error::Busy);
        }
    }
    let result = match &input.action {
        PhysicalAction::PreparePartitions { partitions } => {
            prepare_partitions(&mut connection, &input, partitions).await?
        }
        PhysicalAction::ConvertChunks {
            start_micros,
            end_micros,
            max_chunks,
            columnstore,
        } => {
            convert_chunks(
                &input,
                tenant,
                *start_micros,
                *end_micros,
                *max_chunks,
                *columnstore,
            )
            .await?
        }
    };
    connection.close().await.map_err(|_| Error::Storage)?;
    journal.save(
        &format!("physical-{}-result.json", input.operation_id),
        &result,
    )?;
    Ok(result)
}

async fn prepare_partitions(
    connection: &mut PgConnection,
    input: &PhysicalRequest,
    partitions: &[Partition],
) -> Result<serde_json::Value> {
    if !matches!(
        input.installation.configuration.backend,
        Storage::Postgres { .. }
    ) || partitions.is_empty()
        || partitions.len() > 32
        || partitions
            .iter()
            .any(|p| p.start_micros < 0 || p.end_micros <= p.start_micros)
    {
        return Err(Error::Input);
    }
    let mut tx = connection.begin().await.map_err(|_| Error::Storage)?;
    sql(&mut tx,"SET LOCAL statement_timeout='30s';SET LOCAL lock_timeout='6s';SELECT pg_advisory_xact_lock(2815,1);CREATE TABLE IF NOT EXISTS public.mdm_telemetry_partition_operations(id uuid PRIMARY KEY,binding bytea NOT NULL CHECK(octet_length(binding)=32));REVOKE ALL ON public.mdm_telemetry_partition_operations FROM PUBLIC").await?;
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT binding FROM public.mdm_telemetry_partition_operations WHERE id=$1",
    )
    .bind(input.operation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Storage)?;
    let binding = Sha256::digest(serde_json::to_vec(&input).map_err(|_| Error::Input)?).to_vec();
    if let Some(stored) = stored {
        if stored != binding {
            return Err(Error::Conflict);
        }
    } else {
        sql(
            &mut tx,
            &format!("SET LOCAL ROLE {}", identifier(&input.installation.owner)?),
        )
        .await?;
        for p in partitions {
            let name = format!("samples_{}_{}", p.start_micros, p.end_micros);
            let bound:Option<String>=sqlx::query_scalar("SELECT pg_get_expr(c.relpartbound,c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_inherits i ON i.inhrelid=c.oid WHERE n.nspname='rss_timeseries' AND c.relname=$1 AND i.inhparent='rss_timeseries.samples'::regclass").bind(&name).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
            if let Some(bound) = bound {
                if bound
                    != format!(
                        "FOR VALUES FROM ('{}') TO ('{}')",
                        p.start_micros, p.end_micros
                    )
                {
                    return Err(Error::Conflict);
                }
                continue;
            }
            sqlx::query("SELECT rss_timeseries.create_partition($1,$2)")
                .bind(p.start_micros)
                .bind(p.end_micros)
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
        }
        sql(
            &mut tx,
            &format!(
                "GRANT SELECT ON ALL TABLES IN SCHEMA rss_timeseries TO {}; RESET ROLE",
                identifier(&input.installation.configuration.database().user)?
            ),
        )
        .await?;
        sqlx::query("INSERT INTO public.mdm_telemetry_partition_operations VALUES($1,$2)")
            .bind(input.operation_id)
            .bind(binding)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    Ok(
        serde_json::json!({"operationId":input.operation_id,"state":"complete","partitions":partitions.len()}),
    )
}

async fn convert_chunks(
    input: &PhysicalRequest,
    tenant: rss_request_context::TenantId,
    start_micros: i64,
    end_micros: i64,
    max_chunks: std::num::NonZeroU32,
    columnstore: bool,
) -> Result<serde_json::Value> {
    if !matches!(
        input.installation.configuration.backend,
        Storage::TimescaleDedicated { .. }
    ) || max_chunks.get() > 32
    {
        return Err(Error::Input);
    }
    let window = rss_timeseries::Interval::new(
        rss_timeseries::Timestamp::new(start_micros).map_err(|_| Error::Input)?,
        rss_timeseries::Timestamp::new(end_micros).map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let backend = input
        .installation
        .configuration
        .open_backend(tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let deadline = rss_request_context::Deadline::from_timeout(
        &rss_mdm_telemetry_service::backend::SystemClock,
        std::time::Duration::from_secs(30),
    )
    .map_err(|_| Error::Storage)?;
    let result = match &backend {
        rss_mdm_telemetry_service::backend::Backend::Postgres(store) => {
            store
                .convert_raw_chunks(
                    window,
                    max_chunks,
                    if columnstore {
                        rss_timeseries_postgres::timescale::StorageFormat::Columnstore
                    } else {
                        rss_timeseries_postgres::timescale::StorageFormat::Rowstore
                    },
                    deadline,
                )
                .await
        }
        _ => return Err(Error::Input),
    };
    let close = rss_request_context::Deadline::from_timeout(
        &rss_mdm_telemetry_service::backend::SystemClock,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| Error::Storage)?;
    backend.close(close).await.map_err(|_| Error::Storage)?;
    Ok(match result.map_err(|_| Error::Storage)? {
        rss_timeseries::Outcome::Accepted(count) | rss_timeseries::Outcome::Replay(count) => {
            serde_json::json!({"operationId":input.operation_id,"state":if count==max_chunks.get(){"more"}else{"complete"},"converted":count})
        }
        rss_timeseries::Outcome::Unknown => {
            serde_json::json!({"operationId":input.operation_id,"state":"unknown"})
        }
    })
}

/// Recreate only this installation's original restricted roles from authenticated backup material.
pub(in crate::setup) async fn restore_roles(input: &Request, identity: Uuid) -> Result<()> {
    input.validate()?;
    let mut c =
        PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    install_roles(&mut tx, input, identity).await?;
    let database = input.configuration.database();
    sql(
        &mut tx,
        &format!(
            "GRANT CREATE ON DATABASE {} TO {}",
            identifier(&database.name)?,
            identifier(&input.owner)?
        ),
    )
    .await?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)
}

/// Add one tenant-scoped ClickHouse reader to an existing admitted installation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRequest {
    pub installation: Request,
    pub operation_id: Uuid,
    pub tenant: String,
    pub reader: Credential,
    pub cursor_key_file: PathBuf,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantReceipt {
    pub operation_id: Uuid,
    pub tenant: String,
    pub configuration: Config,
}
pub async fn prepare_tenant(input: TenantRequest) -> Result<TenantReceipt> {
    tokio::time::timeout(
        std::time::Duration::from_secs(180),
        prepare_tenant_inner(input),
    )
    .await
    .map_err(|_| Error::Storage)?
}
async fn prepare_tenant_inner(input: TenantRequest) -> Result<TenantReceipt> {
    input.installation.validate()?;
    let tenant = rss_request_context::TenantId::parse(&input.tenant).map_err(|_| Error::Input)?;
    if input.operation_id.is_nil() || input.tenant == input.installation.tenant {
        return Err(Error::Input);
    }
    identifier(&input.reader.user)?;
    let original = Journal::open(&input.installation.directory)?;
    let frozen: serde_json::Value = original.load("request.json")?.ok_or(Error::Corrupt)?;
    if frozen != serde_json::to_value(&input.installation).map_err(|_| Error::Input)? {
        return Err(Error::Conflict);
    }
    let installation: Receipt = original.load("receipt.json")?.ok_or(Error::Corrupt)?;
    if !installation.admitted {
        return Err(Error::Conflict);
    }
    let mut c = PgConnection::connect_with(
        &input
            .installation
            .administrator
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let actual: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT id,binding FROM public.mdm_telemetry_installation")
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)?;
    if actual
        != (
            installation.installation_id,
            Sha256::digest(serde_json::to_vec(&frozen).map_err(|_| Error::Input)?).to_vec(),
        )
    {
        return Err(Error::Conflict);
    }
    let mut target = input.installation.clone();
    let Storage::ClickHouse {
        reader,
        writer,
        maintenance,
        ..
    } = &mut target.configuration.backend
    else {
        return Err(Error::Input);
    };
    if input.reader.user == reader.user
        || input.reader.user == writer.user
        || input.reader.user == maintenance.user
    {
        return Err(Error::Input);
    }
    *reader = input.reader.clone();
    target.tenant = input.tenant.clone();
    target.operation_id = input.operation_id;
    target.configuration.cursor_key_file = input.cursor_key_file.clone();
    target
        .configuration
        .validate(tenant)
        .map_err(|_| Error::Input)?;
    let journal = Journal::open(
        &input
            .installation
            .directory
            .join(format!("tenant-{}", input.operation_id)),
    )?;
    let request = serde_json::to_value(&input).map_err(|_| Error::Input)?;
    if let Some(previous) = journal.load::<serde_json::Value>("request.json")? {
        if previous != request {
            return Err(Error::Conflict);
        }
    } else {
        let exists = clickhouse::execute(
            &target,
            "reserve-reader",
            &format!(
                "SELECT count() FROM system.users WHERE name='{}' FORMAT TabSeparated",
                input.reader.user
            ),
        )
        .await?;
        if exists.trim() != "0" {
            return Err(Error::Conflict);
        }
        journal.save("request.json", &request)?;
    }
    clickhouse::provision_users(&target).await?;
    let backend = target
        .configuration
        .open_backend(tenant)
        .await
        .map_err(|_| Error::Storage)?;
    let deadline = rss_request_context::Deadline::from_timeout(
        &rss_mdm_telemetry_service::backend::SystemClock,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| Error::Storage)?;
    backend.close(deadline).await.map_err(|_| Error::Storage)?;
    let receipt = TenantReceipt {
        operation_id: input.operation_id,
        tenant: input.tenant,
        configuration: target.configuration,
    };
    journal.save("receipt.json", &receipt)?;
    Ok(receipt)
}
