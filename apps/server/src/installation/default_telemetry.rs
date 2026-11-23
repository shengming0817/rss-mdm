//! Standard-install PostgreSQL profile; all SQL installation remains in the provider owner.
use super::{
    Error, Result,
    install::Input,
    local::Journal,
    providers::telemetry::{self, Partition, Request},
};
use sqlx::Connection;
use uuid::Uuid;

pub(super) const CONNECTIONS: u32 = 4;

pub(super) async fn prepare(
    input: &Input,
    journal: &Journal,
    instance: Uuid,
) -> Result<crate::telemetry::Config> {
    let request = if let Some(request) = journal.load::<Request>("telemetry-request.json")? {
        request
    } else {
        let database_name = format!("mdm_telemetry_{}", instance.simple());
        let password = secret(journal, "telemetry-password", false)?;
        let cursor = secret(journal, "telemetry-cursor.key", true)?;
        let mut database = input.database.administrator.clone();
        database.name = database_name.clone();
        database.user = format!("mdm_ts_{}", instance.simple());
        database.password_file = password;
        let configuration:crate::telemetry::Config=serde_json::from_value(serde_json::json!({
            "resource_id":Uuid::new_v4(),"backend":{"kind":"postgres","database":database},"cursor_key_file":cursor,"connections":CONNECTIONS,
            "maintenance":{"authorization_bytes":65536,"rows":4096,"buckets":64,"step_seconds":6},
            "ingress":{"requestBytes":1048576,"pendingBatches":64,"batchesPerMinute":6000,"bytesPerMinute":67108864},
            "limits":{"max_points":4096,"max_series":4096,"max_bytes":1048576,"replay_micros":86400000000u64,"cursor_micros":900000000u64}
        })).map_err(|_|Error::Input)?;
        let mut administrator = input.database.administrator.clone();
        administrator.name = database_name;
        let request = Request {
            operation_id: crate::administration::baseline::manifest::id(
                instance,
                "telemetry-install",
            ),
            directory: input.directory.join("telemetry"),
            configuration,
            administrator,
            owner: format!("mdm_ts_owner_{}", instance.simple()),
            partitions: partitions(now()?)?,
            clickhouse: None,
        };
        journal.save("telemetry-request.json", &request)?;
        request
    };
    let mut c = sqlx::PgConnection::connect_with(
        &input
            .database
            .administrator
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&request.administrator.name)
            .fetch_one(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
    if !exists {
        let name =
            crate::telemetry::identifier(&request.administrator.name).map_err(|_| Error::Input)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {name} TEMPLATE template0"
        )))
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    telemetry::prepare(request.clone()).await?;
    Ok(request.configuration)
}
fn secret(journal: &Journal, name: &str, binary: bool) -> Result<std::path::PathBuf> {
    let path = journal.path(name)?;
    if path.exists() {
        crate::config::read(&path, 128, true).map_err(|_| Error::Corrupt)?;
        return Ok(path);
    }
    let bytes = if binary {
        [
            Uuid::new_v4().as_bytes().as_slice(),
            Uuid::new_v4().as_bytes().as_slice(),
        ]
        .concat()
    } else {
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()).into_bytes()
    };
    journal.secret(name, &bytes)
}
fn now() -> Result<i64> {
    crate::clock::Clock::unix_seconds(&crate::clock::SystemClock).map_err(|_| Error::Storage)
}
fn partitions(now: i64) -> Result<Vec<Partition>> {
    let day = now.div_euclid(86400);
    if day < 1 {
        return Err(Error::Input);
    }
    Ok((-1..9)
        .map(|offset| Partition {
            start_micros: (day + offset) * 86400000000,
            end_micros: (day + offset + 1) * 86400000000,
        })
        .collect())
}
/// The fixed deployment maintenance call performs no sampling or business dispatch.
pub async fn maintain(input: Input) -> Result<()> {
    let journal = Journal::open(&input.directory)?;
    let Some(request) = journal.load::<Request>("telemetry-request.json")? else {
        return Err(Error::Corrupt);
    };
    let installation = request.operation_id;
    let now = now()?;
    telemetry::maintain(telemetry::PhysicalRequest {
        installation: request,
        operation_id: crate::administration::baseline::manifest::id(
            installation,
            &format!("partitions:{}", now.div_euclid(86400)),
        ),
        action: telemetry::PhysicalAction::PreparePartitions {
            partitions: partitions(now)?,
        },
    })
    .await?;
    Ok(())
}
