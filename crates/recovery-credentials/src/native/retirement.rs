//! Retire exact registration work using the existing command and action reducers.
//! ref: rss device-command-postgres persistence.rs@c83978d9b43d40f6663dc923c3e2afb3e9f51895
use crate::native::{Error, database::db, dc};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use sqlx::Row;
use uuid::Uuid;

pub async fn retire_in(
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<Fact>,
    tenant: &str,
    registration: Uuid,
) -> Result<(), Error> {
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    let audit = RequestAudit::new(
        tenant.to_owned(),
        "credential_revoke",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("registration-retirement");
    audit.registration(registration);
    audit.target(&registration.to_string());
    let mut after = String::new();
    loop {
        let rows = sqlx::query("SELECT * FROM mdm_recovery_tasks.retirement_commands($1,$2)")
            .bind(registration)
            .bind(&after)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
        let count = rows.len();
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
        )
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
        for row in rows {
            let device: Uuid = row.try_get("device_id").map_err(db)?;
            let id: String = row.try_get("command_id").map_err(db)?;
            after.clone_from(&id);
            let coordinate = dc::Coordinate::new(
                row.try_get("generation").map_err(db)?,
                row.try_get("authority_epoch").map_err(db)?,
            )
            .map_err(|_| Error::Conflict)?;
            let spec = dc::CommandSpec::new(
                dc::Scope::new(
                    tenant_id,
                    dc::DeviceId::parse(&device.to_string()).map_err(|_| Error::Conflict)?,
                ),
                dc::CommandId::parse(&id).map_err(|_| Error::Conflict)?,
                coordinate,
                dc::StateDigest::from_bytes(
                    row.try_get::<Vec<u8>, _>("expected_digest")
                        .map_err(db)?
                        .try_into()
                        .map_err(|_| Error::Conflict)?,
                ),
                row.try_get("deadline").map_err(db)?,
            );
            let previous: i64 = row.try_get("version").map_err(db)?;
            let mut command = dc::Command::restore(dc::Record {
                spec,
                version: previous,
                status: dc::Status::restore(&row.try_get::<String, _>("status").map_err(db)?)
                    .map_err(|_| Error::Conflict)?,
                queued_at: row.try_get("queued_at").map_err(db)?,
                published_at: row.try_get("published_at").map_err(db)?,
                received_at: row.try_get("received_at").map_err(db)?,
                terminal_at: None,
            })
            .map_err(|_| Error::Conflict)?;
            if command
                .transition(dc::Event::Cancel, coordinate, now)
                .map_err(|_| Error::Conflict)?
                != dc::Outcome::Advanced
            {
                return Err(Error::Conflict);
            }
            let record = command.record();
            let changed: bool = sqlx::query_scalar(
                "SELECT mdm_recovery_tasks.save_retired_command($1,$2::uuid,$3,$4)",
            )
            .bind(registration)
            .bind(&id)
            .bind(previous)
            .bind(record.terminal_at)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
            if !changed {
                return Err(Error::Conflict);
            }
            facts.push(
                Fact::business(
                    &audit,
                    &format!("registration-retirement:{registration}:command:{id}"),
                    200,
                    "success",
                    None,
                )
                .map_err(Error::from)?,
            );
        }
        if count < 64 {
            break;
        }
    }
    audit.finalize(None);
    Ok(())
}

pub async fn progress_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registrations: &[uuid::Uuid],
) -> crate::native::Result<(bool, Option<uuid::Uuid>)> {
    Ok(sqlx::query_as("SELECT count(*)>0,(array_agg(id ORDER BY id) FILTER(WHERE priority=0))[1] FROM (SELECT o.id,CASE WHEN d.terminal_at IS NOT NULL THEN 0 ELSE 1 END AS priority FROM mdm_recovery_tasks.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration=ANY($2) AND (d.terminal_at IS NULL OR (d.status<>'applied' AND (EXISTS(SELECT 1 FROM mdm_windows.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE(a.tenant_id,a.operation)=(o.tenant_id,o.id) AND a.phase='execute' AND a.state<>'pending'))))) pending").bind(tenant).bind(registrations).fetch_one(c).await?)
}
