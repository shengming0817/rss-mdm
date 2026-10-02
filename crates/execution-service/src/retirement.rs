//! Retire exact registration work using the existing command and action reducers.
//! ref: rss device-command-postgres persistence.rs@c83978d9b43d40f6663dc923c3e2afb3e9f51895
use crate::{Error, database::db, dc};
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
    let audit = RequestAudit::new(tenant.to_owned(), "credential_revoke");
    audit.identify_service("registration-retirement");
    audit.registration(registration);
    audit.target(&registration.to_string());
    let rows = sqlx::query("SELECT d.* FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(o.tenant_id,o.registration) WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND r.state<>'active' AND d.terminal_at IS NULL ORDER BY d.command_id COLLATE \"C\" FOR UPDATE OF d")
        .bind(tenant).bind(registration).fetch_all(&mut *c).await.map_err(db)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    for row in rows {
        let device: Uuid = row.try_get("device_id").map_err(db)?;
        let id: String = row.try_get("command_id").map_err(db)?;
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
        let changed: bool =
            sqlx::query_scalar("SELECT rss_device_command.save($1::uuid,$2,$3,$4,$5,$6,$7,$8)")
                .bind(tenant)
                .bind(device)
                .bind(&id)
                .bind(previous)
                .bind(record.status.as_str())
                .bind(record.published_at)
                .bind(record.received_at)
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
                id.as_bytes(),
                200,
                "success",
                None,
            )
            .map_err(Error::from)?,
        );
    }
    let rows = sqlx::query("SELECT id,state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 ORDER BY id FOR UPDATE").bind(tenant).bind(registration).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let mut state: crate::actions::state::RunState =
            serde_json::from_value(row.try_get("state").map_err(db)?)
                .map_err(|_| Error::Conflict)?;
        let previous = state.clone();
        state.cancel();
        if state == previous {
            continue;
        }
        sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
        facts.push(
            Fact::business(
                &audit,
                &format!("registration-retirement:{registration}:action:{id}"),
                id.as_bytes(),
                200,
                "success",
                None,
            )
            .map_err(Error::from)?,
        );
    }
    audit.finalize(None);
    Ok(())
}
