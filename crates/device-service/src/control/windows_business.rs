//! Windows command business participation; no protocol state or transaction settlement.
use crate::control::authority::Authority;
use crate::control::database::db;
use crate::control::*;
use sqlx::{PgConnection, Row};
pub struct WindowsOperation {
    pub id: Uuid,
    pub request: rss_mdm_windows_mdm::native::Execution,
    pub user: bool,
    pub matches: bool,
    pub dispatch: bool,
    pub receipt: bool,
    pub observe: bool,
    pub replay: bool,
    pub observation: Option<rss_mdm_windows_mdm::native::Request>,
}
impl Service {
    pub async fn windows_operation_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
    ) -> std::result::Result<WindowsOperation, Error> {
        let row=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request,o.authority,d.status FROM mdm_devices.control_operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.id=$2 AND o.registration=$3 AND o.registration_generation=$4 AND o.device=$5")
      .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).bind(p.device()).fetch_optional(&mut *c).await.map_err(database::db)?.ok_or(Error::Forbidden)?;
        let op = input_storage::open_row(
            &self.transactions.protection,
            p.tenant(),
            id,
            &row,
            "request",
        )?;
        let authority: Authority =
            serde_json::from_value(row.try_get("authority").map_err(database::db)?)
                .map_err(|_| Error::Malformed)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(database::db)?;
        let matches = op.target.matches_windows_context(p.user_context());
        let within_deadline = now < op.deadline;
        let status: String = row.try_get("status").map_err(database::db)?;
        let active = matches!(status.as_str(), "published" | "received");

        let key = &self.transactions.protection;
        let permissions = op.task.permissions()?;
        let valid = authority.valid(c, key, &permissions, now).await?;
        let ready = authority.dispatch_ready(c).await?;
        let receipt_valid = authority.receipt_valid(c, key, &permissions, now).await?;
        let control = !matches!(authority, Authority::DeviceControl { .. })
            || authority.control_matches(&op, p.registration(), p.generation())?;
        let Task::Windows { request } = op.task else {
            return Err(Error::Malformed);
        };
        Ok(WindowsOperation {
            id,
            request,
            user: matches!(op.target, NativeTarget::User { .. }),
            matches,
            dispatch: matches && within_deadline && valid && ready && control,
            receipt: matches && within_deadline && active && receipt_valid,
            observe: matches && within_deadline && active && receipt_valid,
            replay: matches && within_deadline && active && valid && ready,
            observation: None,
        })
    }
    pub async fn windows_candidates_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
    ) -> std::result::Result<Vec<WindowsOperation>, Error> {
        let ids=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_devices.control_operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.input_context->>'platform'='windows' AND o.gateway_accepted AND o.dispatch_failure IS NULL AND d.status IN('published','received') AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY o.id LIMIT 64").bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).fetch_all(&mut *c).await.map_err(db)?;
        let mut output = Vec::new();
        for id in ids {
            let op = self.windows_operation_on(c, p, id).await?;
            if op.dispatch {
                output.push(op);
            }
        }
        Ok(output)
    }
    pub async fn windows_dispatch_failure_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
        reason: String,
        phase: Option<AttemptPhase>,
        context: Option<rss_mdm_windows_mdm::native::Context>,
    ) -> std::result::Result<(), Error> {
        sqlx::query("UPDATE mdm_devices.control_operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND registration=$4 AND registration_generation=$5 AND dispatch_failure IS NULL")
      .bind(p.tenant().to_string()).bind(id).bind(sqlx::types::Json(DispatchFailure::Windows{reason,phase,context})).bind(p.registration()).bind(p.generation()).execute(c).await.map_err(database::db)?;
        Ok(())
    }
}
