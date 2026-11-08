//! Windows command business participation; no protocol state or transaction settlement.
use super::*;
use model::{AttemptPhase, DispatchFailure};
use rss_mdm_registration_service as device;
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
    pub software: bool,
    pub agent_minimum_os: Option<[u16; 4]>,
    pub minimum_os: Option<[u16; 4]>,
    pub observation: Option<rss_mdm_windows_mdm::native::Request>,
}
impl Transactions {
    pub async fn windows_operation_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
    ) -> std::result::Result<WindowsOperation, Error> {
        let row=sqlx::query("SELECT o.id, o.device, o.input_context, o.request, o.authority, d.status FROM mdm_planning.configuration_operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = $2 AND o.device = $3 AND o.input_context ->> 'purpose' = $4")
      .bind(p.tenant().to_string()).bind(id).bind(p.device()).bind(p.purpose().as_str()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Forbidden)?;
        let op = input_storage::open_row(&self.protection, p.tenant(), id, &row, "request")?;
        let authority: authority::Authority =
            serde_json::from_value(row.try_get("authority").map_err(db)?)
                .map_err(|_| Error::Malformed)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        let matches = op.task.purpose()? == p.purpose()
            && op.target.matches_windows_context(p.enrolled_user());
        let within_deadline = now < op.deadline;
        let status: String = row.try_get("status").map_err(db)?;
        let active = matches!(status.as_str(), "published" | "received");
        let software = false;
        let source = self.source.as_ref();
        let key = &self.protection;
        let permissions = op.task.permissions()?;
        let valid = authority.valid(source, c, key, &permissions, now).await?;
        let ready = authority.dispatch_ready(source, c).await?;
        let receipt_valid = authority.receipt_valid(c, key, &permissions).await?;
        let Task::Windows { request } = op.task else {
            return Err(Error::Malformed);
        };
        Ok(WindowsOperation {
            id,
            request,
            user: matches!(op.target, NativeTarget::EnrolledUser),
            matches,
            dispatch: matches && within_deadline && valid && ready,
            receipt: matches && within_deadline && active && receipt_valid,
            observe: matches
                && within_deadline
                && (active || (software && status == "applied"))
                && receipt_valid,
            replay: matches && within_deadline && active && valid && ready,
            software,
            agent_minimum_os: None,
            minimum_os: None,
            observation: None,
        })
    }
    pub async fn windows_candidates_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
    ) -> std::result::Result<Vec<WindowsOperation>, Error> {
        let ids=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_planning.configuration_operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.input_context ->> 'platform' = 'windows' AND o.input_context ->> 'purpose' = $3 AND o.gateway_accepted AND o.dispatch_failure IS NULL AND d.status IN ('published', 'received') AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) ORDER BY o.id LIMIT 64").bind(p.tenant().to_string()).bind(p.device()).bind(p.purpose().as_str()).fetch_all(&mut *c).await.map_err(db)?;
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
        sqlx::query("UPDATE mdm_planning.configuration_operations SET dispatch_failure = $3, revision = revision + 1 WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $4 AND dispatch_failure IS NULL")
      .bind(p.tenant().to_string()).bind(id).bind(sqlx::types::Json(DispatchFailure::Windows{reason,phase,context})).bind(p.device()).execute(c).await.map_err(db)?;
        Ok(())
    }
}
