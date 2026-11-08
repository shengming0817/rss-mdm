//! Windows command business participation; no protocol state or transaction settlement.
use crate::deployment::authority::Authority;
use crate::deployment::database::db;
use crate::deployment::*;
use sqlx::{PgConnection, Row};
pub struct WindowsOperation {
    pub id: Uuid,
    pub bootstrap: bool,
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
impl SoftwareService {
    pub fn native_software_enabled(&self) -> bool {
        self.transactions.inputs.software_distribution().mdm_enabled
    }

    pub async fn windows_operation_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
    ) -> std::result::Result<WindowsOperation, Error> {
        let row=sqlx::query("SELECT o.id, o.device, o.device, o.input_context, o.request, o.authority, d.status FROM mdm_software_deployment.operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = $2 AND o.device = $3 AND o.device = $4")
      .bind(p.tenant().to_string()).bind(id).bind(p.device()).bind(p.device()).fetch_optional(&mut *c).await.map_err(database::db)?.ok_or(Error::Forbidden)?;
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
        let matches = op.target.matches_windows_context(p.enrolled_user());
        let within_deadline = now < op.deadline;
        let status: String = row.try_get("status").map_err(database::db)?;
        let active = matches!(status.as_str(), "published" | "received");
        let software = matches!(authority, Authority::Software { .. });
        let source = self.transactions.source.as_ref();
        let key = &self.transactions.protection;
        let permissions = op.task.permissions()?;
        let valid = authority
            .valid(
                source,
                self.transactions.lifecycle.as_ref(),
                c,
                key,
                &permissions,
                now,
            )
            .await?;
        let ready = authority
            .dispatch_ready(
                self.transactions.inventory.as_ref(),
                source,
                self.transactions.lifecycle.as_ref(),
                c,
                self.transactions.inputs.software_distribution().mdm_enabled,
            )
            .await?;
        let receipt_valid = authority
            .receipt_valid(
                source,
                self.transactions.lifecycle.as_ref(),
                c,
                key,
                &permissions,
                now,
            )
            .await?;
        let package = native_software::package_on(key, c, &authority, &op.task).await?;
        let agent_minimum_os = authority.agent_package().and_then(|p| match &p.identity {
            crate::installation::package::Identity::WindowsMsix { minimum_os, .. } => {
                Some(*minimum_os)
            }
            _ => None,
        });
        let Task::Windows { request } = op.task else {
            return Err(Error::Malformed);
        };
        Ok(WindowsOperation {
            id,
            bootstrap: false,
            request,
            user: matches!(op.target, NativeTarget::User { .. }),
            matches,
            dispatch: matches && within_deadline && valid && ready,
            receipt: matches && within_deadline && active && receipt_valid,
            observe: matches
                && within_deadline
                && (active || (software && status == "applied"))
                && receipt_valid,
            replay: matches && within_deadline && active && valid && ready,
            software,
            agent_minimum_os,
            minimum_os: package.as_ref().and_then(|p| p.minimum_os),
            observation: package.and_then(|p| p.observation()),
        })
    }
    pub async fn windows_candidates_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
    ) -> std::result::Result<Vec<WindowsOperation>, Error> {
        let ids=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_software_deployment.operations AS o INNER JOIN rss_device_command.commands AS d ON d.tenant_id = o.tenant_id AND d.command_id = CAST(o.id AS text) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.input_context ->> 'platform' = 'windows' AND o.gateway_accepted AND o.dispatch_failure IS NULL AND (o.authority ->> 'kind' <> 'software' OR NOT EXISTS (SELECT 1 FROM mdm_software_deployment.action_runs AS r WHERE r.tenant_id = o.tenant_id AND r.id = o.id AND r.state ->> 'execution' = 'succeeded')) AND (d.status IN ('published', 'received') OR (d.status = 'applied' AND o.authority ->> 'kind' = 'software')) AND CAST(o.input_context ->> 'deadline' AS bigint) > EXTRACT(EPOCH FROM clock_timestamp()) ORDER BY o.id LIMIT 64").bind(p.tenant().to_string()).bind(p.device()).fetch_all(&mut *c).await.map_err(db)?;
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
        sqlx::query("UPDATE mdm_software_deployment.operations SET dispatch_failure = $3, revision = revision + 1 WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $4 AND dispatch_failure IS NULL")
      .bind(p.tenant().to_string()).bind(id).bind(sqlx::types::Json(DispatchFailure::Windows{reason,phase,context})).bind(p.device()).execute(c).await.map_err(database::db)?;
        Ok(())
    }
}
