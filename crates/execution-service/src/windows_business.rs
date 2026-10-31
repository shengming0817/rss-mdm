//! Windows command business participation; no protocol state or transaction settlement.
use crate::authority::ExecutionAuthority;
use crate::*;
use crate::{database::db, device::DevicePrincipal};
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
impl ExecutionService {
    pub fn native_software_enabled(&self) -> bool {
        self.transactions.source.mdm_software_enabled()
    }

    pub async fn windows_operation_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
    ) -> std::result::Result<WindowsOperation, Error> {
        let row=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request,o.authority,d.status FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.id=$2 AND o.registration=$3 AND o.registration_generation=$4 AND o.device=$5")
      .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).bind(p.device()).fetch_optional(&mut *c).await.map_err(database::db)?.ok_or(Error::Forbidden)?;
        let op = input_storage::open_row(
            &self.transactions.protection,
            p.tenant(),
            id,
            &row,
            "request",
        )?;
        let authority: ExecutionAuthority =
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
        let software = matches!(authority, ExecutionAuthority::Software { .. });
        let source = self.transactions.source.as_ref();
        let key = &self.transactions.protection;
        let permissions = op.task.permissions()?;
        let valid = authority.valid(source, c, key, &permissions, now).await?;
        let ready = authority.dispatch_ready(source, c).await?;
        let receipt_valid = authority
            .receipt_valid(source, c, key, &permissions, now)
            .await?;
        let control = !matches!(authority, ExecutionAuthority::DeviceControl { .. })
            || authority.control_matches(&op, p.registration(), p.generation())?;
        let package = native_software::package_on(key, c, &authority, &op.task).await?;
        let agent_minimum_os = authority.agent_package().and_then(|p| match &p.identity {
            agent_install::Identity::WindowsMsix { minimum_os, .. } => Some(*minimum_os),
            _ => None,
        });
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
        let ids=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.input_context->>'platform'='windows' AND o.gateway_accepted AND o.dispatch_failure IS NULL AND (o.authority->>'kind'<>'software' OR NOT EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=o.tenant_id AND r.id=o.id AND r.state->>'execution'='succeeded')) AND (d.status IN('published','received') OR (d.status='applied' AND o.authority->>'kind'='software')) AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY (o.authority->>'stage'='bootstrap') DESC NULLS LAST,o.id LIMIT 64").bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).fetch_all(&mut *c).await.map_err(db)?;
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
        sqlx::query("UPDATE mdm_commands.operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND registration=$4 AND registration_generation=$5 AND dispatch_failure IS NULL")
      .bind(p.tenant().to_string()).bind(id).bind(sqlx::types::Json(DispatchFailure::Windows{reason,phase,context})).bind(p.registration()).bind(p.generation()).execute(c).await.map_err(database::db)?;
        Ok(())
    }
}
pub async fn wake_configuration(
    c: &mut PgConnection,
    p: &DevicePrincipal,
) -> std::result::Result<(), Error> {
    let tenant = p.tenant().to_string();
    sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1").bind(&tenant).bind(p.device()).execute(&mut *c).await.map_err(crate::database::db)?;
    sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3,'{}'::text[])")
        .bind(&tenant)
        .bind(crate::DOMAIN)
        .bind(crate::wake::configuration_key(p.device()))
        .execute(&mut *c)
        .await
        .map_err(crate::database::db)?;
    crate::worker_wake::notify(c, crate::worker_wake::Work::CommandRecovery)
        .await
        .map_err(crate::database::db)?;
    Ok(())
}

impl ExecutionService {
    pub async fn windows_collection_eligible_on(
        &self,
        c: &mut PgConnection,
        p: &device::DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> std::result::Result<bool, Error> {
        if delivery {
            actions::native_collection::delivery_eligible_on(
                self.transactions.source.as_ref(),
                c,
                p,
                id,
            )
            .await
        } else {
            actions::native_collection::eligible_on(self.transactions.source.as_ref(), c, p, id)
                .await
        }
    }
}

use rss_mdm_windows_mdm::native::{Context, Scope};
pub(crate) fn context(
    version: &str,
    edition: u32,
    scope: Scope,
    purpose: rss_mdm_registration_service::Purpose,
) -> std::result::Result<Context, Error> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(Error::Unavailable(Failure::Protocol));
    }
    let mut build = [0; 4];
    for (i, part) in parts.iter().enumerate() {
        build[i] = part
            .parse()
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    }
    Ok(Context {
        enrollment: match purpose {
            rss_mdm_registration_service::Purpose::Primary => {
                rss_mdm_windows_mdm::native::Enrollment::Primary
            }
            rss_mdm_registration_service::Purpose::WindowsDeclared => {
                rss_mdm_windows_mdm::native::Enrollment::LinkedCertificate
            }
        },
        build: Some(build),
        edition: Some(edition),
        scope,
    })
}
