//! Native peer proof and frozen installation authority persist a grant in one audit commit.
use super::*;
use crate::agent_install;
use crate::device::DevicePrincipal;
use crate::frozen::Frozen;
use rss_mdm_agent_wire::{enroll, runtime as wire};
use sqlx::{PgConnection, Row};
impl ExecutionService {
    async fn register_managed_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        source: rss_mdm_inventory::ReportSource,
        input: &enroll::NativeGrantRequest,
        bootstrap: Uuid,
    ) -> std::result::Result<(enroll::GrantReceipt, bool), Error> {
        rss_mdm_registration_service::admission::lock_in(c, &p.tenant().to_string()).await?;
        let grant = self
            .authorize_managed_on(
                c,
                p,
                source,
                input.installation_operation,
                Some(&input.runtime),
                true,
            )
            .await?;
        let native = serde_json::json!({"installation":input.installation_operation,"registration":p.registration(),"credential":p.credential(),"generation":p.generation(),"source":source,"runtime":input.runtime,"bootstrap":bootstrap});
        rss_mdm_registration_service::agent::native::create_in(c, grant, input, &native)
            .await
            .map_err(Into::into)
    }
    async fn authorize_managed_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        source: rss_mdm_inventory::ReportSource,
        installation: Uuid,
        runtime: Option<&enroll::RuntimeProfile>,
        require_dispatch: bool,
    ) -> std::result::Result<rss_mdm_registration_service::enrollment::managed::Authority, Error>
    {
        #[cfg(feature = "integration")]
        {
            let gate = self
                .managed_admission_gate
                .lock()
                .expect("managed admission gate")
                .take();
            if let Some((ready, resume)) = gate {
                // Only the explicit contention probe extends this transaction's SQL
                // timeout so PostgreSQL can report the old-code deadlock, not a timeout.
                sqlx::query("SELECT set_config('statement_timeout','5s',true),set_config('lock_timeout','5s',true)")
                    .execute(&mut *c).await.map_err(crate::database::db)?;
                let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *c)
                    .await
                    .map_err(crate::database::db)?;
                let _ = ready.send(pid);
                tokio::time::timeout(std::time::Duration::from_secs(5), resume.notified())
                    .await
                    .map_err(|_| Error::Conflict)?;
            }
        }
        rss_mdm_inventory_postgres::lock_watermark_in(c, self.tenant)
            .await
            .map_err(crate::database::db)?;
        let tenant = self.tenant.to_string();
        crate::authorization::lock_shared_on(c, &tenant, &self.instance).await?;
        rss_mdm_registration_service::lifecycle::require_work_in(c, &tenant, p.device()).await?;
        crate::device::store::revalidate_source(c, p, source).await?;
        // The existing request lock serializes absent receipts and distinct retry IDs for one install.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
            .bind(format!("install:{tenant}:{}", installation))
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
        let row=sqlx::query("SELECT o.device,o.registration,o.registration_generation,o.request,o.input_context,o.authority,mdm_commands.installation_status(o.id) AS status FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(&tenant).bind(installation).fetch_optional(&mut *c).await.map_err(crate::database::db)?.ok_or(Error::Forbidden)?;
        if row
            .try_get::<Uuid, _>("registration")
            .map_err(crate::database::db)?
            != p.registration()
            || row
                .try_get::<i64, _>("registration_generation")
                .map_err(crate::database::db)?
                != p.generation()
            || row
                .try_get::<String, _>("device")
                .map_err(crate::database::db)?
                != p.device()
        {
            return Err(Error::Forbidden);
        }
        let request = super::input_storage::open_row(
            &self.protection,
            self.tenant,
            installation,
            &row,
            "request",
        )?;
        let authority: authority::ExecutionAuthority =
            serde_json::from_value(row.try_get("authority").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        let package = authority.agent_package().ok_or(Error::Forbidden)?.clone();
        if request.task.source() != source {
            return Err(Error::Forbidden);
        }
        if let Some(runtime) = runtime {
            let (profile, arch) = package.target.parts();
            if !matches!(
                (profile, runtime.platform),
                (
                    rss_mdm_policy::Platform::Windows,
                    wire::TaskPlatform::Windows
                ) | (rss_mdm_policy::Platform::Macos, wire::TaskPlatform::Macos)
            ) || !matches!(
                (arch, runtime.architecture),
                (
                    rss_mdm_policy::Architecture::X86_64,
                    wire::TaskArchitecture::X86_64
                ) | (
                    rss_mdm_policy::Architecture::Aarch64,
                    wire::TaskArchitecture::Aarch64
                )
            ) {
                return Err(Error::Forbidden);
            }
        }
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(crate::database::db)?;
        let now = self.installation_authorization_time(now);
        if now >= request.deadline
            || !matches!(
                row.try_get::<String, _>("status")
                    .map_err(crate::database::db)?
                    .as_str(),
                "published" | "received" | "applied"
            )
            || (require_dispatch
                && !agent_install::dispatched_on(c, &tenant, request.operation_id).await?)
        {
            return Err(Error::Forbidden);
        }
        if !authority
            .valid(
                self.source.as_ref(),
                c,
                &self.protection,
                &[crate::authorization::Permission::SoftwareDeploy],
                now,
            )
            .await?
        {
            return Err(Error::Forbidden);
        }
        let authority::ExecutionAuthority::AgentInstall { version, .. } = authority else {
            return Err(Error::Forbidden);
        };
        let frozen: serde_json::Value = sqlx::query_scalar(
            "SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(version)
        .fetch_one(&mut *c)
        .await
        .map_err(crate::database::db)?;
        let Frozen::AgentInstall { action } =
            serde_json::from_value(frozen).map_err(|_| Error::Malformed)?
        else {
            return Err(Error::Forbidden);
        };
        let grant = rss_mdm_registration_service::enrollment::managed::authorize_on(
            c,
            p,
            source,
            installation,
            request.deadline,
            &action.actor,
        )
        .await?;
        Ok(grant)
    }
}
impl rss_mdm_registration_service::agent::NativeAdmission for ExecutionService {
    fn bootstrap<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> rss_mdm_registration_service::agent::Pending<'a, ()> {
        Box::pin(async move {
            let delivered: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.id=$2 AND (EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute') OR EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE a.tenant_id=b.tenant_id AND a.operation=b.delivery AND a.phase='execute' AND a.state<>'pending')))")
                .bind(self.tenant.to_string()).bind(source.bootstrap()).fetch_one(&mut *c).await.map_err(|_| rss_mdm_registration_service::Error::Storage)?;
            if !delivered {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            self.authorize_managed_on(
                c,
                source.principal(),
                source.report_source(),
                source.installation(),
                None,
                false,
            )
            .await
            .map(|_| ())
            .map_err(registration_error)
        })
    }
    fn grant<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a rss_mdm_registration_service::agent::native::Source,
        input: &'a enroll::NativeGrantRequest,
    ) -> rss_mdm_registration_service::agent::Pending<'a, (enroll::GrantReceipt, bool)> {
        Box::pin(async move {
            self.register_managed_on(
                c,
                source.principal(),
                source.report_source(),
                input,
                source.bootstrap(),
            )
            .await
            .map_err(registration_error)
        })
    }
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> rss_mdm_registration_service::agent::Pending<'a, ()> {
        Box::pin(async move {
            self.authorize_managed_on(
                c,
                source.principal(),
                source.report_source(),
                source.installation(),
                source.runtime(),
                true,
            )
            .await
            .map(|_| ())
            .map_err(|e| match e {
                Error::Forbidden | Error::Unauthorized => {
                    rss_mdm_registration_service::Error::Forbidden
                }
                _ => rss_mdm_registration_service::Error::Storage,
            })
        })
    }
}

fn registration_error(error: Error) -> rss_mdm_registration_service::Error {
    match error {
        Error::Forbidden | Error::Unauthorized => rss_mdm_registration_service::Error::Forbidden,
        Error::Conflict => rss_mdm_registration_service::Error::Conflict,
        Error::Malformed => rss_mdm_registration_service::Error::Malformed,
        _ => rss_mdm_registration_service::Error::Storage,
    }
}
