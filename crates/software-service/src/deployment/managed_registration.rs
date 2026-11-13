//! Native peer proof and frozen installation authority persist a grant in one audit commit.
use super::*;
use crate::deployment::agent_install;
use crate::deployment::device::DevicePrincipal;
use crate::deployment::frozen::Published;
use rss_mdm_agent_wire::{enroll, runtime as wire};
use sqlx::{PgConnection, Row};
/// Immutable participants form the Installation -> Registration seam without a service cycle.
pub struct AuthorityReader {
    pub inventory: Arc<dyn crate::deployment::inventory::Inventory>,
    pub software_distribution: SoftwareDistribution,
    pub tenant: TenantId,
    pub instance: String,
    pub source: Arc<dyn crate::deployment::scope::Sources>,
    pub lifecycle: Arc<dyn crate::deployment::retirement::Lifecycle>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
impl AuthorityReader {
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
        let tenant = self.tenant.to_string();
        crate::deployment::authorization::lock_shared_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            &self.instance,
        )
        .await?;
        rss_mdm_registration_service::lifecycle::require_work_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            p.device(),
        )
        .await?;
        crate::deployment::device::store::revalidate_source(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            p,
            source,
        )
        .await?;
        // The existing request lock serializes absent receipts and distinct retry IDs for one install.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
            .bind(format!("install:{tenant}:{}", installation))
            .execute(&mut *c)
            .await
            .map_err(crate::deployment::database::db)?;
        let row=sqlx::query("SELECT o.device, o.request, o.input_context, o.authority, mdm_software_deployment.installation_status(o.id) AS status FROM mdm_software_deployment.operations AS o WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = $2").bind(&tenant).bind(installation).fetch_optional(&mut *c).await.map_err(crate::deployment::database::db)?.ok_or(Error::Forbidden)?;
        if row
            .try_get::<Uuid, _>("device")
            .and_then(crate::deployment::database::device_id)
            .map_err(crate::deployment::database::db)?
            != *p.device()
        {
            return Err(Error::Forbidden);
        }
        let request = crate::deployment::input_storage::open_row(
            &self.protection,
            self.tenant,
            installation,
            &row,
            "request",
        )?;
        let authority: authority::Authority = serde_json::from_value(
            row.try_get("authority")
                .map_err(crate::deployment::database::db)?,
        )
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
                .map_err(crate::deployment::database::db)?;

        if now >= request.deadline
            || !matches!(
                row.try_get::<String, _>("status")
                    .map_err(crate::deployment::database::db)?
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
                self.lifecycle.as_ref(),
                c,
                &self.protection,
                &[crate::deployment::authorization::Permission::SoftwareDeploy],
                now,
            )
            .await?
        {
            return Err(Error::Forbidden);
        }
        let authority::Authority::AgentInstall { version, .. } = authority else {
            return Err(Error::Forbidden);
        };
        let frozen: serde_json::Value = sqlx::query_scalar(
            "SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(version)
        .fetch_one(&mut *c)
        .await
        .map_err(crate::deployment::database::db)?;
        let Published::AgentInstall { action } =
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
impl rss_mdm_registration_service::agent::NativeAdmission for AuthorityReader {
    fn bootstrap<'a>(
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
                None,
                false,
            )
            .await
            .map(|_| ())
            .map_err(registration_error)
        })
    }
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> rss_mdm_registration_service::agent::Pending<
        'a,
        rss_mdm_registration_service::enrollment::managed::Authority,
    > {
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

impl rss_mdm_registration_service::installation::Installations for AuthorityReader {
    fn dispatch_ready_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> rss_mdm_registration_service::agent::Pending<'a, bool> {
        Box::pin(async move {
            if tenant != self.tenant {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            let op = storage::load_on(c, tenant, &self.protection, id)
                .await
                .map_err(|e| match e {
                    Fault::Request(e) => registration_error(e),
                    _ => rss_mdm_registration_service::Error::Storage,
                })?;
            op.authority
                .dispatch_ready(
                    self.inventory.as_ref(),
                    self.source.as_ref(),
                    self.lifecycle.as_ref(),
                    c,
                    self.software_distribution.mdm_enabled,
                )
                .await
                .map_err(registration_error)
        })
    }
    fn delivery_ended_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> rss_mdm_registration_service::agent::Pending<'a, bool> {
        Box::pin(async move {
            if tenant != self.tenant {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2 AND d.status IN('rejected','cancelled','timed_out','superseded'))").bind(tenant.to_string()).bind(id).fetch_one(c).await.map_err(|_|rss_mdm_registration_service::Error::Storage)
        })
    }

    fn authorized_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> rss_mdm_registration_service::agent::Pending<
        'a,
        rss_mdm_registration_service::installation::Installation,
    > {
        Box::pin(async move {
            let value:std::result::Result<_,Error>=async {
                if tenant!=self.tenant {return Err(Error::Forbidden);}
                crate::deployment::authorization::lock_shared_on(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant.to_string(),&self.instance).await?;
                let row=sqlx::query("SELECT o.device, o.request, o.input_context, o.authority, mdm_software_deployment.installation_status(o.id) AS status FROM mdm_software_deployment.operations AS o WHERE o.tenant_id = CAST($1 AS uuid) AND o.id = $2").bind(tenant.to_string()).bind(id).fetch_optional(&mut *c).await.map_err(database::db)?.ok_or(Error::Forbidden)?;
                let request=crate::deployment::input_storage::open_row(&self.protection,tenant,id,&row,"request")?;
                let authority:authority::Authority=serde_json::from_value(row.try_get("authority").map_err(database::db)?).map_err(|_|Error::Malformed)?;
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(database::db)?;
                if now>=request.deadline || !matches!(row.try_get::<String,_>("status").map_err(database::db)?.as_str(),"queued"|"published"|"received"|"applied") || !authority.valid(self.source.as_ref(),self.lifecycle.as_ref(),c,&self.protection,&[authorization::Permission::SoftwareDeploy],now).await? {return Err(Error::Forbidden);}
                let authority::Authority::AgentInstall{package,download_origin,origin,device,policy,version,..}=authority else{return Err(Error::Forbidden)};
                rss_mdm_registration_service::lifecycle::require_work_in(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant.to_string(),&device).await?;
                let active:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active')").bind(tenant.to_string()).bind(device.into_uuid()).fetch_one(c).await.map_err(database::db)?;
                if !active {return Err(Error::Forbidden);}
                Ok(rss_mdm_registration_service::installation::Installation{id,policy,version,device,platform:package.target.parts().0,source:request.task.source(),release:package.release.release_id,deadline:request.deadline,input_version:request.input_version,download_origin,origin})
            }.await;
            value.map_err(registration_error)
        })
    }
}
