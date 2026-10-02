//! Native peer proof, frozen Policy authority, Enrollment and Agent binding share one audit commit.
use super::*;
use crate::device::DevicePrincipal;
use crate::planning::policies::{Frozen, agent_install};
use rss_mdm_agent_wire as wire;
use rss_mdm_audit_integration::Fact;
use sqlx::{PgConnection, Row};
impl ExecutionService {
    pub async fn managed_registration(
        &self,
        p: &DevicePrincipal,
        source: rss_mdm_inventory::ReportSource,
        input: &wire::ManagedRegistrationRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<(wire::RegistrationReceipt, bool), Error> {
        input.validate().map_err(|_| Error::Malformed)?;
        if p.tenant() != self.tenant || source == rss_mdm_inventory::ReportSource::AgentBuiltin {
            return Err(Error::Forbidden);
        }
        audit.identify_device(p.registration());
        audit.target(p.device());
        audit.operation(input.operation_id, "agent_registration");
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
        let control = budget.control();
        let result = self
            .audit_store
            .write(
                self.tenant,
                &control,
                (self, p, source, input, audit),
                |ctx, tx| {
                    Box::pin(async move {
                        let (service, p, source, input, audit) = *ctx;
                        let (receipt, replay) = tx
                            .with_connection_context(
                                &mut (service, p, source, input, audit),
                                |ctx, c| {
                                    Box::pin(async move {
                                        let (service, p, source, input, audit) = *ctx;
                                        service
                                            .register_managed_on(c, p, source, input, audit)
                                            .await
                                    })
                                },
                            )
                            .await?;
                        let digest = rss_mdm_registration_service::enrollment::digest(&(
                            "mdm.agent.managed-registration/v5",
                            input,
                        ));
                        let fact = Fact::business(
                            audit,
                            &format!(
                                "agent-registration:device:{}:{}",
                                p.registration(),
                                input.operation_id
                            ),
                            digest.as_bytes(),
                            201,
                            "success",
                            Some(input.installation_operation),
                        )
                        .map_err(Error::from)?;
                        service
                            .audit_store
                            .append(tx, &fact, replay)
                            .await
                            .map_err(Error::from)?;
                        if replay {
                            audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        audit.mark_commit_started();
                        Ok::<_, Error>((receipt, replay))
                    })
                },
            )
            .await;
        result.fold(
            |v| {
                audit.mark_committed();
                Ok(v.into_value())
            },
            |e| Err(audit_error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(audit_error(e))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |e| Err(audit_error(e)),
        )
    }
    async fn register_managed_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        source: rss_mdm_inventory::ReportSource,
        input: &wire::ManagedRegistrationRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<(wire::RegistrationReceipt, bool), Error> {
        let tenant = self.tenant.to_string();
        crate::authorization::lock_on(c, &tenant, &self.instance).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
            .bind(&tenant)
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
            .bind(format!("{tenant}:{}", p.device()))
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
        crate::device::store::revalidate_source(c, p, source).await?;
        // The existing request lock serializes absent receipts and distinct retry IDs for one install.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
            .bind(format!("install:{tenant}:{}", input.installation_operation))
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
        if let Some(receipt) = self.agent_store.managed_replay(c, p, input, audit).await? {
            return Ok((receipt, true));
        }
        let row=sqlx::query("SELECT o.device,o.registration,o.registration_generation,o.request,o.input_context,o.approval,mdm_commands.installation_status(o.id) AS status FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(&tenant).bind(input.installation_operation).fetch_optional(&mut *c).await.map_err(crate::database::db)?.ok_or(Error::Forbidden)?;
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
            input.installation_operation,
            &row,
            "request",
        )?;
        let approval: authority::ExecutionAuthority =
            serde_json::from_value(row.try_get("approval").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        let package = approval.agent_package().ok_or(Error::Forbidden)?.clone();
        if request.task.source() != source {
            return Err(Error::Forbidden);
        }
        let (profile, arch) = package.target.parts();
        if !matches!(
            (profile, input.platform),
            (
                rss_mdm_policy::Platform::Windows,
                wire::TaskPlatform::Windows
            ) | (rss_mdm_policy::Platform::Macos, wire::TaskPlatform::Macos)
        ) || !matches!(
            (arch, input.architecture),
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
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(crate::database::db)?;
        if now >= request.deadline
            || !matches!(
                row.try_get::<String, _>("status")
                    .map_err(crate::database::db)?
                    .as_str(),
                "published" | "received" | "applied"
            )
            || !agent_install::dispatched_on(c, &tenant, request.operation_id).await?
        {
            return Err(Error::Forbidden);
        }
        if !approval
            .valid(
                c,
                &self.protection,
                &[crate::authorization::Permission::SoftwareDeploy],
                now,
            )
            .await?
        {
            return Err(Error::Forbidden);
        }
        let authority::ExecutionAuthority::AgentInstall { version, .. } = approval else {
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
            input.installation_operation,
            request.deadline,
            &action.enrollment,
        )
        .await?;
        Ok((
            self.agent_store
                .managed_register(c, grant, input, audit)
                .await?,
            false,
        ))
    }
}
fn audit_error(e: rss_audit_postgres::TransactionError<Error>) -> Error {
    match e {
        rss_audit_postgres::TransactionError::Operation(e) => e,
        rss_audit_postgres::TransactionError::Audit(e) => {
            rss_mdm_audit_integration::Error::from(e).into()
        }
        rss_audit_postgres::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
