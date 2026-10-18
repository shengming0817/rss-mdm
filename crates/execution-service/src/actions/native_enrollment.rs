//! Native handoff is available only to the authenticated holder of a started enrollment task.
use super::{
    agent,
    state::{Cancellation, Execution},
    storage as db,
};
use crate::{device::DevicePrincipal, *};
use rss_mdm_agent_wire::enroll::{NativeEnrollmentReceipt, NativeEnrollmentRequest};
use rss_mdm_inventory::ReportSource;
use rss_mdm_registration_service::enrollment::{
    self,
    native::{AgentPolicyAuthority, Coordinates},
};
use sqlx::{PgConnection, Row};
impl ExecutionService {
    pub async fn native_enrollment(
        &self,
        p: &DevicePrincipal,
        task: Uuid,
        input: &NativeEnrollmentRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<NativeEnrollmentReceipt, Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, p, task, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, task, input, audit) = *ctx;
                    storage::lock(tx, p.device()).await?;
                    agent::principal(s, tx, p).await?;
                    let run = db::load_run(tx, task).await?;
                    agent::belongs(&run, p)?;
                    let plan = db::load_source(&s.policy_reader, tx, run.source).await?;
                    let now = storage::now(tx).await?;
                    let continued = if run.state.execution==Execution::Running {true} else if run.state.execution==Execution::Failed {false} else {
                        let tenant=s.tenant;
                        tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_native_enrollments WHERE tenant_id=$1::uuid AND task=$2)").bind(tenant.to_string()).bind(task).fetch_one(c).await})).await?
                    };
                    if run.state.attempt() != Some(input.attempt_id)
                        || run.state.started_at.is_none()
                        || !continued
                        || run.state.cancellation != Cancellation::None
                        || !plan.authorized_run_in(s, tx, &run, now).await?
                    {
                        return Err(Error::Forbidden.into());
                    }
                    let db::ScheduledPolicy::Enrollment(policy) = plan else {
                        return Err(Error::Forbidden.into());
                    };
                    let (platform, _) = db::agent_profile_in(s, tx, p.registration())
                        .await?
                        .ok_or(Error::Forbidden)?;
                    let entry = policy
                        .frozen
                        .entries
                        .for_platform(platform)
                        .ok_or(Error::Unsupported)?;
                    let source = match platform {
                        rss_mdm_policy::Platform::Windows => ReportSource::MdmWindows,
                        rss_mdm_policy::Platform::Macos => ReportSource::MdmApple,
                    };
                    let password = enrollment::Password::new(input.password.expose().to_owned())
                        .map_err(rss_mdm_registration_service::Error::from)?;
                    let principal = p.clone();
                    let operation = input.operation_id;
                    let attempt = input.attempt_id;
                    let authority = policy.frozen.grant;
                    let deadline = run.deadline;
                    let (receipt, replay) = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(enrollment::agent_policy::create_in(
                                    c,
                                    enrollment::agent_policy::Create {
                                        principal: &principal,
                                        task,
                                        attempt,
                                        operation,
                                        password: &password,
                                        authority: &authority,
                                        source,
                                        deadline,
                                    },
                                )
                                .await)
                            })
                        })
                        .await??;
                    let (username, profile_url) = match &entry {
                        rss_mdm_agent_wire::runtime::EnrollmentEntry::Windows { server } => {
                            let url = url::Url::parse(server).map_err(|_| Error::Malformed)?;
                            (
                                Some(format!(
                                    "{}@{}",
                                    receipt.enrollment_id,
                                    url.host_str().ok_or(Error::Malformed)?
                                )),
                                None,
                            )
                        }
                        rss_mdm_agent_wire::runtime::EnrollmentEntry::Macos { url } => {
                            let origin = url::Url::parse(url)
                                .map_err(|_| Error::Malformed)?
                                .origin()
                                .ascii_serialization();
                            (
                                None,
                                Some(format!(
                                    "{origin}/api/v1/enrollments/{}/profile",
                                    receipt.enrollment_id
                                )),
                            )
                        }
                    };
                    let fingerprint = crate::transaction::fingerprint(&(task, input))?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("agent-native:{task}:{}", input.operation_id),
                        &fingerprint,
                        200,
                        "success",
                        Some(receipt.enrollment_id),
                    )?;
                    s.audit_store.append_in(tx, &fact, replay).await?;
                    Ok(NativeEnrollmentReceipt {
                        enrollment_id: receipt.enrollment_id,
                        expires_at: receipt.expires_at,
                        entry,
                        username,
                        profile_url,
                    })
                })
            },
        )
        .await
    }
}
impl AgentPolicyAuthority for ExecutionService {
    fn lock_in<'a>(
        &'a self,
        c: &'a mut PgConnection,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<(), rss_mdm_registration_service::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            rss_mdm_inventory_postgres::lock_watermark_in(c, self.tenant)
                .await
                .map(|_| ())
                .map_err(|_| rss_mdm_registration_service::Error::Storage)
        })
    }

    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        d: &'a Coordinates,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<(), rss_mdm_registration_service::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use rss_mdm_registration_service::Error as E;
            if self.tenant.to_string() != d.tenant {
                return Err(E::Forbidden);
            }
            <Self as AgentPolicyAuthority>::lock_in(self, c).await?;
            enrollment::agent_policy::current_source_in(c, self.tenant, d.id).await?;
            let row=sqlx::query("SELECT l.authority,r.invocation,r.device,r.policy_version,p.id AS policy,p.definition,r.state AS task_state,r.deadline,(p.state='enabled') AND p.current_version=v.id AS live FROM mdm_access.agent_native_enrollments l JOIN mdm_commands.action_runs r ON(r.tenant_id,r.id,r.registration,r.generation)=(l.tenant_id,l.task,l.source_registration,l.source_generation) JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) JOIN mdm_access.registrations g ON(g.tenant_id,g.id,g.generation)=(l.tenant_id,l.source_registration,l.source_generation) WHERE l.tenant_id=$1::uuid AND l.request=$2 AND g.state='active' AND g.channel='agent' AND EXISTS(SELECT 1 FROM mdm_access.credentials k WHERE k.tenant_id=g.tenant_id AND k.registration=g.id AND k.state='active')")
                .bind(&d.tenant).bind(d.id).fetch_optional(&mut *c).await.map_err(|_|E::Storage)?.ok_or(E::Forbidden)?;
            let policy = row.try_get::<Uuid, _>("policy").map_err(|_| E::Storage)?;
            let definition: rss_mdm_policy::Definition =
                serde_json::from_value(row.try_get("definition").map_err(|_| E::Storage)?)
                    .map_err(|_| E::Corrupt)?;
            if let Some(value) = row
                .try_get::<Option<serde_json::Value>, _>("invocation")
                .map_err(|_| E::Storage)?
            {
                let invocation: crate::self_service::Invocation =
                    serde_json::from_value(value).map_err(|_| E::Corrupt)?;
                if invocation
                    .qualified_on(c, policy, self.tenant, &self.instance, &self.sessions)
                    .await
                    .map_err(|e| match e {
                        crate::transaction::Fault::Request(
                            Error::Unauthorized | Error::Forbidden,
                        ) => E::Forbidden,
                        _ => E::Storage,
                    })?
                    .is_none()
                {
                    return Err(E::Forbidden);
                }
            }
            let version = row
                .try_get::<Uuid, _>("policy_version")
                .map_err(|_| E::Storage)?;
            if !self
                .source
                .policy_readable_on(c, self.tenant, version)
                .await
                .map_err(|_| E::Storage)?
            {
                return Err(E::Forbidden);
            }
            let device = row.try_get::<String, _>("device").map_err(|_| E::Storage)?;
            if !matches!(
                self.source
                    .admission_on(
                        c,
                        self.tenant,
                        definition.scope,
                        rss_mdm_inventory::Channel::Agent,
                        &device
                    )
                    .await
                    .map_err(|_| E::Storage)?,
                crate::source_authority::ScopeAdmission::Eligible { .. }
            ) {
                return Err(E::Forbidden);
            }
            let state: serde_json::Value = row.try_get("task_state").map_err(|_| E::Storage)?;
            let now: i64 =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|_| E::Storage)?;
            if !row.try_get::<bool, _>("live").map_err(|_| E::Storage)?
                || row.try_get::<i64, _>("deadline").map_err(|_| E::Storage)? <= now
                || state["cancellation"] != "none"
                || state["startedAt"].is_null()
                || state["execution"] == "failed"
            {
                return Err(E::Forbidden);
            }
            let grant: rss_mdm_authorization_service::UserGrant =
                serde_json::from_value(row.try_get("authority").map_err(|_| E::Storage)?)
                    .map_err(|_| E::Corrupt)?;
            if !grant
                .valid(c, crate::authorization::Permission::Enrollment, now)
                .await?
            {
                return Err(E::Forbidden);
            }
            Ok(())
        })
    }
}
