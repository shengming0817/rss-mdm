//! DA configuration selection and native-session admission without a Scope backend.
use crate::{
    Error, Pending, Service,
    database::db,
    device_access::{self, Admission as AdmissionPort},
};
use rss_mdm_agent_wire::runtime::{AccessLocalSession, AccessPolicyOption};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_device_access::PolicySelection;
use rss_mdm_registration_service::{DevicePrincipal, participants::agent};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
/// Runtime resources for the DA admission port. Agent delivery is optional.
pub struct Admission {
    pub tenant: TenantId,
    pub installation: Uuid,
    pub platform: Option<Arc<crate::platform_sso::Runtime>>,
    pub evidence: Arc<crate::evidence::Authorities>,
    pub agent: Option<Arc<dyn agent::Store>>,
    pub broker_query: &'static str,
}
impl Admission {
    async fn session(
        &self,
        c: &mut PgConnection,
        anchor: &rss_mdm_registration_service::device::endpoints::DaRegistration,
    ) -> Result<AccessLocalSession, Error> {
        let now = crate::platform_sso::store::now(c).await?;
        let value = self
            .evidence
            .native_on(c, self.tenant, self.installation, anchor, now)
            .await?;
        match &value.deployment {
            rss_mdm_device_access::deployment::Deployment::Windows { .. }
                if value.windows_session(now) =>
            {
                // reason: windows_session already verified the broker and local session.
            }
            rss_mdm_device_access::deployment::Deployment::Macos { .. } => {
                let rt = self.platform.as_deref().ok_or(Error::Forbidden)?;
                let login = crate::platform_sso::deployment::configuration_for_object(
                    c,
                    self.tenant,
                    anchor,
                )
                .await?;
                if !value.qualifies(
                    &rt.qualification_configuration()?,
                    rt.profile(&login)?.uuid,
                    now,
                ) {
                    return Err(Error::Forbidden);
                }
            }
            _ => return Err(Error::Forbidden),
        }
        value.local_session.ok_or(Error::Forbidden)
    }
}
impl AdmissionPort for Admission {
    fn broker_release_query(&self) -> &'static str {
        self.broker_query
    }

    fn policies<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        device: &'a str,
        after: Option<Uuid>,
        limit: u16,
    ) -> Pending<'a, (Vec<AccessPolicyOption>, Option<Uuid>)> {
        Box::pin(async move {
            if tenant.to_string() != self.tenant.to_string() || limit == 0 || limit > 100 {
                return Err(Error::Forbidden);
            }
            let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM rss_da.policies WHERE tenant_id=$1 AND ($2::uuid IS NULL OR id>$2) AND rss_da.access_policy(id,$3,0)->>'state'='eligible' ORDER BY id LIMIT 2").bind(tenant).bind(after).bind(device).fetch_all(&mut *c).await.map_err(db)?;
            if ids.len() > 1 {
                return Err(Error::Corrupt);
            }
            let mut values = Vec::new();
            for id in ids {
                let p = self.policy(c, tenant, device, id).await?;
                if p.configuration.enabled && p.configuration.self_enrollment {
                    values.push(AccessPolicyOption {
                        policy: p.policy,
                        version: p.version,
                        configuration: p.configuration,
                    });
                }
            }
            Ok((values, None))
        })
    }
    fn policy<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        device: &'a str,
        policy: Uuid,
    ) -> Pending<'a, PolicySelection> {
        Box::pin(device_access::execution::admission::policy_on(
            self.tenant,
            c,
            tenant,
            device,
            policy,
        ))
    }
    fn local_session<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, AccessLocalSession> {
        Box::pin(async move {
            if p.tenant() != self.tenant {
                return Err(Error::Forbidden);
            }
            let target = crate::delivery::resolve_on(c, p).await?;
            if p.kind() == rss_mdm_registration_service::device::RegistrationKind::Agent {
                let store = self.agent.as_ref().ok_or(Error::Unsupported)?;
                let native = store
                    .binding(c, self.tenant.to_string(), p.registration())
                    .await?
                    .ok_or(Error::Forbidden)?;
                return device_access::execution::admission::native_local_session(native);
            }
            self.session(
                c,
                &rss_mdm_registration_service::device::endpoints::DaRegistration {
                    device: target.device().into(),
                    registration_id: target.registration(),
                    generation: target.generation(),
                },
            )
            .await
        })
    }
    fn binding_session<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        b: &'a device_access::Binding,
    ) -> Pending<'a, AccessLocalSession> {
        Box::pin(async move {
            if tenant.to_string() != self.tenant.to_string() || tenant != b.tenant {
                return Err(Error::Forbidden);
            }
            device_access::storage::lock_registration(
                c,
                tenant,
                &b.device,
                b.registration,
                b.registration_generation,
            )
            .await?;
            let session = if let Some(store) = &self.agent
                && let Some(delivery) = crate::delivery::for_binding_on(c, b).await?
            {
                let native = store
                    .binding(c, self.tenant.to_string(), delivery.registration)
                    .await?
                    .ok_or(Error::Forbidden)?;
                device_access::execution::admission::native_local_session(native)?
            } else {
                self.session(
                    c,
                    &rss_mdm_registration_service::device::endpoints::DaRegistration {
                        device: b.device.clone(),
                        registration_id: b.registration,
                        generation: b.registration_generation,
                    },
                )
                .await?
            };
            if b.account.as_ref() != Some(&session.account) {
                return Err(Error::Forbidden);
            }
            Ok(session)
        })
    }
}
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub publication: rss_mdm_policy_postgres::device_access::Publication,
}
impl Service {
    pub async fn publish_configuration(
        &self,
        p: &AuthorizedPrincipal,
        input: &Change,
        a: &RequestAudit,
    ) -> Result<rss_mdm_policy_postgres::device_access::Publication, Error> {
        use sha2::{Digest, Sha256};
        self.proof(p, a)?;
        p.session()?;
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?)
        );
        a.operation(
            input.operation_id,
            "da_configuration_publish",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write_admitted(&self.access_audit,a,(p,input,&digest,a),|ctx,c|Box::pin(async move{
            rss_identity_postgres::recheck_authenticated_session_on(c,ctx.0.session()?).await.map_err(|_|Error::Unauthorized)?;Ok(())
        }),|ctx,c|Box::pin(async move{
            let(p,input,digest,a)=ctx;
            rss_mdm_authorization_service::lock_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?;
            rss_mdm_authorization_service::snapshot_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?.require_all_devices(p,Permission::AccountWrite)?;
            let op=crate::operations::Operation::new(p,input.operation_id,digest)?;
            if let Some(old)=crate::operations::replay(c,&op).await?{return Ok(crate::service::Change{value:serde_json::from_str(&old).map_err(|_|Error::Corrupt)?,replay:true});}
            let tenant=Uuid::parse_str(p.tenant_id()).map_err(|_|Error::Malformed)?;
            if let rss_mdm_policy_postgres::device_access::Target::Device{device}=&input.publication.target {
                rss_mdm_registration_service::device::endpoints::lock_da_in(c,p.tenant_id(),device).await?;
                rss_mdm_registration_service::device::endpoints::current_da_in(c,p.tenant_id(),device).await?.ok_or(Error::NotFound)?;
            }
            let now=crate::platform_sso::store::now(c).await?;
            rss_mdm_policy_postgres::device_access::publish_on(c,tenant,&input.publication,input.expected_revision,serde_json::json!({"instance":p.instance_id(),"principal":p.principal_id()}),now).await.map_err(|e|match e{rss_mdm_policy_postgres::device_access::Error::Malformed=>Error::Malformed,rss_mdm_policy_postgres::device_access::Error::Conflict=>Error::Conflict,rss_mdm_policy_postgres::device_access::Error::Storage(_)=>Error::Storage})?;
            crate::operations::save(c,&op,&serde_json::to_string(&input.publication).map_err(|_|Error::Corrupt)?,a).await?;
            Ok(crate::service::Change{value:input.publication.clone(),replay:false})
        })).await
    }
}
