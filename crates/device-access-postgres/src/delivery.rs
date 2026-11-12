//! Optional, current authorization for an Agent to carry DA business work.
//! The Agent remains an Agent principal. No device identifier establishes this authorization.
use crate::{Error, Service, database::db, operations::Operation};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::{
    DevicePrincipal,
    device::{
        ConsumerUse, RegistrationKind,
        endpoints::{self, DaRegistration},
    },
};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Agent {
    pub installation: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    pub operation_id: Uuid,
    pub da: DaRegistration,
    pub agent: Agent,
    pub expected_revision: i64,
    pub enabled: bool,
}
impl Authorization {
    pub fn step_up_context(
        &self,
        p: &AuthorizedPrincipal,
    ) -> Result<rss_identity_core::step_up::StepUpContext, Error> {
        use sha2::{Digest, Sha256};
        p.session()?;
        if self.operation_id.is_nil() || self.expected_revision < 0 {
            return Err(Error::Malformed);
        }
        rss_identity_core::step_up::StepUpContext::new(
            "da.agent_delivery".into(),
            Sha256::digest(
                serde_json::to_vec(&(p.tenant_id(), p.instance_id(), p.principal_id(), self))
                    .map_err(|_| Error::Malformed)?,
            )
            .into(),
        )
        .map_err(|_| Error::Malformed)
    }
}
/// A resolved business target keeps the actual authenticated peer separate from its DA anchor.
pub struct ResolvedDevice {
    tenant: TenantId,
    anchor: DaRegistration,
}
impl ResolvedDevice {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn device(&self) -> &rss_mdm_agent_wire::DeviceId {
        &self.anchor.device
    }
}
async fn current_agent(c: &mut PgConnection, tenant: &str, agent: &Agent) -> Result<(), Error> {
    if rss_mdm_registration_service::device::installation_in(StorageProfile::Mdm, c).await?
        != agent.installation
    {
        return Err(Error::Forbidden);
    }
    let r = endpoints::current_in(
        StorageProfile::Mdm,
        c,
        tenant,
        &agent.device,
        Channel::Agent,
    )
    .await?
    .ok_or(Error::Forbidden)?;
    if r.device != agent.device {
        return Err(Error::Forbidden);
    }
    Ok(())
}
async fn current_da(c: &mut PgConnection, tenant: &str, da: &DaRegistration) -> Result<(), Error> {
    endpoints::lock_da_in(c, tenant, &da.device).await?;
    if endpoints::current_da_in(c, tenant, &da.device)
        .await?
        .as_ref()
        != Some(da)
    {
        return Err(Error::Forbidden);
    }
    Ok(())
}
/// Lock the optional physical transport before the DA anchor. A changed mapping is retried;
/// no transaction acquires a newly discovered Agent fence while holding a DA fence.
pub async fn lock_da_target(
    c: &mut PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    extra: Option<&Agent>,
) -> Result<(), Error> {
    lock_da_targets(c, tenant, &[device.to_owned()], extra).await
}
pub(crate) async fn lock_da_targets(
    c: &mut PgConnection,
    tenant: &str,
    devices: &[rss_mdm_agent_wire::DeviceId],
    extra: Option<&Agent>,
) -> Result<(), Error> {
    let before:Vec<(Uuid,i64)>=sqlx::query_as("SELECT agent_device,revision FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=ANY($2) AND enabled ORDER BY agent_device").bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(&mut *c).await.map_err(db)?;
    let mut agents = std::collections::BTreeSet::new();
    for (agent, _) in &before {
        agents.insert(crate::database::device_id(*agent).map_err(db)?);
    }
    if let Some(agent) = extra {
        agents.insert(agent.device);
    }
    for agent in agents {
        endpoints::lock_in(StorageProfile::Mdm, c, tenant, &agent, Channel::Agent).await?;
    }
    for device in devices.iter().collect::<std::collections::BTreeSet<_>>() {
        endpoints::lock_da_in(c, tenant, device).await?;
    }
    let after:Vec<(Uuid,i64)>=sqlx::query_as("SELECT agent_device,revision FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=ANY($2) AND enabled ORDER BY agent_device").bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.map_err(db)?;
    if before != after {
        return Err(Error::ReadConflict);
    }
    Ok(())
}

pub async fn resolve_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
) -> Result<ResolvedDevice, Error> {
    let tenant = p.tenant().to_string();
    let anchor = if p.kind() == RegistrationKind::DaDevice && p.profile() == StorageProfile::Da {
        lock_da_target(c, &tenant, p.device(), None).await?;
        rss_mdm_registration_service::device::require_use_in(c, p, ConsumerUse::DaConfiguration)
            .await?;
        DaRegistration {
            device: *p.device(),
        }
    } else if p.kind() == RegistrationKind::Agent && p.profile() == StorageProfile::Mdm {
        let row=sqlx::query("SELECT da_device FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND agent_device=$2 AND agent_installation=$3 AND enabled")
            .bind(&tenant).bind(p.device().into_uuid()).bind(p.installation()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Forbidden)?;
        let da = DaRegistration {
            device: row
                .try_get::<Uuid, _>("da_device")
                .and_then(crate::database::device_id)
                .map_err(db)?,
        };
        rss_mdm_registration_service::device::require_use_in(c, p, ConsumerUse::AgentTask).await?;
        current_da(c, &tenant, &da).await?;
        let live:bool=sqlx::query_scalar("SELECT enabled FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=$2 AND agent_device=$3 AND agent_installation=$4")
            .bind(&tenant).bind(da.device.into_uuid()).bind(p.device().into_uuid()).bind(p.installation()).fetch_optional(&mut *c).await.map_err(db)?.unwrap_or(false);
        if !live {
            return Err(Error::Forbidden);
        }
        da
    } else {
        return Err(Error::Forbidden);
    };
    Ok(ResolvedDevice {
        tenant: p.tenant(),
        anchor,
    })
}
pub async fn for_da_on(
    c: &mut PgConnection,
    tenant: Uuid,
    da: &DaRegistration,
) -> Result<Option<Agent>, Error> {
    lock_da_target(c, &tenant.to_string(), &da.device, None).await?;
    current_da(c, &tenant.to_string(), da).await?;
    let row=sqlx::query("SELECT agent_installation,agent_device FROM rss_da.agent_delivery WHERE tenant_id=$1 AND da_device=$2 AND enabled")
        .bind(tenant).bind(da.device.into_uuid()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(r) = row else {
        return Ok(None);
    };
    let agent = Agent {
        installation: r.try_get("agent_installation").map_err(db)?,
        device: r
            .try_get::<Uuid, _>("agent_device")
            .and_then(crate::database::device_id)
            .map_err(db)?,
    };
    match current_agent(c, &tenant.to_string(), &agent).await {
        Ok(()) => Ok(Some(agent)),
        Err(Error::Forbidden) => Ok(None),
        Err(e) => Err(e),
    }
}
impl Service {
    pub async fn authorize_agent_delivery(
        &self,
        p: &AuthorizedPrincipal,
        input: &Authorization,
        proof: &rss_mdm_agent_wire::runtime::Secret,
        a: &RequestAudit,
    ) -> Result<i64, Error> {
        use sha2::{Digest, Sha256};
        self.proof(p, a)?;
        let context = input.step_up_context(p)?;
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?)
        );
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::AgentDelivery,
            input.operation_id,
            "da_agent_delivery",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        if let Some(value) = self.delivery_replay(p, input.operation_id, &digest).await? {
            a.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            return Ok(value);
        }

        let result=self.write_admitted(&self.access_audit,a,(p,input,proof,&context,&digest,a),|ctx,c|Box::pin(async move{
            rss_identity_postgres::consume_step_up_on(c,ctx.0.session()?,ctx.3,ctx.2.expose()).await.map_err(|_|Error::Unauthorized)?;Ok(())
        }),|ctx,c|Box::pin(async move{
            let(p,input,_,_,digest,a)=ctx;
            rss_mdm_authorization_service::lock_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?;
            rss_mdm_authorization_service::snapshot_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?.require_all_devices(p,Permission::AccountWrite)?;
            lock_da_target(c,p.tenant_id(),&input.da.device,Some(&input.agent)).await?;
            if input.enabled {
                current_da(c,p.tenant_id(),&input.da).await?;
                current_agent(c,p.tenant_id(),&input.agent).await?;
            } else {
                let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=$2 AND agent_installation=$3 AND agent_device=$4)")
                    .bind(p.tenant_id()).bind(input.da.device.into_uuid()).bind(input.agent.installation).bind(input.agent.device.into_uuid()).fetch_one(&mut *c).await.map_err(db)?;
                if !exact {return Err(Error::Conflict);}
            }
            let op=Operation::new(p,input.operation_id,digest)?;
            if crate::operations::replay(c,&op).await?.is_some(){return Err(Error::Conflict);}
            let rev:Option<i64>=sqlx::query_scalar("SELECT revision FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid AND da_device=$2 FOR UPDATE").bind(p.tenant_id()).bind(input.da.device.into_uuid()).fetch_optional(&mut *c).await.map_err(db)?;
            if rev.unwrap_or(0)!=input.expected_revision{return Err(Error::Conflict);}
            let revision=input.expected_revision.checked_add(1).ok_or(Error::Capacity)?;
            sqlx::query("INSERT INTO rss_da.agent_delivery(tenant_id,da_device,agent_installation,agent_device,enabled,revision) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,da_device) DO UPDATE SET agent_installation=excluded.agent_installation,agent_device=excluded.agent_device,enabled=excluded.enabled,revision=excluded.revision")
                .bind(p.tenant_id()).bind(input.da.device.into_uuid()).bind(input.agent.installation).bind(input.agent.device.into_uuid()).bind(input.enabled).bind(revision).execute(&mut *c).await.map_err(db)?;

            crate::operations::save(c,&op,&revision.to_string(),a).await?;
            Ok(crate::service::Change{value:revision,replay:false})
        })).await;
        match result {
            Ok(value) => Ok(value),
            Err(error) => match self.delivery_replay(p, input.operation_id, &digest).await {
                Ok(Some(value)) => {
                    a.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                    Ok(value)
                }
                _ => Err(error),
            },
        }
    }
    async fn delivery_replay(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        digest: &str,
    ) -> Result<Option<i64>, Error> {
        self.read_with_session(p, (p, id, digest), |ctx, c| {
            Box::pin(async move {
                let (p, id, digest) = *ctx;
                rss_mdm_authorization_service::lock_on(
                    p.authority_profile(),
                    c,
                    p.tenant_id(),
                    p.instance_id(),
                )
                .await?;
                rss_mdm_authorization_service::snapshot_on(
                    p.authority_profile(),
                    c,
                    p.tenant_id(),
                    p.instance_id(),
                )
                .await?
                .require_all_devices(p, Permission::AccountWrite)?;
                crate::operations::read(c, &Operation::new(p, id, digest)?)
                    .await?
                    .map(|v| serde_json::from_str(&v).map_err(|_| Error::Corrupt))
                    .transpose()
            })
        })
        .await
    }
}

pub async fn for_binding_on(
    c: &mut PgConnection,
    b: &crate::device_access::Binding,
) -> Result<Option<Agent>, Error> {
    for_da_on(c, b.tenant, &DaRegistration { device: b.device }).await
}

impl Service {
    /// Original revision receipt; session admission does not consume a step-up proof.
    pub async fn delivery_operation(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<i64, Error> {
        self.read_with_session(p,(p,id),|ctx,c|Box::pin(async move{
            let(p,id)=*ctx;
            rss_mdm_authorization_service::lock_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?;
            rss_mdm_authorization_service::snapshot_on(p.authority_profile(),c,p.tenant_id(),p.instance_id()).await?.require_all_devices(p,Permission::AccountWrite)?;
            let raw:Option<String>=sqlx::query_scalar("SELECT result FROM rss_da.operations WHERE tenant_id=$1::uuid AND instance=$2::uuid AND actor=$3::uuid AND operation_id=$4")
                .bind(p.tenant_id()).bind(p.instance_id()).bind(p.principal_id()).bind(id).fetch_optional(c).await.map_err(db)?;
            raw.ok_or(Error::NotFound)?.parse().map_err(|_|Error::NotFound)
        })).await
    }
}
