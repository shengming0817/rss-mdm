//! Current native credibility remains separate from the unverified application receipt.
use super::management::{authorize, fault, tenant};
use crate::{Error, Service, evidence::Authorities};
use rss_mdm_agent_wire::da;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_access::configuration::{Resolution, resolve};
use rss_mdm_policy_postgres::device_access as policy;
use rss_mdm_registration_service::device::endpoints;
use rss_mdm_task_trust::configuration::ConfigurationService;
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub publication: Option<policy::Publication>,
    pub managed_state: da::SourceState,
    pub evidence: Option<da::EvidenceLevel>,
    pub resolution: Resolution,
}
impl Service {
    pub async fn configuration_diagnostics(
        &self,
        signing: &ConfigurationService,
        authorities: &Authorities,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Diagnostics, Error> {
        self.read_with_session(p,(self,signing,authorities,p,device),|ctx,c|Box::pin(async move{
            let(service,signing,authorities,p,device)=*ctx;
            authorize(c,p,&policy::Target::Device{device:device.into()},false,false).await?;
            endpoints::lock_da_in(c,p.tenant_id(),device).await?;
            let anchor=endpoints::current_da_in(c,p.tenant_id(),device).await?.ok_or(Error::NotFound)?;
            policy::lock_publications_on(c,tenant(p)?).await.map_err(fault)?;
            let publication=policy::selected_on(c,tenant(p)?,device).await.map_err(fault)?;
            let now=crate::platform_sso::store::now(c).await?;
            let observed=authorities.native_on(c,service.tenant,service.service_id()?,&anchor,now).await;
            let previous:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.deployment_evidence WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND document->'configuration' IS NOT NULL AND document->'configuration'<>'null'::jsonb)").bind(p.tenant_id()).bind(anchor.registration_id).bind(anchor.generation).fetch_one(&mut *c).await.map_err(crate::database::db)?;
            let mut state=da::SourceState::Missing;let mut managed=None;let mut evidence=None;
            match observed {
                Ok(o)=>if let Some(proof)=o.configuration {
                    state=proof.state;
                    {
                        let artifact=signing.read_on(c,proof.artifact).await?;
                        let config=artifact.decode().map_err(|_|Error::Corrupt)?;
                        let identity=da::ReportIdentity{service_id:service.service_id()?,tenant:tenant(p)?,registration:anchor.registration_id,generation:anchor.generation};
                        let audience=config.permits(&identity,device);
                        if artifact.digest!=proof.digest||config.native.digest!=proof.native_digest||config.delivery!=proof.delivery||!audience||config.service_id!=service.service_id()?||config.tenant!=tenant(p)?||config.issued_at>now||config.expires_at<=now||publication.as_ref().is_none_or(|v|!v.enabled||v.id!=config.id||v.version!=config.version){state=da::SourceState::Invalid;}
                        else{evidence=Some(da::EvidenceLevel::Verified);if proof.delivery==da::DeliveryPermission::ManagedMandatory && proof.state==da::SourceState::Present {managed=Some(config);}}
                    }
                },
                Err(Error::Forbidden|Error::NotFound)=>state=if previous{da::SourceState::ReadFailed}else{da::SourceState::Missing},
                Err(Error::Conflict)=>state=da::SourceState::Conflict,
                Err(e)=>return Err(e),
            }
            // A previously observed mandatory source remains closed while its current proof is unavailable.
            let locked=managed.as_ref().map(|v|v.managed_fields.as_slice()).unwrap_or(&[]);
            if state==da::SourceState::Missing && previous {state=da::SourceState::ReadFailed;}
            let backend=publication.as_ref().filter(|v|v.enabled).map(|v|&v.configuration);
            if publication.as_ref().is_some_and(|v|!v.enabled){state=da::SourceState::Withdrawn;}
            let candidates:Vec<_>=managed.iter().collect();
            let resolution=resolve(backend,&candidates,state,locked)?;
            Ok(Diagnostics{publication,managed_state:state,evidence,resolution})
        })).await
    }
}
