//! Publication authorization, exact operation recovery and current-device distribution.
use super::Change;
use crate::{Error, Service, operations::Operation, service::Change as Changed};
use rss_mdm_agent_wire::{da, runtime::Secret};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy_postgres::device_access::{self as policy, Publication, Target};
use rss_mdm_registration_service::{DevicePrincipal, device::endpoints};
use rss_mdm_task_trust::configuration::ConfigurationService;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;
pub(super) fn fault(e: policy::Error) -> Error {
    match e {
        policy::Error::Malformed => Error::Malformed,
        policy::Error::Conflict => Error::Conflict,
        policy::Error::Storage(_) => Error::Storage,
    }
}
pub(super) fn tenant(p: &AuthorizedPrincipal) -> Result<Uuid, Error> {
    Uuid::parse_str(p.tenant_id()).map_err(|_| Error::Malformed)
}
fn digest(input: &impl Serialize) -> Result<String, Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?)
    ))
}
pub(super) async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    target: &Target,
    write: bool,
    accounts: bool,
) -> Result<(), Error> {
    rss_mdm_authorization_service::lock_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    let grants = rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    let device = match target {
        Target::TenantDefault => None,
        Target::Device { device } => Some(device.as_str()),
    };
    grants
        .require(
            p,
            match (device, write) {
                (None, true) => Permission::RegistrationConfigurationWrite,
                (None, false) => Permission::RegistrationConfigurationRead,
                (Some(_), true) => Permission::ConfigurationWrite,
                (Some(_), false) => Permission::OperationRead,
            },
            device,
        )
        .map_err(|_| Error::Forbidden)?;
    if accounts {
        if let Some(device) = device {
            grants
                .require(p, Permission::AccountWrite, Some(device))
                .map_err(|_| Error::Forbidden)?;
        } else {
            grants
                .require_all_devices(p, Permission::AccountWrite)
                .map_err(|_| Error::Forbidden)?;
        }
    }
    Ok(())
}
impl Change {
    pub fn step_up_context(
        &self,
        p: &AuthorizedPrincipal,
    ) -> Result<rss_identity_core::step_up::StepUpContext, Error> {
        p.session()?;
        rss_identity_core::step_up::StepUpContext::new(
            "da.configuration.authority".into(),
            Sha256::digest(
                serde_json::to_vec(&(p.tenant_id(), p.instance_id(), p.principal_id(), self))
                    .map_err(|_| Error::Malformed)?,
            )
            .into(),
        )
        .map_err(|_| Error::Malformed)
    }
}
impl Service {
    pub async fn publish_configuration(
        &self,
        p: &AuthorizedPrincipal,
        input: &Change,
        proof: Option<&Secret>,
        a: &RequestAudit,
    ) -> Result<Publication, Error> {
        self.proof(p, a)?;
        p.session()?;
        let hash = digest(input)?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DaPublication,
            input.operation_id,
            "da_configuration_publish",
            AuditIntent::Management,
        );
        // Check the receipt before consuming one-use step-up, including recovery after unknown commit.
        if let Some(value) = self
            .read_with_session(p, (p, input, &hash), |ctx, c| {
                Box::pin(async move {
                    let (p, input, hash) = *ctx;
                    authorize(c, p, &input.publication.target, true, false).await?;
                    crate::operations::read(c, &Operation::new(p, input.operation_id, hash)?)
                        .await?
                        .map(|v| serde_json::from_str(&v).map_err(|_| Error::Corrupt))
                        .transpose()
                })
            })
            .await?
        {
            a.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            return Ok(value);
        }
        let context = input.step_up_context(p)?;
        self.write_admitted(&self.access_audit,a,(p,input,proof,&hash,&context,a),|ctx,c|Box::pin(async move{
            rss_identity_postgres::recheck_authenticated_session_on(c,ctx.0.session()?).await.map_err(|_|Error::Unauthorized)?;
            // Step-up is optional for ordinary configuration; when supplied its one-use consumption
            // precedes product locks and rolls back with the complete operation.
            if let Some(proof)=ctx.2 {rss_identity_postgres::consume_step_up_on(c,ctx.0.session()?,ctx.4,proof.expose()).await.map_err(|_|Error::Unauthorized)?;}
            Ok(())
        }),|ctx,c|Box::pin(async move{
            let(p,input,proof,hash,_,a)=ctx; let tenant=tenant(p)?;
            authorize(c,p,&input.publication.target,true,false).await?;
            if let Target::Device{device}=&input.publication.target {endpoints::lock_da_in(c,p.tenant_id(),device).await?;}
            policy::lock_publications_on(c,tenant).await.map_err(fault)?;
            let previous=policy::get_on(c,tenant,input.publication.id).await.map_err(fault)?;
            if let Some(old)=&previous {authorize(c,p,&old.target,true,false).await?;if old.target!=input.publication.target{return Err(Error::Conflict);}}
            let account_change=previous.as_ref().is_none_or(|old|old.enabled!=input.publication.enabled || old.configuration.role!=input.publication.configuration.role || old.configuration.self_enrollment!=input.publication.configuration.self_enrollment || old.configuration.enabled!=input.publication.configuration.enabled);
            if account_change {authorize(c,p,&input.publication.target,true,true).await?;}
            let managed_change=previous.as_ref().map(|v|&v.managed_fields)!=Some(&input.publication.managed_fields)
                && (previous.as_ref().is_some_and(|v|!v.managed_fields.is_empty())||!input.publication.managed_fields.is_empty());
            let managed_withdrawal=previous.as_ref().is_some_and(|v|v.enabled!=input.publication.enabled && (!v.managed_fields.is_empty()||!input.publication.managed_fields.is_empty()));
            if (managed_change||managed_withdrawal)&&proof.is_none(){return Err(Error::Unauthorized);}
            let op=Operation::new(p,input.operation_id,hash)?;
            if crate::operations::replay(c,&op).await?.is_some(){return Err(Error::Conflict);}
            if let Target::Device{device}=&input.publication.target {endpoints::lock_da_in(c,p.tenant_id(),device).await?;endpoints::current_da_in(c,p.tenant_id(),device).await?.ok_or(Error::NotFound)?;}
            let now=crate::platform_sso::store::now(c).await?;
            policy::publish_on(c,tenant,&input.publication,input.expected_revision,serde_json::json!({"instance":p.instance_id(),"principal":p.principal_id()}),now).await.map_err(fault)?;
            crate::operations::save(c,&op,&serde_json::to_string(&input.publication).map_err(|_|Error::Corrupt)?,a).await?;
            Ok(Changed{value:input.publication.clone(),replay:false})
        })).await
    }
    pub async fn export_configuration(
        &self,
        signing: &ConfigurationService,
        p: &AuthorizedPrincipal,
        input: &da::Export,
        platform: Option<&crate::platform_sso::Runtime>,
        a: &RequestAudit,
    ) -> Result<da::SignedConfiguration, Error> {
        self.proof(p, a)?;
        p.session()?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::DaConfigurationExport,
            input.operation_id,
            "da_configuration_export",
            AuditIntent::Management,
        );
        self.write_admitted(
            &self.access_audit,
            a,
            (self, signing, p, input, platform),
            |ctx, c| {
                Box::pin(async move {
                    rss_identity_postgres::recheck_authenticated_session_on(c, ctx.2.session()?)
                        .await
                        .map_err(|_| Error::Unauthorized)?;
                    Ok(())
                })
            },
            |ctx, c| {
                Box::pin(async move {
                    let (service, signing, p, input, platform) = *ctx;
                    if let Some(value) = signing.replay_on(c, p, input).await? {
                        return Ok(Changed {
                            value,
                            replay: true,
                        });
                    }
                    let tenant = tenant(p)?;
                    let hint = policy::get_on(c, tenant, input.policy)
                        .await
                        .map_err(fault)?
                        .ok_or(Error::NotFound)?;
                    authorize(c, p, &hint.target, true, false).await?;
                    if let Target::Device { device } = &hint.target {
                        endpoints::lock_da_in(c, p.tenant_id(), device).await?;
                    }
                    policy::lock_publications_on(c, tenant)
                        .await
                        .map_err(fault)?;
                    let publication = policy::get_on(c, tenant, input.policy)
                        .await
                        .map_err(fault)?
                        .ok_or(Error::NotFound)?;
                    if publication.target != hint.target
                        || !publication.enabled
                        || publication.version != input.version
                    {
                        return Err(Error::Conflict);
                    }
                    let audience = match &publication.target {
                        Target::TenantDefault => da::Audience::Tenant,
                        Target::Device { device } => {
                            endpoints::lock_da_in(c, p.tenant_id(), device).await?;
                            let r = endpoints::current_da_in(c, p.tenant_id(), device)
                                .await?
                                .ok_or(Error::NotFound)?;
                            da::Audience::Device {
                                device: device.clone(),
                                registration: r.registration_id,
                                generation: r.generation as u64,
                            }
                        }
                    };
                    let managed_fields =
                        if input.delivery == da::DeliveryPermission::ManagedMandatory {
                            if publication.managed_fields.is_empty() {
                                return Err(Error::Forbidden);
                            }
                            publication.managed_fields.clone()
                        } else {
                            Vec::new()
                        };
                    let mut bindings = Vec::new();
                    let mut mac = None;
                    if let Some(login) = &publication.configuration.mac {
                        let platform = platform.ok_or(Error::Unsupported)?;
                        let mut profile = platform.profile(login)?;
                        rss_mdm_apple_mdm::da::bind(&mut profile)
                            .map_err(|_| Error::Configuration)?;
                        let origin = platform
                            .endpoints
                            .base
                            .split("/api/")
                            .next()
                            .ok_or(Error::Configuration)?
                            .to_owned();
                        mac = Some(da::MacNativeInput {
                            deployment: platform.configuration.clone(),
                            origin,
                        });
                        bindings.push(da::NativeBinding {
                            schema: "Configuration".into(),
                            identifier: profile.identifier,
                            uuid: profile.uuid,
                            version: 1,
                        });
                        for payload in profile.payloads {
                            bindings.push(da::NativeBinding {
                                schema: payload.schema,
                                identifier: payload.identifier,
                                uuid: payload.uuid,
                                version: 1,
                            });
                        }
                    }
                    let native =
                        da::NativeExpectation::new(&publication.configuration, bindings, mac)
                            .map_err(|_| Error::Malformed)?;
                    let config = da::Configuration {
                        service_id: service.service_id()?,
                        tenant,
                        id: publication.id,
                        version: publication.version,
                        revision: publication.revision as u64,
                        trust_revision: 1,
                        operation_id: input.operation_id,
                        audience,
                        delivery: input.delivery,
                        managed_fields,
                        issued_at: 1,
                        expires_at: 2,
                        content: publication.configuration,
                        native,
                    };
                    let value = signing.issue_on(c, p, input, config).await?;
                    Ok(Changed {
                        value,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
    pub async fn configuration_operation(
        &self,
        signing: &ConfigurationService,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<da::SignedConfiguration, Error> {
        self.read_with_session(p, (signing, p, id), |ctx, c| {
            Box::pin(async move { Ok(ctx.0.operation_on(c, ctx.1, ctx.2).await?) })
        })
        .await
    }
    pub async fn retrieve_configuration(
        &self,
        signing: &ConfigurationService,
        p: &DevicePrincipal,
        id: Option<Uuid>,
        a: &RequestAudit,
    ) -> Result<CurrentConfiguration, Error> {
        a.identify_device(p.registration());
        self.write(a, (self, signing, p, id), |ctx, c| {
            Box::pin(async move {
                let (service, signing, p, id) = *ctx;
                crate::reports::admit(c, service, p, None).await?;
                let tenant =
                    Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?;
                policy::lock_publications_on(c, tenant)
                    .await
                    .map_err(fault)?;
                let publication = policy::selected_on(c, tenant, p.device())
                    .await
                    .map_err(fault)?;
                let Some(publication) = publication else {
                    return Ok(Changed {
                        value: CurrentConfiguration {
                            state: da::SourceState::Missing,
                            publication: None,
                            artifact: None,
                        },
                        replay: false,
                    });
                };
                if !publication.enabled {
                    return Ok(Changed {
                        value: CurrentConfiguration {
                            state: da::SourceState::Withdrawn,
                            publication: Some(publication),
                            artifact: None,
                        },
                        replay: false,
                    });
                }
                let artifact = match id {
                    Some(id) => Some(signing.read_on(c, id).await?),
                    None => {
                        signing
                            .current_on(c, publication.id, publication.revision)
                            .await?
                    }
                };
                if let Some(value) = &artifact {
                    let config = signing.admit_device_on(c, p, value).await?;
                    if config.id != publication.id
                        || config.version != publication.version
                        || config.delivery != da::DeliveryPermission::Da
                    {
                        return Err(Error::Conflict);
                    }
                }
                Ok(Changed {
                    value: CurrentConfiguration {
                        state: if artifact.is_some() {
                            da::SourceState::Present
                        } else {
                            da::SourceState::Missing
                        },
                        publication: Some(publication),
                        artifact,
                    },
                    replay: false,
                })
            })
        })
        .await
    }
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentConfiguration {
    pub state: da::SourceState,
    pub publication: Option<Publication>,
    pub artifact: Option<da::SignedConfiguration>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationPage {
    pub items: Vec<Publication>,
    pub next_cursor: Option<String>,
}

fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Malformed,
    }
}
pub static DIRECTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "da_configurations",
    default_limit: 64,
    max_limit: 100,
    order: "id asc",
    context: &["device"],
};
pub static HISTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "da_configuration_history",
    default_limit: 64,
    max_limit: 100,
    order: "revision desc",
    context: &[],
};
impl Service {
    /// Recover an immutable publication receipt for its original authenticated actor.
    pub async fn publication_operation(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<Publication, Error> {
        self.read_with_session(p,(p,id),|ctx,c|Box::pin(async move{
            let(p,id)=*ctx;
            let raw:Option<String>=sqlx::query_scalar("SELECT result FROM rss_da.operations WHERE tenant_id=$1::uuid AND instance=$2::uuid AND actor=$3::uuid AND operation_id=$4")
                .bind(p.tenant_id()).bind(p.instance_id()).bind(p.principal_id()).bind(id).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
            let value:Publication=serde_json::from_str(&raw.ok_or(Error::NotFound)?).map_err(|_|Error::NotFound)?;
            authorize(c,p,&value.target,false,false).await?;
            Ok(value)
        })).await
    }
    pub async fn configuration(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<Publication, Error> {
        self.read_with_session(p, (p, id), |ctx, c| {
            Box::pin(async move {
                let (p, id) = *ctx;
                let value = policy::get_on(c, tenant(p)?, id)
                    .await
                    .map_err(fault)?
                    .ok_or(Error::NotFound)?;
                authorize(c, p, &value.target, false, false).await?;
                Ok(value)
            })
        })
        .await
    }
    pub async fn configurations(
        &self,
        p: &AuthorizedPrincipal,
        device: Option<&str>,
        input: &DirectoryQuery,
    ) -> Result<ConfigurationPage, Error> {
        let q = DIRECTORY
            .page(input.limit, input.cursor.clone(), 4096)
            .map_err(query_error)?;
        self.read_with_session(p, (self, p, device, input, &q), |ctx, c| {
            Box::pin(async move {
                let (service, p, device, input, q) = *ctx;
                let target = device
                    .map(|device| Target::Device {
                        device: device.into(),
                    })
                    .unwrap_or(Target::TenantDefault);
                authorize(c, p, &target, false, false).await?;
                let grants = rss_mdm_authorization_service::snapshot_on(
                    p.authority_profile(),
                    c,
                    p.tenant_id(),
                    p.instance_id(),
                )
                .await?;
                if device.is_none() {
                    grants.require_all_devices(p, Permission::OperationRead)?;
                }
                policy::lock_publications_on(c, tenant(p)?)
                    .await
                    .map_err(fault)?;
                let binding = rss_mdm_query::cursor::fingerprint(&(
                    "da.configuration.directory",
                    p.tenant_id(),
                    p.instance_id(),
                    p.principal_id(),
                    grants.query_binding(p)?,
                    device,
                    q.limit(),
                ))
                .map_err(query_error)?;
                let after: Option<Uuid> = input
                    .cursor
                    .as_ref()
                    .map(|v| service.cursor.decode_bounded(v, &binding, 4096))
                    .transpose()
                    .map_err(query_error)?;
                let mut items =
                    policy::directory_on(c, tenant(p)?, device, after, q.limit() as i64 + 1)
                        .await
                        .map_err(fault)?;
                let more = items.len() > q.limit();
                items.truncate(q.limit());
                let next_cursor = if more {
                    Some(
                        service
                            .cursor
                            .encode_bounded(&binding, &items.last().ok_or(Error::Corrupt)?.id, 4096)
                            .map_err(query_error)?,
                    )
                } else {
                    None
                };
                Ok(ConfigurationPage { items, next_cursor })
            })
        })
        .await
    }
    pub async fn configuration_history(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: &DirectoryQuery,
    ) -> Result<ConfigurationPage, Error> {
        let q = HISTORY
            .page(input.limit, input.cursor.clone(), 4096)
            .map_err(query_error)?;
        self.read_with_session(p, (self, p, id, input, &q), |ctx, c| {
            Box::pin(async move {
                let (service, p, id, input, q) = *ctx;
                let current = policy::get_on(c, tenant(p)?, id)
                    .await
                    .map_err(fault)?
                    .ok_or(Error::NotFound)?;
                authorize(c, p, &current.target, false, false).await?;
                let grants = rss_mdm_authorization_service::snapshot_on(
                    p.authority_profile(),
                    c,
                    p.tenant_id(),
                    p.instance_id(),
                )
                .await?;
                let binding = rss_mdm_query::cursor::fingerprint(&(
                    "da.configuration.history",
                    p.tenant_id(),
                    p.instance_id(),
                    p.principal_id(),
                    grants.query_binding(p)?,
                    id,
                    q.limit(),
                ))
                .map_err(query_error)?;
                let after: Option<i64> = input
                    .cursor
                    .as_ref()
                    .map(|v| service.cursor.decode_bounded(v, &binding, 4096))
                    .transpose()
                    .map_err(query_error)?;
                let mut items = policy::history_on(c, tenant(p)?, id, after, q.limit() as i64 + 1)
                    .await
                    .map_err(fault)?;
                let more = items.len() > q.limit();
                items.truncate(q.limit());
                let next_cursor = if more {
                    Some(
                        service
                            .cursor
                            .encode_bounded(
                                &binding,
                                &items.last().ok_or(Error::Corrupt)?.revision,
                                4096,
                            )
                            .map_err(query_error)?,
                    )
                } else {
                    None
                };
                Ok(ConfigurationPage { items, next_cursor })
            })
        })
        .await
    }
}
