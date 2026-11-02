//! Resource assembly for DA. Hosts own connection, listener and worker lifetimes.
//! No MDM/Agent business service is required for independent DA registration or PSSO.
use rss_mdm_device_access_postgres as pg;
use rss_mdm_registration_service as registration;
use std::{num::NonZeroU32, sync::Arc};
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Business(#[from] pg::Error),
    #[error(transparent)]
    Registration(#[from] registration::Error),
    #[error(transparent)]
    ConfigurationTrust(#[from] rss_mdm_task_trust::Error),
}
pub struct Resources {
    pub report_limits: pg::reports::Limits,
    pub tenant: rss_request_context::TenantId,
    pub installation: Uuid,
    pub identity_instance: rss_identity_core::InstanceId,
    pub pool: sqlx::PgPool,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub proof_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub platform: Option<Arc<pg::platform_sso::Runtime>>,
    pub evidence: Arc<pg::evidence::Authorities>,
    pub broker_query: Option<&'static str>,
    pub agent_facts: Option<Arc<dyn registration::participants::agent::Store>>,
}
pub struct Registration {
    pub issuer: Arc<registration::certificate_issuance::DeviceIssuer>,
    pub clock: Arc<dyn registration::certificate_issuance::Clock>,
    pub signing: Arc<rss_mdm_task_trust::Signing>,
    pub configuration_lifetime: NonZeroU32,
}
pub struct Runtime {
    pub business: Arc<pg::Service>,
    pub admission: Arc<pg::configuration::Admission>,
    pub platform: Arc<pg::platform_sso::Context>,
    pub registrations: Option<Arc<registration::agent::da::RegistrationService>>,
    pub configurations: Option<Arc<rss_mdm_task_trust::configuration::ConfigurationService>>,
}
impl Runtime {
    pub fn assemble(r: Resources, registration: Option<Registration>) -> Result<Self, Error> {
        let store = Arc::new(registration::Store::for_device_access(r.pool));
        let business = Arc::new(pg::Service::new(pg::Assembly {
            report_limits: r.report_limits,
            cursor: r.cursor.clone(),
            tenant: r.tenant,
            instance: r.installation,
            store: store.clone(),
            audit: r.audit.clone(),
            access_audit: r.proof_audit.clone(),
            protection: r.protection.clone(),
        })?);
        let admission = Arc::new(pg::configuration::Admission {
            tenant: r.tenant,
            installation: r.installation,
            platform: r.platform.clone(),
            evidence: r.evidence,
            agent: r.agent_facts,
            broker_query: r.broker_query.unwrap_or(pg::broker_release_query!("SELECT NULL::uuid AS tenant_id,NULL::uuid AS installation,NULL::text AS device,NULL::uuid AS registration,NULL::bigint AS generation,NULL::text AS platform,NULL::jsonb AS capabilities,NULL::jsonb AS execution_context WHERE false")),
        });
        let platform = Arc::new(pg::platform_sso::Context {
            tenant: r.tenant,
            instance: r.identity_instance,
            installation: r.installation,
            access: store.clone(),
            audit_store: r.audit.clone(),
            protection: r.protection.clone(),
            access_admission: admission.clone(),
            platform_sso: r.platform,
        });
        let (registrations, configurations) = if let Some(inputs) = registration {
            let service = Arc::new(registration::agent::da::RegistrationService::new(
                registration::agent::da::Assembly {
                    cursor: r.cursor,
                    tenant: r.tenant,
                    store,
                    audit: r.audit.clone(),
                    issuer: inputs.issuer,
                    clock: inputs.clock,
                    protection: r.protection.clone(),
                },
            )?);
            let trust = Arc::new(rss_mdm_task_trust::Service::for_configurations(
                r.tenant,
                inputs.signing,
                r.protection,
                r.audit,
            )?);
            (
                Some(service),
                Some(Arc::new(
                    rss_mdm_task_trust::configuration::ConfigurationService::new(
                        trust,
                        inputs.configuration_lifetime,
                    )?,
                )),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            business,
            admission,
            platform,
            registrations,
            configurations,
        })
    }
}
