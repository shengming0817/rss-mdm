//! Typed DA exports and their immutable receipts, settled with audit and key retention.
//! ref: ring src/ec/curve25519/ed25519/signing.rs@2723abbca9e83347d82b056d5b239c6604f786df.
use crate::{Error, Service, Use, trust};
use rss_mdm_agent_wire::da::{Audience, Configuration, Export, SignedConfiguration};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::{PgConnection, Row};
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use uuid::Uuid;

pub struct ConfigurationService {
    trust: Arc<Service>,
    max_lifetime: NonZeroU32,
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
impl ConfigurationService {
    /// Deployment must select a verification lifetime explicitly; there is no implicit policy.
    pub fn new(trust: Arc<Service>, max_lifetime: NonZeroU32) -> Result<Self, Error> {
        if trust.signing.usage != Use::DaConfiguration {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            trust,
            max_lifetime,
        })
    }
    pub fn trust(&self) -> &Arc<Service> {
        &self.trust
    }
    async fn authorize(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        config: Option<&Configuration>,
    ) -> Result<(), Error> {
        let profile = self.trust.signing.profile;
        if p.profile() != profile || p.tenant_id() != self.trust.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        rss_mdm_authorization_service::lock_shared_on(
            p.authority_profile(),
            c,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let scope = config.and_then(|v| match &v.audience {
            Audience::Tenant => None,
            Audience::Device { device, .. } => Some(device.as_str()),
        });
        rss_mdm_authorization_service::snapshot_on(
            p.authority_profile(),
            c,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?
        .require(
            p,
            if scope.is_some() {
                Permission::ConfigurationWrite
            } else {
                Permission::RegistrationConfigurationWrite
            },
            scope,
        )?;
        Ok(())
    }
    pub async fn export(
        &self,
        p: &AuthorizedPrincipal,
        input: &Export,
        a: &RequestAudit,
    ) -> Result<SignedConfiguration, Error> {
        if input.operation_id.is_nil()
            || a.profile() != self.trust.signing.profile
            || a.tenant() != self.trust.tenant.to_string()
        {
            return Err(Error::Malformed);
        }
        p.bind_audit(a)?;
        a.operation(
            input.operation_id,
            "da_configuration_export",
            AuditIntent::Management,
        );
        a.require_final_request();
        let request = serde_json::to_value(input).map_err(|_| Error::Malformed)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.trust.audit.write(self.trust.tenant,&budget.source_control(),(self,p,input,a,request),|(service,p,input,a,request),tx|Box::pin(async move {
            let mut context=(*service,*p,*input,request);
            let (signed,replay)=tx.with_connection_context(&mut context,|(service,p,input,request),c|Box::pin(async move {
                service.authorize(c,p,Some(&input.configuration)).await?;
                let profile=service.trust.signing.profile; let tenant=service.trust.tenant;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3129))").bind(format!("{tenant}:{}",input.operation_id)).execute(&mut *c).await.map_err(db)?;
                if let Some(row)=sqlx::query(crate::storage_profile::sql(profile,Use::DaConfiguration).configuration_receipt).bind(tenant.to_string()).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)? {
                    if row.try_get::<String,_>("actor").map_err(db)?!=p.principal_id() || row.try_get::<String,_>("instance").map_err(db)?!=p.instance_id() || row.try_get::<serde_json::Value,_>("request").map_err(db)?!=**request { return Err(Error::Conflict); }
                    return Ok((serde_json::from_value(row.try_get("result").map_err(db)?).map_err(|_| Error::Conflict)?,true));
                }
                let config=&input.configuration;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3130))").bind(format!("{tenant}:{}",config.id)).execute(&mut *c).await.map_err(db)?;
                if let Some(previous)=sqlx::query_scalar::<_,serde_json::Value>(crate::storage_profile::sql(profile,Use::DaConfiguration).configuration_latest).bind(tenant.to_string()).bind(config.id).fetch_optional(&mut *c).await.map_err(db)? {
                    let previous:SignedConfiguration=serde_json::from_value(previous).map_err(|_| Error::Conflict)?;
                    // Replacing a configuration requires authority over its existing audience
                    // as well as the requested audience; an ID cannot escape its owner scope.
                    service.authorize(c,p,Some(&previous.configuration)).await?;
                    if config.revision<=previous.configuration.revision || config.epoch<previous.configuration.epoch { return Err(Error::Conflict); }
                }

                let current=trust::current(profile,Use::DaConfiguration,c,tenant).await?;
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(db)?;
                if config.service_id!=current.service_id || config.tenant!=current.tenant || config.issued_at>now || config.issued_at<now.saturating_sub(300) || config.expires_at<=now || config.expires_at.checked_sub(config.issued_at).is_none_or(|lifetime| lifetime <= 0 || lifetime > i64::from(service.max_lifetime.get())) { return Err(Error::Malformed); }
                let signer=service.trust.signing.signer.as_ref().ok_or(Error::Unsupported)?;
                trust::require_active_key(profile,Use::DaConfiguration,c,tenant,signer.key_id()).await?;
                let signed=signer.sign_configuration(config.clone())?;
                trust::retain_until(profile,Use::DaConfiguration,c,tenant,signer.key_id(),config.expires_at).await?;
                sqlx::query(crate::storage_profile::sql(profile,Use::DaConfiguration).configuration_save)
                    .bind(tenant.to_string()).bind(input.operation_id).bind(p.principal_id()).bind(p.instance_id()).bind(&**request)
                    .bind(config.id).bind(i64::try_from(config.revision).map_err(|_| Error::Malformed)?).bind(i64::try_from(config.epoch).map_err(|_| Error::Malformed)?)
                    .bind(serde_json::to_value(&signed).map_err(|_| Error::Malformed)?).execute(c).await.map_err(|e| if e.as_database_error().is_some_and(|e| e.is_unique_violation()) {Error::Conflict} else {db(e)})?;
                Ok::<_,Error>((signed,false))
            })).await?;
            if !replay { let fact=Fact::business(a,&format!("da-configuration:{}",input.operation_id),200,"success",None).map_err(|_| Error::Malformed)?; service.trust.audit.append(tx,&fact).await?; }
            else { a.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            a.mark_commit_started(); Ok(signed)
        })).await;
        crate::service::settle(result, a, true)
    }
    pub async fn operation(
        &self,
        p: &AuthorizedPrincipal,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<SignedConfiguration, Error> {
        p.bind_audit(a)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .trust
            .audit
            .read(
                self.trust.tenant,
                &budget.control(),
                (self, p, operation),
                |(service, p, op), tx| {
                    Box::pin(async move {
                        let mut context = (*service, *p, *op);
                        tx.with_connection_context(&mut context, |(service, p, op), c| {
                            Box::pin(async move {
                                let row = sqlx::query(
                                    crate::storage_profile::sql(
                                        service.trust.signing.profile,
                                        Use::DaConfiguration,
                                    )
                                    .configuration_receipt,
                                )
                                .bind(service.trust.tenant.to_string())
                                .bind(*op)
                                .fetch_optional(&mut *c)
                                .await
                                .map_err(db)?
                                .ok_or(Error::NotFound)?;
                                let signed: SignedConfiguration =
                                    serde_json::from_value(row.try_get("result").map_err(db)?)
                                        .map_err(|_| Error::Conflict)?;
                                service.authorize(c, p, Some(&signed.configuration)).await?;
                                Ok(signed)
                            })
                        })
                        .await
                    })
                },
            )
            .await;
        crate::service::settle(result, a, false)
    }
    /// Device retrieval can only return an authorized receipt, never sign a device-supplied payload.
    pub async fn retrieve(
        &self,
        p: &DevicePrincipal,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<SignedConfiguration, Error> {
        self.trust.require_device(p, a)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .trust
            .audit
            .write(
                self.trust.tenant,
                &budget.source_control(),
                (self, p, operation),
                |(service, p, op), tx| {
                    Box::pin(async move {
                        let mut context = (*service, *p, *op);
                        tx.with_connection_context(&mut context, |(service, p, op), c| {
                            Box::pin(async move {
                                service.trust.signing.revalidate(c, p).await?;
                                let profile = service.trust.signing.profile;
                                let row = sqlx::query(
                                    crate::storage_profile::sql(profile, Use::DaConfiguration)
                                        .configuration_receipt,
                                )
                                .bind(p.tenant().to_string())
                                .bind(*op)
                                .fetch_optional(&mut *c)
                                .await
                                .map_err(db)?
                                .ok_or(Error::NotFound)?;
                                let signed: SignedConfiguration =
                                    serde_json::from_value(row.try_get("result").map_err(db)?)
                                        .map_err(|_| Error::Conflict)?;
                                let config = &signed.configuration;
                                let now: i64 = sqlx::query_scalar(
                                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                                )
                                .fetch_one(&mut *c)
                                .await
                                .map_err(db)?;
                                if config.service_id != p.installation()
                                    || config.tenant.to_string() != p.tenant().to_string()
                                    || config.expires_at <= now
                                    || config.delivery
                                        != rss_mdm_agent_wire::da::DeliveryPermission::Da
                                {
                                    return Err(Error::Forbidden);
                                }
                                if let Audience::Device {
                                    device,
                                    registration,
                                    generation,
                                } = &config.audience
                                    && (device != p.device()
                                        || *registration != p.registration()
                                        || *generation != p.generation() as u64)
                                {
                                    return Err(Error::Forbidden);
                                }
                                trust::require_verification(
                                    profile,
                                    Use::DaConfiguration,
                                    c,
                                    p,
                                    &signed.key_id,
                                )
                                .await?;
                                Ok(signed)
                            })
                        })
                        .await
                    })
                },
            )
            .await;
        crate::service::settle(result, a, false)
    }
}
