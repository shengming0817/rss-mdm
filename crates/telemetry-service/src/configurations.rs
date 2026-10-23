//! Management summaries and Agent discovery share current assignment admission.
use crate::{Error, Service, admission::capable_on};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_flow_service::planning::policies::telemetry::FrozenProfile;
use rss_mdm_inventory::{Channel, Source};
use rss_mdm_policy::ExactResourceBinding;
use rss_mdm_registration_service::device::{endpoints, store};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Current telemetry-capable registration coordinates, not credential evidence.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub id: Uuid,
    pub generation: i64,
}

/// Public configuration metadata; contains neither executable inputs nor device receipts.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub policy_id: Uuid,
    pub policy_version_id: Uuid,
    pub resource: ExactResourceBinding,
    pub source: Source,
    pub projection: rss_mdm_resource::TelemetryProjection,
    pub sample_millis: u32,
    pub normal_sample_millis: u32,
    pub boost_expires_at: Option<i64>,
    pub upload_millis: u32,
    pub supported: bool,
}

/// Complete bounded current configuration set. Absence never removes historical samples.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configurations {
    pub device: String,
    pub registration: Option<Registration>,
    pub evaluated_at_micros: i64,
    pub configurations: Vec<Configuration>,
}

pub(crate) struct Eligible {
    pub policy: Uuid,
    pub version: Uuid,
    pub resource: ExactResourceBinding,
    pub frozen: FrozenProfile,
}

/// Resolve author/Policy locks before acquiring the registration fence, as ingress does.
pub(crate) async fn eligible_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    device: &str,
) -> Result<Vec<Eligible>, Error> {
    let candidates: Vec<(Uuid, Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT p.id,p.current_version,p.definition FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='telemetry_profile' ORDER BY p.id LIMIT 257",
    )
    .bind(service.tenant.to_string())
    .fetch_all(&mut *c)
    .await?;
    if candidates.len() > 256 {
        return Err(Error::Capacity);
    }
    let mut eligible = Vec::new();
    for (policy, version, definition) in candidates {
        match rss_mdm_flow_service::planning::policies::telemetry::resolve_on(
            &service.planning,
            c,
            device,
            policy,
            version,
        )
        .await
        {
            Ok(frozen) => {
                let definition: rss_mdm_policy::Definition =
                    serde_json::from_value(definition).map_err(|_| Error::Storage)?;
                let rss_mdm_policy::Action::TelemetryProfile { resource } = definition.action
                else {
                    return Err(Error::Storage);
                };
                eligible.push(Eligible {
                    policy,
                    version,
                    resource,
                    frozen,
                });
            }
            Err(rss_mdm_flow_service::Error::Forbidden) => {}
            Err(_) => return Err(Error::Storage),
        }
    }
    Ok(eligible)
}

/// Field retirement and collector capability have the same meaning in both projections.
pub(crate) async fn supported_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    registration: Uuid,
    frozen: &FrozenProfile,
) -> Result<Option<bool>, Error> {
    let keys = frozen
        .fields
        .iter()
        .map(|f| rss_mdm_inventory::FieldKey::parse(f.key.as_str()).map_err(|_| Error::Storage))
        .collect::<Result<Vec<_>, _>>()?;
    if !rss_mdm_inventory_postgres::admit_time_series_fields_in(c, service.tenant, &keys)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Ok(None);
    }
    match capable_on(c, service.tenant, registration, frozen).await {
        Ok(()) => Ok(Some(true)),
        Err(Error::Unsupported) => Ok(Some(false)),
        Err(e) => Err(e),
    }
}

impl Service {
    /// Read current configuration metadata with device-scoped management authority.
    pub async fn configurations(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<Configurations, Error> {
        proof.check_live().map_err(|_| Error::Denied)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Denied);
        }
        if device.is_empty() || device.len() > 512 || device.chars().any(char::is_control) {
            return Err(Error::Invalid);
        }
        let service = self.clone();
        let proof = proof.clone();
        let device = device.to_owned();
        let audit = audit.clone();
        let failure = Arc::new(Mutex::new(None));
        let rejected = failure.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    service
                        .planning
                        .audit_store
                        .bind_in(tx)
                        .await
                        .map_err(crate::storage_error)?;
                    let reader = service.clone();
                    let page = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                read_on(&reader, c, &proof, &device).await.map_err(|e| {
                                    *rejected.lock().expect("configuration query rejection") =
                                        Some(e);
                                    sqlx::Error::Protocol("configuration query rejected".into())
                                })
                            })
                        })
                        .await?;
                    audit.require_request_settlement();
                    Ok(page)
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| {
                    Err(failure
                        .lock()
                        .expect("configuration query rejection")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}

async fn read_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    device: &str,
) -> Result<Configurations, Error> {
    rss_mdm_inventory_postgres::lock_watermark_in(c, service.tenant)
        .await
        .map_err(|_| Error::Storage)?;
    rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
        .await
        .map_err(|_| Error::Denied)?;
    let authorization =
        rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(|_| Error::Denied)?;
    for permission in [Permission::PolicyRead, Permission::ResourceRead] {
        authorization
            .require(proof, permission, None)
            .map_err(|_| Error::Denied)?;
    }
    authorization
        .require(proof, Permission::InventoryRead, Some(device))
        .map_err(|_| Error::Denied)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2)",
    )
    .bind(service.tenant.to_string())
    .bind(device)
    .fetch_one(&mut *c)
    .await?;
    if !exists {
        return Err(Error::NotFound);
    }
    let eligible = eligible_on(service, c, device).await?;
    endpoints::lock_in(c, &service.tenant.to_string(), device, Channel::Agent)
        .await
        .map_err(|_| Error::Storage)?;
    let primary = endpoints::current_in(c, &service.tenant.to_string(), device, Channel::Agent)
        .await
        .map_err(|_| Error::Storage)?;
    let live = store::live_collection_streams_on(c, service.tenant, device)
        .await
        .map_err(|_| Error::Storage)?;
    let primary = primary.filter(|p| live.iter().any(|(id, _, _)| *id == p.registration_id));
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *c)
            .await?;
    let mut configurations = Vec::new();
    if let Some(primary) = &primary {
        for candidate in eligible {
            if !live.iter().any(|(id, source, _)| {
                *id == primary.registration_id && *source == candidate.frozen.source.as_str()
            }) {
                continue;
            }
            let Some(supported) =
                supported_on(service, c, primary.registration_id, &candidate.frozen).await?
            else {
                continue;
            };
            let spec = candidate.frozen.profile.spec();
            configurations.push(Configuration {
                policy_id: candidate.policy,
                policy_version_id: candidate.version,
                resource: candidate.resource,
                source: candidate.frozen.source,
                projection: spec.projection,
                sample_millis: candidate.frozen.profile.sample_millis(now / 1_000_000),
                normal_sample_millis: spec.sample_millis,
                boost_expires_at: spec
                    .boost
                    .as_ref()
                    .filter(|b| now / 1_000_000 < b.expires_at)
                    .map(|b| b.expires_at),
                upload_millis: spec.upload_millis,
                supported,
            });
        }
    }
    proof.check_live().map_err(|_| Error::Denied)?;
    Ok(Configurations {
        device: device.into(),
        registration: primary.map(|p| Registration {
            id: p.registration_id,
            generation: p.generation,
        }),
        evaluated_at_micros: now,
        configurations,
    })
}
