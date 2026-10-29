//! Device configuration resolves the same current authority as upload admission.
use crate::{Error, Service, admission::capable_on};
use rss_mdm_agent_wire::runtime::{
    SignedTelemetryConfiguration, TaskResource, TelemetryConfiguration,
};
use rss_mdm_registration_service::device::DevicePrincipal;
use std::sync::Arc;
use uuid::Uuid;
impl Service {
    /// Discover a complete bounded set; never expose policies outside the current device scope.
    pub async fn directory(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
    ) -> Result<rss_mdm_agent_wire::runtime::TelemetryDirectory, Error> {
        let service = self.clone();
        let principal = principal.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move { Ok(directory_on(&service, c, &principal).await) })
                    })
                    .await
                })
            })
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
    /// Verify exact material under the same current assignment and registration fences.
    pub async fn content(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        policy: Uuid,
        version: Uuid,
        store: Arc<rss_mdm_content_service::Store>,
    ) -> Result<rss_mdm_content_service::Verified, Error> {
        let service = self.clone();
        let principal = principal.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            let result = async {
                                let frozen = service
                                    .policies
                                    .current_on(c, principal.device(), policy, version)
                                    .await
                                    .map_err(policy_error)?;
                                let configuration =
                                    configuration_on(&service, c, &principal, policy, version)
                                        .await?;
                                service
                                    .execution
                                    .sign_telemetry_on(c, &principal, configuration)
                                    .await
                                    .map_err(signing_error)?;
                                let rss_mdm_policy_service::telemetry::FrozenCollector::Script {
                                    reference,
                                    length,
                                    digest,
                                    ..
                                } = frozen.collector
                                else {
                                    return Err(Error::Unsupported);
                                };
                                let artifact = rss_mdm_resource::Artifact::new(
                                    rss_mdm_resource::Id::new(reference)
                                        .map_err(|_| Error::Storage)?,
                                    length,
                                    rss_mdm_resource::Digest::from_bytes(digest),
                                )
                                .map_err(|_| Error::Storage)?;
                                store.verify(&artifact).await.map_err(|_| Error::Storage)
                            }
                            .await;
                            Ok(result)
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
    /// Exact-version fetch; stale policies, unsupported bindings and revoked scopes fail closed.
    pub async fn configuration(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        policy: Uuid,
        version: Uuid,
    ) -> Result<SignedTelemetryConfiguration, Error> {
        if principal.tenant() != self.tenant {
            return Err(Error::Denied);
        }
        let service = self.clone();
        let principal = principal.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(async {
                                let configuration =
                                    configuration_on(&service, c, &principal, policy, version)
                                        .await?;
                                service
                                    .execution
                                    .sign_telemetry_on(c, &principal, configuration)
                                    .await
                                    .map_err(signing_error)
                            }
                            .await)
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn configuration_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    policy: Uuid,
    version: Uuid,
) -> Result<TelemetryConfiguration, Error> {
    if principal.tenant() != service.tenant {
        return Err(Error::Denied);
    }
    let frozen = service
        .policies
        .current_on(c, principal.device(), policy, version)
        .await
        .map_err(policy_error)?;
    capable_on(c, service.tenant, principal.registration(), &frozen).await?;
    let scope = rss_mdm_registration_service::device::store::revalidate_collection_source(
        c,
        principal,
        frozen.source,
    )
    .await
    .map_err(registration_error)?;
    let keys = frozen
        .fields
        .iter()
        .map(|f| rss_mdm_inventory::FieldKey::parse(f.key.as_str()).map_err(|_| Error::Storage))
        .collect::<Result<Vec<_>, _>>()?;
    if !rss_mdm_inventory_postgres::admit_time_series_fields_in(c, service.tenant, &keys)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Denied);
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?;
    let epoch = Uuid::parse_str(scope.epoch().as_str()).map_err(|_| Error::Storage)?;
    let binding = crate::admission::binding(
        principal,
        policy,
        version,
        frozen.source,
        epoch,
        &frozen.profile,
    )?;
    let spec = frozen.profile.spec();
    let (template_timeout, template_output) = match &frozen.collector {
        rss_mdm_policy_service::telemetry::FrozenCollector::Native { definition } => (
            definition.spec().plan.spec().budget.timeout_seconds,
            definition.spec().plan.spec().budget.output_bytes,
        ),
        rss_mdm_policy_service::telemetry::FrozenCollector::Script { definition, .. } => (
            definition.spec().timeout_seconds,
            definition.spec().output_bytes,
        ),
    };
    let source = match frozen.source {
        rss_mdm_inventory::Source::AgentNative => rss_mdm_agent_wire::runtime::Source::AgentNative,
        rss_mdm_inventory::Source::AgentScript => rss_mdm_agent_wire::runtime::Source::AgentScript,
        rss_mdm_inventory::Source::AgentOsquery => {
            rss_mdm_agent_wire::runtime::Source::AgentOsquery
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(TelemetryConfiguration {
        resource_digest: frozen.resource_digest,
        tenant_id: Uuid::parse_str(&principal.tenant().to_string()).map_err(|_| Error::Storage)?,
        device_id: principal.device().into(),
        registration_id: principal.registration(),
        generation: principal
            .generation()
            .try_into()
            .map_err(|_| Error::Storage)?,
        source_epoch: epoch,
        issued_at: now,
        expires_at: now.checked_add(300).ok_or(Error::Storage)?,
        policy,
        policy_version: version,
        binding,
        source,
        template: TaskResource {
            id: spec.template.resource.clone(),
            version: spec.template.version.clone(),
            variant: spec.template.variant.clone(),
        },
        collector: collector(&frozen)?,
        fields: frozen
            .fields
            .iter()
            .map(rss_mdm_inventory_service::collection::wire::to_wire_field)
            .collect::<Result<_, _>>()
            .map_err(|_| Error::Storage)?,
        sample_millis: frozen.profile.sample_millis(now),
        normal_sample_millis: spec.sample_millis,
        boost_expires_at: spec
            .boost
            .as_ref()
            .filter(|v| now < v.expires_at)
            .map(|v| v.expires_at),
        upload_millis: spec.upload_millis,
        max_bytes: spec
            .budget
            .bytes
            .min(service.limits.request_bytes)
            .min(service.storage_budget.bytes.get()),
        max_points: spec.budget.points.min(service.storage_budget.points.get()),
        max_resources: spec
            .budget
            .resources
            .min(service.storage_budget.series.get()),
        execution_millis: spec
            .budget
            .execution_millis
            .min(template_timeout.saturating_mul(1000)),
        output_bytes: spec
            .budget
            .output_bytes
            .min(template_output)
            .min(service.limits.request_bytes)
            .min(service.storage_budget.bytes.get()),
        backfill_seconds: spec.backfill_seconds,
    })
}

fn collector(
    frozen: &rss_mdm_policy_service::telemetry::FrozenProfile,
) -> Result<rss_mdm_agent_wire::runtime::TelemetryCollector, Error> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_policy_service::telemetry::FrozenCollector as F;
    use rss_mdm_resource as r;
    let fields = &frozen.fields;
    Ok(match &frozen.collector {
        F::Native { definition } => w::TelemetryCollector::Native {
            plan_digest: definition.spec().plan.digest(),
            plan: definition.spec().plan.clone(),
            mappings: definition
                .spec()
                .mappings
                .iter()
                .filter(|(key, _)| fields.iter().any(|f| f.key.as_str() == key.as_str()))
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        w::AgentCollectionMapping {
                            counter_normalization: value.counter_normalization,
                            query: value.query.clone(),
                            missing: value.missing,
                            mapping: value.mapping.clone(),
                        },
                    ))
                })
                .collect::<Result<_, Error>>()?,
        },
        F::Script {
            definition,
            length,
            digest,
            ..
        } => {
            let spec = definition.spec();
            let r::ScriptPurpose::Collection { mappings, .. } = &spec.purpose else {
                return Err(Error::Storage);
            };
            let (arguments, environment) = definition
                .prepare_parameters(&frozen.profile.spec().parameters)
                .map_err(|_| Error::Storage)?;
            w::TelemetryCollector::Script {
                content: w::TaskContent {
                    length: *length,
                    sha256: *digest,
                },
                profile: match spec.profile {
                    r::ScriptProfile::PowerShell7 => w::ExecutorProfile::PowerShell7,
                    r::ScriptProfile::PosixSh => w::ExecutorProfile::PosixSh,
                    r::ScriptProfile::Bash => w::ExecutorProfile::Bash,
                    r::ScriptProfile::Osquery => w::ExecutorProfile::Osquery,
                },
                arguments,
                environment,
                sql_parameters: spec
                    .sql
                    .as_ref()
                    .map(|_| frozen.profile.spec().parameters.clone()),
                output_schema: spec.output.clone(),
                timeout_seconds: spec
                    .timeout_seconds
                    .min(frozen.profile.spec().budget.execution_millis / 1000),
                max_rows: spec.max_rows,
                mappings: mappings
                    .iter()
                    .filter(|(key, _)| fields.iter().any(|f| f.key.as_str() == key.as_str()))
                    .map(|(k, v)| Ok((k.clone(), v.clone())))
                    .collect::<Result<_, Error>>()?,
            }
        }
    })
}

async fn directory_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
) -> Result<rss_mdm_agent_wire::runtime::TelemetryDirectory, Error> {
    use rss_mdm_agent_wire::runtime::{TelemetryAssignment, TelemetryDirectory};
    if principal.tenant() != service.tenant
        || principal.channel() != rss_mdm_inventory::Channel::Agent
        || principal.purpose() != rss_mdm_registration_service::device::Purpose::Primary
    {
        return Err(Error::Denied);
    }
    let eligible = crate::configurations::eligible_on(service, c, principal.device()).await?;
    rss_mdm_registration_service::device::store::revalidate_management(c, principal)
        .await
        .map_err(registration_error)?;
    let mut assignments = Vec::new();
    for candidate in eligible {
        let frozen = &candidate.frozen;
        match rss_mdm_registration_service::device::store::revalidate_collection_source(
            c,
            principal,
            frozen.source,
        )
        .await
        .map_err(registration_error)
        {
            Ok(_) => {}
            Err(Error::Denied) => continue,
            Err(error) => return Err(error),
        }
        let Some(supported) =
            crate::configurations::supported_on(service, c, principal.registration(), frozen)
                .await?
        else {
            continue;
        };
        assignments.push(TelemetryAssignment {
            policy: candidate.policy,
            version: candidate.version,
            supported,
        });
    }
    Ok(TelemetryDirectory { assignments })
}

fn signing_error(error: rss_mdm_execution_service::Error) -> Error {
    use rss_mdm_execution_service::Error as E;
    match error {
        E::Forbidden | E::Unauthorized => Error::Denied,
        E::Conflict => Error::Conflict,
        E::Unsupported => Error::Unsupported,
        E::Malformed => Error::Invalid,
        _ => Error::Storage,
    }
}

fn policy_error(error: rss_mdm_policy_service::Error) -> Error {
    use rss_mdm_policy_service::Error as E;
    match error {
        E::Forbidden | E::Unauthorized => Error::Denied,
        E::Conflict => Error::Conflict,
        E::Unsupported => Error::Unsupported,
        _ => Error::Storage,
    }
}
fn registration_error(error: rss_mdm_registration_service::Error) -> Error {
    use rss_mdm_registration_service::Error as E;
    match error {
        E::Forbidden | E::Unauthorized | E::Agent(_) => Error::Denied,
        E::Conflict => Error::Conflict,
        _ => Error::Storage,
    }
}
