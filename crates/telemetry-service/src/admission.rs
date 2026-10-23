//! Device input is authorized inside the original fenced product transaction.
use crate::{Error, Service, samples};
use rss_mdm_agent_wire::runtime::{TelemetryDelivery, TelemetryReceipt, TelemetryUpload};
use rss_mdm_registration_service::device::{DevicePrincipal, store::revalidate_collection_source};
use rss_request_context::TenantId;
use rss_timeseries::{Id, Scope, Stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Accepted {
    pub tenant: String,
    pub device: String,
    pub registration: Uuid,
    pub credential: Uuid,
    pub generation: i64,
    #[schemars(with = "rss_mdm_agent_wire::runtime::Source")]
    pub source: rss_mdm_inventory::Source,
    pub epoch: Uuid,
    pub received_at: i64,
    pub profile: rss_mdm_resource::TelemetryProfile,
    #[schemars(with = "Vec<rss_mdm_agent_wire::runtime::FieldDefinition>")]
    pub fields: Vec<rss_mdm_inventory::FieldDefinition>,
    pub input: TelemetryUpload,
}
impl Accepted {
    pub fn stream(&self) -> Result<Stream, Error> {
        Ok(Stream::new(
            Scope::new(
                TenantId::parse(&self.tenant).map_err(|_| Error::Storage)?,
                Id::new("mdm.telemetry")?,
            ),
            Id::new(format!("{}:{}", self.registration, self.source.as_str()))?,
            Id::new(self.epoch.to_string())?,
        ))
    }
    pub fn history(&self) -> Result<Option<rss_timeseries::Batch>, Error> {
        samples::prepare(
            &self.profile,
            &self.fields,
            &self.input,
            self.stream()?,
            &self.device,
            self.received_at,
        )
    }
}
pub(crate) async fn receive_on(
    service: &Service,
    c: &mut PgConnection,
    principal: &DevicePrincipal,
    input: &TelemetryUpload,
    wire_bytes: usize,
) -> Result<TelemetryReceipt, Error> {
    if principal.tenant() != service.tenant {
        return Err(Error::Denied);
    }
    input.validate().map_err(|_| Error::Invalid)?;
    if input
        .observations
        .iter()
        .map(|point| point.values.len())
        .sum::<usize>()
        > service.storage_budget.points.get() as usize
    {
        return Err(Error::Capacity);
    }
    let frozen = rss_mdm_flow_service::planning::policies::telemetry::resolve_on(
        &service.planning,
        c,
        principal.device(),
        input.policy,
        input.policy_version,
    )
    .await
    .map_err(|_| Error::Denied)?;
    capable_on(c, service.tenant, principal.registration(), &frozen).await?;
    let scope = revalidate_collection_source(c, principal, frozen.source)
        .await
        .map_err(|_| Error::Denied)?;
    let epoch = Uuid::parse_str(scope.epoch().as_str()).map_err(|_| Error::Storage)?;
    if input.binding
        != binding(
            principal,
            input.policy,
            input.policy_version,
            frozen.source,
            epoch,
            &frozen.profile,
        )?
    {
        return Err(Error::Denied);
    }
    let bytes = serde_json::to_vec(input)?;
    let digest = Sha256::digest(&bytes).to_vec();
    let accounted = wire_bytes.max(bytes.len());
    if accounted
        > service
            .limits
            .request_bytes
            .min(service.storage_budget.bytes.get())
            .min(frozen.profile.spec().budget.bytes) as usize
    {
        return Err(Error::Capacity);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2815))")
        .bind(format!("{}:{}", service.tenant, input.batch_id))
        .execute(&mut *c)
        .await?;
    if let Some(row) = sqlx::query("SELECT registration,credential,epoch,input_digest,received_at,delivery FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2")
        .bind(service.tenant.to_string()).bind(input.batch_id).fetch_optional(&mut *c).await? {
        if row.try_get::<Uuid,_>("registration")? != principal.registration() || row.try_get::<Uuid,_>("epoch")? != epoch
            || row.try_get::<Vec<u8>,_>("input_digest")? != digest { return Err(Error::Conflict); }
        return Ok(TelemetryReceipt { batch_id: input.batch_id, received_at: row.try_get("received_at")?, replayed: true, delivery: delivery(row.try_get("delivery")?)? });
    }
    let keys = frozen
        .fields
        .iter()
        .map(|f| rss_mdm_inventory::FieldKey::parse(f.key.as_str()).map_err(|_| Error::Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    if !rss_mdm_inventory_postgres::admit_time_series_fields_in(c, service.tenant, &keys)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Denied);
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *c)
            .await?;
    // The immutable field policy also bounds late arrival. Maintenance holds the
    // same device fence, so no accepted work can appear behind an advanced cutoff.
    if frozen.profile.spec().projection != rss_mdm_resource::TelemetryProjection::Current {
        for field in &frozen.fields {
            let reference = &field.time_series.as_ref().ok_or(Error::Invalid)?.retention;
            let policy = rss_mdm_inventory_postgres::retention_policy_in(
                c,
                service.tenant,
                &reference.key,
                reference.revision,
            )
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Storage)?;
            if input.observations.iter().any(|point| {
                point.observed_at < now.saturating_sub(i64::from(policy.raw_seconds) * 1_000_000)
            }) {
                return Err(Error::Invalid);
            }
        }
    }
    let accepted = Accepted {
        tenant: service.tenant.to_string(),
        device: principal.device().into(),
        registration: principal.registration(),
        credential: principal.credential(),
        generation: principal.generation(),
        source: frozen.source,
        epoch,
        received_at: now,
        profile: frozen.profile,
        fields: frozen.fields,
        input: input.clone(),
    };
    if accepted.profile.spec().projection != rss_mdm_resource::TelemetryProjection::History {
        crate::current::prepare(&accepted)?;
    }
    admit_observations_on(c, service.tenant, &accepted).await?;
    let history = accepted.history()?;
    if let Some(history) = &history {
        let unique = history
            .samples()
            .iter()
            .map(|s| s.input().series.digest().map(|d| *d.as_bytes()))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        if history.samples().len() > service.storage_budget.points.get() as usize
            || unique.len() > service.storage_budget.series.get() as usize
            || history.encode()?.len() > service.storage_budget.bytes.get() as usize
        {
            return Err(Error::Capacity);
        }
        admit_resources_on(c, service.tenant, &accepted, history).await?;
        crate::retention::register(c, service.tenant, history, now).await?;
    }
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND registration=$2 AND delivery<>'published'")
        .bind(service.tenant.to_string()).bind(principal.registration()).fetch_one(&mut *c).await?;
    if pending >= i64::from(service.limits.pending_batches) {
        return Err(Error::Capacity);
    }
    admit_rate_on(service, c, now, accounted).await?;
    let fields: Vec<_> = accepted
        .fields
        .iter()
        .map(|f| f.key.as_str().to_owned())
        .collect();
    let first = input
        .observations
        .iter()
        .map(|v| v.observed_at)
        .min()
        .ok_or(Error::Invalid)?;
    let last = input
        .observations
        .iter()
        .map(|v| v.observed_at)
        .max()
        .ok_or(Error::Invalid)?;
    let mut quality = std::collections::BTreeMap::<String, [u32; 3]>::new();
    for observation in &input.observations {
        for (field, reading) in &observation.values {
            if !accepted
                .fields
                .iter()
                .any(|definition| definition.key.as_str() == field.as_str())
            {
                continue;
            }
            let index = match reading {
                rss_mdm_agent_wire::runtime::TelemetryReading::Valid { .. } => 0,
                rss_mdm_agent_wire::runtime::TelemetryReading::Missing { .. } => 1,
                rss_mdm_agent_wire::runtime::TelemetryReading::Failed { .. } => 2,
            };
            quality.entry(field.as_str().into()).or_default()[index] += 1;
        }
    }
    sqlx::query("INSERT INTO mdm_telemetry.batches VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',$15,$16,$17,$18,$19)")
        .bind(service.tenant.to_string()).bind(input.batch_id).bind(principal.device()).bind(principal.registration()).bind(principal.credential()).bind(principal.generation())
        .bind(accepted.source.as_str()).bind(epoch).bind(input.policy).bind(input.policy_version).bind(digest).bind(Sha256::digest(serde_json::to_vec(&accepted)?).to_vec()).bind(fields).bind(now).bind(first).bind(last).bind(serde_json::to_value(quality)?).bind(input.observations.iter().map(|v|v.id).collect::<Vec<_>>()).bind(accepted.profile.spec().projection!=rss_mdm_resource::TelemetryProjection::History).execute(&mut *c).await?;
    crate::delivery::append_on(c, &accepted).await?;
    Ok(TelemetryReceipt {
        batch_id: input.batch_id,
        received_at: now,
        replayed: false,
        delivery: TelemetryDelivery::Pending,
    })
}
pub(crate) fn delivery(s: &str) -> Result<TelemetryDelivery, Error> {
    match s {
        "pending" => Ok(TelemetryDelivery::Pending),
        "published" => Ok(TelemetryDelivery::Published),
        "unknown" => Ok(TelemetryDelivery::Unknown),
        "blocked" => Ok(TelemetryDelivery::Blocked),
        _ => Err(Error::Storage),
    }
}

pub(crate) async fn status_on(
    service: &Service,
    c: &mut PgConnection,
    principal: &DevicePrincipal,
    batch: Uuid,
) -> Result<TelemetryReceipt, Error> {
    if principal.channel() != rss_mdm_inventory::Channel::Agent
        || principal.purpose() != rss_mdm_registration_service::device::Purpose::Primary
    {
        return Err(Error::Denied);
    }
    rss_mdm_registration_service::device::store::revalidate_management(c, principal)
        .await
        .map_err(|_| Error::Denied)?;
    if principal.tenant() != service.tenant {
        return Err(Error::Denied);
    }
    let row = sqlx::query("SELECT received_at,delivery FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 AND device=$4")
        .bind(service.tenant.to_string()).bind(batch).bind(principal.registration()).bind(principal.device()).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    Ok(TelemetryReceipt {
        batch_id: batch,
        received_at: row.try_get("received_at")?,
        replayed: true,
        delivery: delivery(row.try_get("delivery")?)?,
    })
}

/// Binding coordinates are authenticated enrollment facts, never upload assertions.
pub(crate) async fn capable_on(
    c: &mut PgConnection,
    tenant: TenantId,
    registration: Uuid,
    frozen: &rss_mdm_flow_service::planning::policies::telemetry::FrozenProfile,
) -> Result<(), Error> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_flow_service::planning::policies::telemetry::FrozenCollector as F;
    use rss_mdm_resource as r;
    let target = &frozen.profile.spec().template;
    let row=sqlx::query("SELECT b.platform,b.architecture,b.execution_context,b.capabilities,p.profiles FROM mdm_agent.bindings b JOIN mdm_commands.action_polls p ON(p.tenant_id,p.registration)=(b.tenant_id,b.registration) WHERE b.tenant_id=$1::uuid AND b.registration=$2 AND b.wire_version=1")
        .bind(tenant.to_string()).bind(registration).fetch_optional(c).await?.ok_or(Error::Unsupported)?;
    let binding = rss_mdm_execution_service::channels::AgentBinding {
        platform: row.try_get("platform")?,
        architecture: row.try_get("architecture")?,
        execution_context: serde_json::from_value(row.try_get("execution_context")?)?,
        capabilities: serde_json::from_str(&row.try_get::<String, _>("capabilities")?)?,
    };
    if !binding
        .capabilities
        .contains(&w::Capability::TelemetryCollectV1)
    {
        return Err(Error::Unsupported);
    }
    let poll: serde_json::Value = row
        .try_get::<Option<serde_json::Value>, _>("profiles")?
        .ok_or(Error::Unsupported)?;
    let platform = match target.platform {
        r::Platform::Windows => rss_mdm_policy::Platform::Windows,
        r::Platform::MacOS => rss_mdm_policy::Platform::Macos,
    };
    let architecture = match target.architecture {
        r::Architecture::X86_64 => rss_mdm_policy::Architecture::X86_64,
        r::Architecture::Aarch64 => rss_mdm_policy::Architecture::Aarch64,
    };
    let supported = match &frozen.collector {
        F::Native { definition } => {
            if frozen.fields.iter().any(|field| {
                definition
                    .spec()
                    .mappings
                    .get(field.key.as_str())
                    .is_some_and(|mapping| mapping.counter_normalization.is_some())
            }) && !binding
                .capabilities
                .contains(&w::Capability::TelemetryCounterLocalV1)
            {
                return Err(Error::Unsupported);
            }
            let environment = rss_mdm_agent_wire::CollectionEnvironment {
                edition: serde_json::from_value(poll["environment"]["edition"].clone())?,
                tools: serde_json::from_value(poll["environment"]["tools"].clone())?,
                native_engines: serde_json::from_value(poll["nativeEngines"].clone())?,
            };
            rss_mdm_execution_service::native_collection_supported(
                &binding,
                platform,
                architecture,
                definition,
                &environment,
            )
        }
        F::Script { definition, .. } => {
            let r::ScriptPurpose::Collection { applicability, .. } = &definition.spec().purpose
            else {
                return Err(Error::Storage);
            };
            let profile = match definition.spec().profile {
                r::ScriptProfile::PowerShell7 => w::ExecutorProfile::PowerShell7,
                r::ScriptProfile::PosixSh => w::ExecutorProfile::PosixSh,
                r::ScriptProfile::Bash => w::ExecutorProfile::Bash,
                r::ScriptProfile::Osquery => w::ExecutorProfile::Osquery,
            };
            let profiles: Vec<w::ExecutorProfile> =
                serde_json::from_value(poll["profiles"].clone())?;
            let environment = serde_json::from_value(poll["environment"].clone())?;
            let capabilities = serde_json::from_value(poll["profiles"].clone())?;
            rss_mdm_execution_service::script_eligibility::matches(
                &binding,
                platform,
                architecture,
                profile,
                &profiles,
            ) && applicability.allows(&environment, "agent", &capabilities)
        }
    };
    if supported {
        Ok(())
    } else {
        Err(Error::Unsupported)
    }
}

async fn admit_resources_on(
    c: &mut PgConnection,
    tenant: TenantId,
    accepted: &Accepted,
    batch: &rss_timeseries::Batch,
) -> Result<(), Error> {
    let mut fields =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for sample in batch.samples() {
        let series = &sample.input().series;
        fields
            .entry(series.definition().spec().key.as_str().into())
            .or_default()
            .insert(series.resource().as_str().into());
    }
    // A stable sorted lock order covers different profiles and registration generations.
    let catalog = rss_mdm_inventory_postgres::catalog_in(c, tenant)
        .await
        .map_err(|_| Error::Storage)?;
    for (field, resources) in fields {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2814))")
            .bind(format!("{tenant}:{}:{field}", accepted.device))
            .execute(&mut *c)
            .await?;
        let current = catalog
            .definition(rss_mdm_inventory::FieldKey::parse(&field).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Denied)?;
        let maximum = current
            .time_series
            .as_ref()
            .ok_or(Error::Invalid)?
            .max_resources;
        for resource in resources {
            sqlx::query("INSERT INTO mdm_telemetry.resources VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(tenant.to_string()).bind(&accepted.device).bind(&field).bind(resource).execute(&mut *c).await?;
        }
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_telemetry.resources WHERE tenant_id=$1::uuid AND device=$2 AND field=$3")
            .bind(tenant.to_string()).bind(&accepted.device).bind(&field).fetch_one(&mut *c).await?;
        if count > i64::from(maximum) {
            return Err(Error::Capacity);
        }
    }
    Ok(())
}

pub(crate) async fn current_on(
    service: &Service,
    c: &mut PgConnection,
    principal: &DevicePrincipal,
    batch: Uuid,
    observation: Uuid,
) -> Result<crate::CurrentObservation, Error> {
    status_on(service, c, principal, batch).await?;
    let row=sqlx::query("SELECT current_assets,delivery,source,epoch,policy FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2 AND $3=ANY(observations)")
        .bind(service.tenant.to_string()).bind(batch).bind(observation).fetch_optional(&mut *c).await?.ok_or(Error::Denied)?;
    if !row.try_get::<bool, _>("current_assets")? {
        return Ok(crate::CurrentObservation::NotRequested);
    }
    if row.try_get::<String, _>("delivery")? != "published" {
        return Ok(crate::CurrentObservation::Pending);
    }
    let source = row.try_get::<String, _>("source")?;
    let epoch = row.try_get::<Uuid, _>("epoch")?;
    let policy = row.try_get::<Uuid, _>("policy")?;
    let expected = rss_mdm_registration_service::device::scope_dataset(
        service.tenant,
        principal.registration(),
        &source,
        epoch,
        &format!("telemetry.{policy}"),
    )
    .map_err(|_| Error::Storage)?;
    let run = rss_mdm_inventory_service::collection::store::read_on(
        c,
        &service.tenant.to_string(),
        observation,
    )
    .await
    .map_err(|_| Error::Storage)?;
    if run.scope != expected {
        return Err(Error::Storage);
    }
    Ok(crate::CurrentObservation::Admitted(Box::new(run)))
}

/// A descriptive equality fence, never an authentication token or a client-selectable source.
pub(crate) fn binding(
    principal: &DevicePrincipal,
    policy: Uuid,
    version: Uuid,
    source: rss_mdm_inventory::Source,
    epoch: Uuid,
    profile: &rss_mdm_resource::TelemetryProfile,
) -> Result<String, Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            principal.tenant().to_string(),
            principal.device(),
            principal.registration(),
            principal.generation(),
            source.as_str(),
            epoch,
            policy,
            version,
            profile
        ))?)
    ))
}

async fn admit_observations_on(
    c: &mut PgConnection,
    tenant: TenantId,
    accepted: &Accepted,
) -> Result<(), Error> {
    let mut receipts = std::collections::BTreeMap::new();
    for point in &accepted.input.observations {
        // Credential renewal does not change a source incarnation; batch regrouping does not change a sampling fact.
        let mut digest = Sha256::new();
        digest.update(b"mdm.telemetry.observation.v1\0");
        digest.update(accepted.input.binding.as_bytes());
        digest.update(serde_json::to_vec(point)?);
        let digest = digest.finalize().to_vec();
        receipts.insert(point.id, digest);
    }
    let ids = receipts.keys().copied().collect::<Vec<_>>();
    let digests = receipts.values().cloned().collect::<Vec<_>>();
    sqlx::query("INSERT INTO mdm_telemetry.observation_receipts(tenant_id,id,digest) SELECT $1::uuid,id,digest FROM unnest($2::uuid[],$3::bytea[]) AS input(id,digest) ORDER BY id ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(&ids).bind(digests).execute(&mut *c).await?;
    let rows:Vec<(Uuid,Vec<u8>)>=sqlx::query_as("SELECT id,digest FROM mdm_telemetry.observation_receipts WHERE tenant_id=$1::uuid AND id=ANY($2::uuid[])")
        .bind(tenant.to_string()).bind(ids).fetch_all(c).await?;
    if rows.len() != receipts.len()
        || rows
            .iter()
            .any(|(id, digest)| receipts.get(id) != Some(digest))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Shared tenant ingress quota; callers must roll back every rejection.
pub(crate) async fn admit_rate_on(
    service: &Service,
    c: &mut PgConnection,
    now: i64,
    accounted: usize,
) -> Result<(), Error> {
    let window = now / 60_000_000;
    let row = sqlx::query("INSERT INTO mdm_telemetry.rate_windows VALUES($1::uuid,$2,1,$3) ON CONFLICT(tenant_id) DO UPDATE SET minute=excluded.minute,batches=CASE WHEN mdm_telemetry.rate_windows.minute=excluded.minute THEN mdm_telemetry.rate_windows.batches+1 ELSE 1 END,bytes=CASE WHEN mdm_telemetry.rate_windows.minute=excluded.minute THEN mdm_telemetry.rate_windows.bytes+excluded.bytes ELSE excluded.bytes END RETURNING batches,bytes")
        .bind(service.tenant.to_string()).bind(window).bind(accounted as i64).fetch_one(&mut *c).await?;
    if row.try_get::<i64, _>("batches")? > i64::from(service.limits.batches_per_minute)
        || row.try_get::<i64, _>("bytes")? > i64::from(service.limits.bytes_per_minute)
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
