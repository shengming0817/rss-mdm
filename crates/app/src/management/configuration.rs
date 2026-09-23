//! Product-owned authored configuration and immutable execution inputs.
use super::*;
use crate::{PlanFailureReason as Reason, PlanStage};
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use sqlx::Row;
pub(crate) const MAX_TARGETS: usize = 32;
pub(super) const MAX_EXECUTIONS: usize = 10_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Evidence {
    pub registration: Uuid,
    pub generation: i64,
    pub os_version: String,
    pub edition: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Frozen {
    pub enabled: bool,
    pub policy_status: String,
    pub version: u64,
    pub resource_digest: Vec<u8>,
    pub ddf: String,
    pub compiled_digest: [u8; 32],
    pub devices: std::collections::BTreeMap<String, Evidence>,
}
impl Management {
    pub(super) async fn firewall_version(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
        enabled: bool,
    ) -> Result<r::Version> {
        use sha2::{Digest, Sha256};
        let id = |s: &str| input(r::Id::new(s));
        let bytes = serde_json::to_vec(&serde_json::json!({"enabled":enabled}))
            .map_err(|_| Error::Malformed)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let v = input(r::Version::new(
            self.tenant,
            id(resource)?,
            id(version)?,
            r::Kind::Configuration,
            vec![r::Variant::new(
                r::Platform::Windows,
                r::Architecture::X86_64,
                id("domain-firewall")?,
                r::Declaration::Configuration {
                    artifact: input(r::Artifact::new(
                        id("inline-domain-firewall")?,
                        bytes.len() as u64,
                        r::Digest::from_bytes(digest),
                    ))?,
                    schema: id("windows-firewall-domain-v1")?,
                    apply: id("replace")?,
                    detect: id("device-firewall-status")?,
                    remove: None,
                },
            )],
        ))?;
        let tenant = self.tenant.to_string();
        let resource = resource.to_owned();
        let version = version.to_owned();
        let digest = v.digest().bytes().to_vec();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_management.firewall_resources VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(tenant).bind(resource).bind(version).bind(enabled).bind(digest).execute(c).await?;Ok(())})).await?;
        Ok(v)
    }
    pub(super) async fn freeze_firewall(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        devices: &[String],
    ) -> Result<Option<Frozen>> {
        let Some(version) = policy.version() else {
            return Ok(None);
        };
        let tenant = self.tenant.to_string();
        let key = policy.key().value().to_owned();
        let number = version.number();
        let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT r.enabled,r.digest FROM mdm_management.firewall_versions v JOIN mdm_management.firewall_resources r ON(r.tenant_id,r.resource,r.version)=(v.tenant_id,v.resource,v.resource_version) WHERE v.tenant_id=$1::uuid AND v.policy=$2 AND v.version=$3").bind(tenant).bind(key).bind(number as i64).fetch_optional(c).await})).await?;
        let Some(row) = row else { return Ok(None) };
        if devices.len() > MAX_TARGETS {
            return Err(Error::ConfigurationTargetLimit.into());
        }
        let enabled: bool = row.try_get("enabled")?;
        use sha2::{Digest, Sha256};
        let compiled_digest =
            Sha256::digest(rss_mdm_windows_mdm::configuration::identity(enabled)).into();
        let mut evidence_map = std::collections::BTreeMap::new();
        for device in devices
            .iter()
            .filter(|_| policy.status() == rss_mdm_policy::Status::Active)
        {
            let e = evidence(tx, device, PlanStage::Preview).await?;
            let rejected = || Reason::PlatformUnsupported.at(Some(device), PlanStage::Preview);
            let p = rss_mdm_windows_mdm::configuration::Platform::new(&e.os_version, e.edition)
                .map_err(|_| rejected())?;
            rss_mdm_windows_mdm::configuration::Firewall::compile(enabled, &p)
                .map_err(|_| rejected())?;
            evidence_map.insert(device.clone(), e);
        }
        Ok(Some(Frozen {
            enabled,
            policy_status: match policy.status() {
                rss_mdm_policy::Status::Draft => "draft",
                rss_mdm_policy::Status::Active => "active",
                rss_mdm_policy::Status::Paused => "paused",
                rss_mdm_policy::Status::Archived => "archived",
            }
            .into(),
            compiled_digest,
            version: number,
            resource_digest: row.try_get("digest")?,
            ddf: rss_mdm_windows_mdm::configuration::REVISION.into(),
            devices: evidence_map,
        }))
    }
}
pub(super) async fn evidence(
    tx: &mut PgTransaction<'_>,
    device: &str,
    stage: PlanStage,
) -> Result<Evidence> {
    let unknown = Reason::CapabilityUnknown.at(Some(device), stage);
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT r.id::text,r.generation,c.os_version,c.edition FROM mdm_access.registrations r JOIN mdm_commands.capabilities c ON(c.tenant_id,c.registration,c.generation)=(r.tenant_id,r.id,r.generation) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='mdm' AND r.state='active'").bind(tenant).bind(device).fetch_all(c).await})).await?;
    if rows.len() != 1 {
        return Err(unknown.into());
    }
    let r = &rows[0];
    Ok(Evidence {
        registration: stored(Uuid::parse_str(&r.try_get::<String, _>("id")?))?,
        generation: r.try_get("generation")?,
        os_version: r.try_get("os_version")?,
        edition: r.try_get::<i32, _>("edition")? as u32,
    })
}
/// Derive policy execution facts from the sole command/receipt owner.
impl Management {
    pub(super) async fn firewall_facts(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::PolicyId,
    ) -> Result<Vec<rss_mdm_policy::ExecutionRecord>> {
        use rss_mdm_policy as p;
        let key = policy.value().to_owned();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query("SELECT * FROM mdm_commands.policy_facts($1)")
                        .bind(key)
                        .fetch_all(c)
                        .await
                })
            })
            .await?;
        if rows.len() > MAX_EXECUTIONS {
            return Err(Error::ConfigurationTargetLimit.into());
        }
        let tenant = self.tenant.to_string();
        let key = policy.value().to_owned();
        let numbers = rows
            .iter()
            .map(|row| row.try_get::<i64, _>("version"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let versions: Vec<(i64, Vec<u8>)> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("SELECT v.version,r.digest FROM mdm_management.firewall_versions v JOIN mdm_management.firewall_resources r ON (r.tenant_id,r.resource,r.version)=(v.tenant_id,v.resource,v.resource_version) WHERE v.tenant_id=$1::uuid AND v.policy=$2 AND v.version=ANY($3)")
                .bind(tenant).bind(key).bind(numbers).fetch_all(c).await
        })).await?;
        let versions: std::collections::BTreeMap<_, _> = versions.into_iter().collect();
        rows.into_iter()
            .map(|row| {
                let number: i64 = row.try_get("version")?;
                let digest: [u8; 32] = stored(
                    versions
                        .get(&number)
                        .ok_or(Error::Unavailable(Failure::ManagementStorage))?
                        .as_slice()
                        .try_into(),
                )?;
                let label = digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let payload = input(p::PayloadRef::new(
                    input(p::PayloadId::new(self.tenant, format!("r-{label}")))?,
                    1,
                    digest,
                ))?;
                let version = input(p::Version::new(
                    policy.clone(),
                    row.try_get::<i64, _>("version")? as u64,
                    payload,
                    p::RemovalRule::CancelOutstandingRetainEffects,
                ))?;
                let status: String = row.try_get("status")?;
                let write: Option<i32> = row.try_get("write_status")?;
                let progress = match (write, status.as_str()) {
                    (Some(200), _) => p::Progress::Succeeded,
                    (_, "cancelled" | "superseded") => p::Progress::Cancelled,
                    (Some(n), _) if n >= 400 => p::Progress::Failed,
                    (_, "timed_out") => p::Progress::Unknown,
                    _ => p::Progress::Running,
                };
                input(p::ExecutionRecord::new(
                    version,
                    input(p::DeviceId::new(
                        self.tenant,
                        row.try_get::<String, _>("device")?,
                    ))?,
                    progress,
                    p::Effect::Unknown,
                ))
            })
            .collect()
    }
}

impl Management {
    pub(super) async fn import_firewall_facts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        policy: &str,
        expected: u64,
        at: Timepoint,
    ) -> Result<u64> {
        use rss_mdm_policy as p;
        use rss_mdm_policy_postgres as pg;
        let policy_key = input(p::PolicyId::new(self.tenant, policy))?;
        let facts = self.firewall_facts(tx, &policy_key).await?;
        if facts.is_empty() {
            return Ok(expected);
        }
        tx.prepare_outbox_partitions(&[self.policies.partition(policy)?])
            .await?;
        let mut revision = expected;
        for (page, facts) in facts.chunks(1000).enumerate() {
            revision = checked(
                self.policies
                    .execute_in(
                        tx,
                        &pg::Request {
                            id: input(p::RequestId::new(
                                self.tenant,
                                format!("{task}-facts-{page}"),
                            ))?,
                            expected_storage_revision: revision,
                            as_of: at,
                            command: pg::Command::RecordExecutions {
                                policy: policy_key.clone(),
                                facts: facts.to_vec(),
                            },
                        },
                    )
                    .await?,
            )?
            .storage_revision;
        }
        Ok(revision)
    }
}
