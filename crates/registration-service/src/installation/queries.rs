//! Native bootstrap/cleanup projections on the management caller's authorized snapshot.
use super::*;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

/// Contact facts for Agent identities bound to one original native generation.
pub struct NativeContact {
    pub active: i64,
    pub bindings: i64,
    pub last: Option<i64>,
}

pub async fn native_contact_on(
    c: &mut PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> std::result::Result<NativeContact, crate::Error> {
    let (active, bindings, last) = sqlx::query_as::<_, (i64, i64, Option<i64>)>(
        "SELECT count(*) FILTER (WHERE r.state = 'active'), count(*), CAST(floor(EXTRACT(EPOCH FROM max(COALESCE(r.last_communication_received_at, r.first_authenticated_at, g.created_at)))) AS bigint) FROM mdm_access.certificate_grants AS g INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.certificate_grant_id) = (g.tenant_id, g.id) WHERE g.tenant_id = CAST($1 AS uuid) AND g.source = 'native' AND (g.native_authority ->> 'device')::uuid = $2 AND r.channel = 'agent' AND r.purpose = 'primary'",
    ).bind(tenant).bind(device.into_uuid())
        .fetch_one(c).await.map_err(crate::database::db)?;
    Ok(NativeContact {
        active,
        bindings,
        last,
    })
}

/// A retained bootstrap duty blocks another installation for its original source generation.
pub async fn cleanup_pending_on(
    c: &mut PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> std::result::Result<bool, crate::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND (source->>'device')::uuid=$2 AND active AND NOT cleanup_complete)")
        .bind(tenant).bind(device.into_uuid())
        .fetch_one(c).await.map_err(crate::database::db)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapState {
    Prepared,
    Signing,
    Issued,
    Consumed,
    Revoked,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapObservation {
    pub state: BootstrapState,
    pub delivery: Uuid,
    pub cleanup: Option<Uuid>,
    pub cleanup_complete: bool,
    pub cleanup_retry_at: i64,
    pub deadline: i64,
}

#[derive(Deserialize)]
pub struct AgentRegistration {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub state: crate::enrollment::read::RegistrationState,
}

pub struct InstallationObservation {
    pub bootstrap: Option<BootstrapObservation>,
    pub registration: Option<AgentRegistration>,
}

/// Reads only Registration facts on the caller's authorized, tenant-bound snapshot.
pub async fn installations_on(
    c: &mut PgConnection,
    tenant: TenantId,
    installations: &[Uuid],
) -> std::result::Result<std::collections::BTreeMap<Uuid, InstallationObservation>, crate::Error> {
    if installations.len() > 1000 {
        return Err(crate::Error::Malformed);
    }
    let rows = sqlx::query(INSTALLATIONS)
        .bind(tenant.to_string())
        .bind(installations)
        .fetch_all(c)
        .await
        .map_err(crate::database::db)?;
    rss_mdm_query_postgres::observe_rows("registration.installations", &rows)
        .map_err(crate::database::db)?;
    let mut output = std::collections::BTreeMap::new();
    for row in rows {
        if !row
            .try_get::<bool, _>("within_budget")
            .map_err(crate::database::db)?
        {
            return Err(crate::Error::Capacity);
        }
        if let Some(id) = row
            .try_get::<Option<Uuid>, _>("installation")
            .map_err(crate::database::db)?
        {
            let bootstrap = row
                .try_get::<Option<serde_json::Value>, _>("bootstrap")
                .map_err(crate::database::db)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| crate::Error::Corrupt)?;
            let registration = row
                .try_get::<Option<serde_json::Value>, _>("registration")
                .map_err(crate::database::db)?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| crate::Error::Corrupt)?;
            output.insert(
                id,
                InstallationObservation {
                    bootstrap,
                    registration,
                },
            );
        }
    }
    Ok(output)
}

const INSTALLATIONS: &str = "WITH selected AS MATERIALIZED (SELECT i AS installation, (SELECT jsonb_build_object('state', state, 'delivery', delivery, 'cleanup', cleanup, 'cleanupComplete', cleanup_complete, 'cleanupRetryAt', cleanup_retry_at, 'deadline', deadline) FROM mdm_access.agent_bootstraps WHERE tenant_id = CAST($1 AS uuid) AND installation = i AND active) AS bootstrap, (SELECT jsonb_build_object('device', r.id, 'state', r.state) FROM mdm_access.certificate_grants AS g INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.certificate_grant_id) = (g.tenant_id, g.id) WHERE g.tenant_id = CAST($1 AS uuid) AND g.source = 'native' AND g.native_authority ->> 'installation' = CAST(i AS text) ORDER BY r.id LIMIT 1) AS registration FROM unnest(CAST($2 AS uuid[])) AS i), budget AS (SELECT COALESCE(sum(pg_column_size(selected)), 0) <= 16777216 AS ok FROM selected) SELECT selected.*, budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok";

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Detail<O = NativeObservation> {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub revision: i64,
    pub task: super::model::TaskSummary,
    pub target: NativeTarget,
    pub input_version: String,
    pub deadline: i64,
    pub dispatch_failure: Option<DispatchFailure>,
    pub authorization: Authorization,
    pub reauthorization: Reauthorization,
    pub command_status: CommandStatus,
    pub observation: O,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Authorization {
    Authorized,
    Blocked { reason: BlockReason },
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    SourceInvalid,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reauthorization {
    NotApplicable,
}
#[derive(Serialize)]
pub struct Decision {
    pub authorization: Authorization,
    pub reauthorization: Reauthorization,
}
impl Service {
    pub async fn read_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &Snapshot,
        device: &rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> Result<Detail> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        let s = &self.transactions;
        let op = storage::load_on(c, s.tenant, &s.protection, id).await?;
        if op.device != *device {
            return Err(Error::Forbidden.into());
        }
        let status: String =
            sqlx::query_scalar("SELECT mdm_registration_tasks.installation_status($1)")
                .bind(id)
                .fetch_one(&mut *c)
                .await?;
        let status = stored(dc::Status::restore(&status))?;
        let authorization = if op.authority.valid(&s.materials, c, s.tenant).await? {
            Authorization::Authorized
        } else {
            Authorization::Blocked {
                reason: BlockReason::SourceInvalid,
            }
        };
        let observation = super::protocol::observation_on(
            c,
            s.tenant,
            s.windows_results.clone(),
            s.apple_results.clone(),
            &op,
            status,
            false,
        )
        .await?;
        Ok(Detail {
            operation_id: id,
            command_id: id,
            revision: op.revision,
            task: op.request.task.summary()?,
            target: op.request.target,
            input_version: op.request.input_version,
            deadline: op.request.deadline,
            dispatch_failure: op.dispatch_failure,
            authorization,
            reauthorization: Reauthorization::NotApplicable,
            command_status: CommandStatus(status),
            observation,
        })
    }
    pub async fn decisions_on(
        &self,
        c: &mut sqlx::PgConnection,
        ids: Vec<Uuid>,
    ) -> Result<std::collections::BTreeMap<Uuid, Decision>> {
        let s = &self.transactions;
        let operations = storage::load_many_on(c, s.tenant, &s.protection, ids).await?;
        let mut result = std::collections::BTreeMap::new();
        for op in operations.into_values() {
            let authorization = if op.authority.valid(&s.materials, c, s.tenant).await? {
                Authorization::Authorized
            } else {
                Authorization::Blocked {
                    reason: BlockReason::SourceInvalid,
                }
            };
            result.insert(
                op.id,
                Decision {
                    authorization,
                    reauthorization: Reauthorization::NotApplicable,
                },
            );
        }
        Ok(result)
    }
}
pub enum NativeObservation {
    Apple {
        facts: rss_mdm_apple_mdm::native::evidence::ReadEvidence,
        progress: CommandStatus,
        effect_confirmed: bool,
    },
    Declarations {
        facts: Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>,
        progress: CommandStatus,
    },
    Windows {
        receipts: Vec<WindowsReceipt>,
        progress: CommandStatus,
        effect: rss_mdm_windows_mdm::native::verification::EffectState,
        reason: Option<&'static str>,
    },
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsReceipt {
    pub phase: crate::installation::AttemptPhase,
    pub ordinal: i64,
    pub session: i64,
    pub message: i64,
    pub command: i64,
    pub parent_command: Option<i64>,
    pub item: i32,
    pub kind: String,
    pub uri: Option<String>,
    pub status: Option<i32>,
    pub value: Option<String>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
    pub result_accepted: Option<bool>,
    pub result_received_at: Option<i64>,
    pub frames: Vec<WindowsFrame>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFrame {
    pub message: i64,
    pub command: i64,
    pub start_byte: i64,
    pub end_byte: i64,
    pub total_bytes: i64,
    pub status: Option<i32>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
}
/// The shared command owner's closed public state, without a second state table.
#[derive(Clone, Copy, Debug)]
pub struct CommandStatus(pub rss_device_command::Status);
impl Serialize for CommandStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}
impl<'de> Deserialize<'de> for CommandStatus {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        rss_device_command::Status::ALL
            .into_iter()
            .find(|s| s.as_str() == value)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("unknown command state"))
    }
}
impl schemars::JsonSchema for CommandStatus {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CommandStatus".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"string","enum":rss_device_command::Status::ALL.map(|s|s.as_str())})
    }
}

pub const RELATION_SQL: &str = "SELECT o.id, o.device, CAST('command' AS text) AS kind, CAST('policy' AS text) AS source_kind, CAST(o.authority -> 'installation' ->> 'version' AS uuid) AS policy_version, CAST(o.authority -> 'installation' ->> 'policy' AS uuid) AS policy, CAST(o.input_context ->> 'deadline' AS bigint) AS deadline, COALESCE(d.status, 'unknown') AS status, CAST(octet_length(o.request) + octet_length(CAST(o.authority AS text)) + octet_length(CAST(o.input_context AS text)) + COALESCE(octet_length(CAST(o.dispatch_failure AS text)), 0) + 1024 AS bigint) AS input_bytes FROM mdm_registration_tasks.operations AS o LEFT JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE o.tenant_id = CAST($1 AS uuid)";
