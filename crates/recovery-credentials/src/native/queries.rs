use super::*;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
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
        device: &str,
        id: Uuid,
    ) -> Result<Detail> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        let s = &self.transactions;
        let op = storage::load_on(c, s.tenant, &s.protection, id).await?;
        if op.device != device {
            return Err(Error::Forbidden.into());
        }
        let status: String = sqlx::query_scalar("SELECT mdm_recovery_tasks.native_status($1)")
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
        let observation =
            super::apple::observation_on(c, s.tenant, s.apple_results.clone(), &op, status, false)
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

pub const RELATION_SQL: &str = "SELECT o.id, o.device, CAST('command' AS text) AS kind, CAST('direct' AS text) AS source_kind, CAST(NULL AS uuid) AS policy_version, CAST(NULL AS uuid) AS policy, CAST(o.input_context ->> 'deadline' AS bigint) AS deadline, COALESCE(d.status, 'unknown') AS status, CAST(octet_length(o.request) + octet_length(CAST(o.authority AS text)) + octet_length(CAST(o.input_context AS text)) + COALESCE(octet_length(CAST(o.dispatch_failure AS text)), 0) + 1024 AS bigint) AS input_bytes FROM mdm_recovery_tasks.operations AS o LEFT JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE o.tenant_id = CAST($1 AS uuid)";
