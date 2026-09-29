//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::authorization::{Permission, Snapshot, UserGrant};
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionAuthority {
    AgentInstall {
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        operation: uuid::Uuid,
    },
    User {
        evidence: UserGrant,
    },
    RemoteOperation {
        tenant: String,
        operation: uuid::Uuid,
        device: String,
    },
    Policy {
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        remove: bool,
    },
}
impl ExecutionAuthority {
    pub async fn dispatch_ready(&self, c: &mut PgConnection) -> Result<bool, Error> {
        match self {
            Self::AgentInstall {
                tenant,
                version,
                device,
                operation,
                ..
            } => {
                crate::planning::policies::agent_install::dispatch_ready_on(
                    c, tenant, *version, device, *operation,
                )
                .await
            }
            _ => Ok(true),
        }
    }
    pub fn from_proof(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Self, Error> {
        Ok(Self::User {
            evidence: UserGrant::from_proof(snapshot, proof, device, permission)?,
        })
    }
    pub async fn valid(
        &self,
        conn: &mut PgConnection,
        permission: Permission,
        now: i64,
    ) -> Result<bool, Error> {
        match self {
            Self::AgentInstall {
                tenant,
                policy,
                version,
                device,
                operation,
            } => {
                if permission != Permission::SoftwareDeploy {
                    return Ok(false);
                }
                crate::planning::policies::agent_install::authorized_on(
                    conn, tenant, *policy, *version, device, *operation, now,
                )
                .await
            }
            Self::User { evidence } => evidence
                .valid(conn, permission, now)
                .await
                .map_err(Error::from),
            Self::RemoteOperation {
                tenant,
                operation,
                device,
            } => {
                if permission != Permission::FirewallWrite {
                    return Ok(false);
                }
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.remote_operations o JOIN mdm_planning.remote_operation_targets t ON(t.tenant_id,t.operation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND o.id=$2 AND NOT o.cancelled AND o.deadline>$4 AND o.frozen->>'kind'='configuration' AND t.device=$3 AND t.status='accepted')").bind(tenant).bind(operation).bind(device).bind(now).fetch_one(conn).await.map_err(db)
            }
            Self::Policy {
                tenant,
                policy,
                version,
                device,
                remove,
            } => {
                if permission != Permission::FirewallWrite {
                    return Ok(false);
                }
                let valid=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) JOIN mdm_policy.versions original ON original.tenant_id=p.tenant_id AND original.id=$3::uuid AND original.policy=$2::uuid WHERE p.tenant_id=$1::uuid AND p.enabled AND v.frozen->>'kind'='configuration' AND (v.frozen->'enabled',v.frozen->'platform')=(original.frozen->'enabled',original.frozen->'platform') AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$4)->>'state'='eligible'))")
                    .bind(tenant).bind(policy.to_string()).bind(version.to_string()).bind(device).fetch_one(&mut *conn).await.map_err(db)?;
                if !remove {
                    if !valid {
                        return Ok(false);
                    }
                    return sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) JOIN mdm_policy.versions expected ON expected.tenant_id=p.tenant_id AND expected.id=$3 WHERE p.tenant_id=$1::uuid AND p.enabled AND v.frozen->>'kind'='configuration' AND (v.frozen->'enabled',v.frozen->'platform') IS DISTINCT FROM(expected.frozen->'enabled',expected.frozen->'platform') AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded'))")
                        .bind(tenant).bind(device).bind(version).fetch_one(conn).await.map_err(db);
                }
                // Cleanup is admitted only for a supported immutable resource and no remaining desired owner.
                if valid {
                    return Ok(false);
                }
                let supported=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3 AND frozen->>'kind'='configuration' AND frozen->>'platform'='macos' AND frozen->>'exit'='remove')").bind(tenant).bind(version).bind(policy).fetch_one(&mut *conn).await.map_err(db)?;
                if !supported {
                    return Ok(false);
                }
                sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'action'->>'kind'='configuration' AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded'))")
                    .bind(tenant).bind(device).fetch_one(conn).await.map_err(db)
            }
        }
    }
}
