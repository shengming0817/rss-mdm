//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use super::*;
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExecutionAuthority {
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
    pub(crate) fn from_proof(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Self, Error> {
        Ok(Self::User {
            evidence: UserGrant::from_proof(snapshot, proof, device, permission)?,
        })
    }
    pub(crate) async fn valid(
        &self,
        conn: &mut PgConnection,
        permission: Permission,
        now: i64,
    ) -> Result<bool, Error> {
        match self {
            Self::User { evidence } => evidence.valid(conn, permission, now).await,
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
                sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'behavior'->>'kind'='configuration' AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded'))")
                    .bind(tenant).bind(device).fetch_one(conn).await.map_err(db)
            }
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct UserGrant {
    permission: Permission,
    user: User,
    device: String,
    rules: Vec<Basis>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Basis {
    id: uuid::Uuid,
    revision: u64,
    expires_at: Option<i64>,
}
impl UserGrant {
    pub(crate) fn from_proof(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Self, Error> {
        snapshot.require(proof, permission, Some(device))?;
        let rules = snapshot.approval_bases(proof, device, permission)?;
        Ok(Self {
            permission,
            user: proof.user(),
            device: device.into(),
            rules,
        })
    }
    pub(crate) async fn valid(
        &self,
        conn: &mut PgConnection,
        permission: Permission,
        now: i64,
    ) -> Result<bool, Error> {
        if self.permission != permission {
            return Ok(false);
        }
        super::store::lock(conn, &self.user.tenant_id, &self.user.instance_id).await?;
        for basis in &self.rules {
            if basis.expires_at.is_some_and(|until| now >= until) {
                continue;
            }
            let row = sqlx::query("SELECT revision,document::text FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid")
                .bind(&self.user.tenant_id).bind(&self.user.instance_id).bind(basis.id.to_string()).fetch_optional(&mut *conn).await.map_err(db)?;
            let Some(row) = row else { continue };
            if row.try_get::<i64, _>("revision").map_err(db)? as u64 != basis.revision {
                continue;
            }
            let Some(raw) = row.try_get::<Option<String>, _>("document").map_err(db)? else {
                continue;
            };
            let rule: Rule = serde_json::from_str(&raw).map_err(|_| Error::Forbidden)?;
            if !rule
                .grants
                .iter()
                .any(|g| g.covers(self.permission, Some(&self.device)))
            {
                continue;
            }
            match rule.subject {
                Subject::User { user } if user == self.user => return Ok(true),
                Subject::IdpGroup { .. } | Subject::Department { .. }
                    if basis.expires_at.is_some() =>
                {
                    return Ok(true);
                }
                Subject::UserGroup { id } => {
                    let raw = sqlx::query_scalar::<_,Option<String>>("SELECT document::text FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid")
                        .bind(&self.user.tenant_id).bind(&self.user.instance_id).bind(id.to_string()).fetch_optional(&mut *conn).await.map_err(db)?.flatten();
                    if let Some(raw) = raw {
                        let group: UserGroup =
                            serde_json::from_str(&raw).map_err(|_| Error::Forbidden)?;
                        if group.enabled && group.members.contains(&self.user) {
                            return Ok(true);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }
}
impl Snapshot {
    fn approval_bases(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Vec<Basis>, Error> {
        self.effective(proof).map_err(Error::from).map(|grants| {
            grants
                .into_iter()
                .filter(|g| g.grant.covers(permission, Some(device)))
                .map(|g| Basis {
                    id: g.rule_id,
                    revision: g.rule_revision,
                    expires_at: g.observation.map(|o| o.expires_at),
                })
                .collect()
        })
    }
}
