//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::authorization::{Permission, Snapshot, UserGrant};
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionAuthority {
    AgentInstall {
        package: Box<crate::planning::policies::agent_install::Package>,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        operation: uuid::Uuid,
    },
    User {
        evidence: Vec<UserGrant>,
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
        permissions: &[Permission],
    ) -> Result<Self, Error> {
        Ok(Self::User {
            evidence: permissions
                .iter()
                .map(|&p| UserGrant::from_proof(snapshot, proof, device, p))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn agent_package(&self) -> Option<&crate::planning::policies::agent_install::Package> {
        match self {
            Self::AgentInstall { package, .. } => Some(package),
            _ => None,
        }
    }
    pub async fn valid(
        &self,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        now: i64,
    ) -> Result<bool, Error> {
        if permissions.is_empty() {
            return Ok(false);
        }
        for &permission in permissions {
            if !self.valid_one(conn, key, permission, now).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn valid_one(
        &self,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
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
                ..
            } => {
                if permission != Permission::SoftwareDeploy {
                    return Ok(false);
                }
                crate::planning::policies::agent_install::authorized_on(
                    conn, tenant, *policy, *version, device, *operation, now,
                )
                .await
            }
            Self::User { evidence } => {
                for grant in evidence {
                    if grant.valid(conn, permission, now).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::RemoteOperation {
                tenant,
                operation,
                device,
            } => {
                let frozen=sqlx::query_scalar::<_,serde_json::Value>("SELECT o.frozen FROM mdm_planning.remote_operations o JOIN mdm_planning.remote_operation_targets t ON(t.tenant_id,t.operation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND o.id=$2 AND NOT o.cancelled AND o.deadline>$4 AND t.device=$3 AND t.status='accepted'").bind(tenant).bind(operation).bind(device).bind(now).fetch_optional(&mut *conn).await.map_err(db)?;
                let Some(frozen) = frozen else {
                    return Ok(false);
                };
                native_grant(conn, frozen, device, permission, now).await
            }
            Self::Policy {
                tenant,
                policy,
                version,
                device,
                remove,
            } => {
                let frozen=sqlx::query_scalar::<_,serde_json::Value>("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3").bind(tenant).bind(version).bind(policy).fetch_optional(&mut *conn).await.map_err(db)?;
                let Some(frozen) = frozen else {
                    return Ok(false);
                };
                if *remove && !native_grant(conn, frozen.clone(), device, permission, now).await? {
                    return Ok(false);
                }
                let expected: crate::planning::policies::Frozen =
                    serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
                let crate::planning::policies::Frozen::Configuration { native, exit, .. } =
                    expected
                else {
                    return Ok(false);
                };
                let tenant_id =
                    rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
                let native = native.open(
                    key,
                    tenant_id,
                    crate::planning::configuration::Owner::Policy {
                        policy: *policy,
                        version: *version,
                    },
                )?;
                if *remove
                    && (!matches!(exit, rss_mdm_policy::Exit::Remove) || native.remove.is_none())
                {
                    return Ok(false);
                }
                let expected_objects = native.objects()?;
                let expected = serde_json::to_vec(&(&native.target, &native.apply))
                    .map_err(|_| Error::Malformed)?;
                let mut after = uuid::Uuid::nil();
                let mut live = false;
                loop {
                    let rows=sqlx::query("SELECT p.id,v.id AS version,v.frozen,mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state' AS admission FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.enabled AND p.id>$3 AND p.definition->'action'->>'kind'='configuration' AND mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded' ORDER BY p.id LIMIT 64").bind(tenant).bind(device).bind(after).fetch_all(&mut *conn).await.map_err(db)?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        use sqlx::Row;
                        after = row.try_get("id").map_err(db)?;
                        let current_frozen: serde_json::Value =
                            row.try_get("frozen").map_err(db)?;
                        let current: crate::planning::policies::Frozen =
                            serde_json::from_value(current_frozen.clone())
                                .map_err(|_| Error::Malformed)?;
                        let crate::planning::policies::Frozen::Configuration {
                            native: other, ..
                        } = current
                        else {
                            return Ok(false);
                        };
                        let other = other.open(
                            key,
                            tenant_id,
                            crate::planning::configuration::Owner::Policy {
                                policy: after,
                                version: row.try_get("version").map_err(db)?,
                            },
                        )?;
                        if !other
                            .objects()?
                            .iter()
                            .any(|o| expected_objects.contains(o))
                        {
                            continue;
                        }
                        if *remove {
                            return Ok(false);
                        }
                        if serde_json::to_vec(&(&other.target, &other.apply))
                            .map_err(|_| Error::Malformed)?
                            != expected
                        {
                            return Ok(false);
                        }
                        // The operation belongs to its native content. Any live coowner of
                        // that exact input may authorize it after the original author exits.
                        if row.try_get::<String, _>("admission").map_err(db)? == "eligible"
                            && native_grant(conn, current_frozen, device, permission, now).await?
                        {
                            live = true;
                        }
                    }
                }
                Ok(*remove || live)
            }
        }
    }
}
async fn native_grant(
    conn: &mut PgConnection,
    frozen: serde_json::Value,
    device: &str,
    permission: Permission,
    now: i64,
) -> Result<bool, Error> {
    let frozen: crate::planning::policies::Frozen =
        serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
    let crate::planning::policies::Frozen::Configuration { grants, .. } = frozen else {
        return Ok(false);
    };
    let Some(grants) = grants.get(device).or_else(|| grants.get("*")) else {
        return Ok(false);
    };
    for grant in grants {
        if grant.valid(conn, permission, now).await? {
            return Ok(true);
        }
    }
    Ok(false)
}
