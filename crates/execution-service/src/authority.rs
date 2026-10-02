//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::authorization::{Permission, Snapshot, UserGrant};
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionAuthority {
    AgentInstall {
        required: Vec<Permission>,
        package: Box<crate::agent_install::Package>,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        operation: uuid::Uuid,
    },
    User {
        required: Vec<Permission>,
        evidence: Vec<UserGrant>,
    },
    RemoteOperation {
        required: Vec<Permission>,
        tenant: String,
        operation: uuid::Uuid,
        device: String,
    },
    Policy {
        required: Vec<Permission>,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        remove: bool,
    },
}
impl ExecutionAuthority {
    pub async fn dispatch_ready(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        c: &mut PgConnection,
    ) -> Result<bool, Error> {
        match self {
            Self::AgentInstall {
                tenant,
                version,
                device,
                operation,
                ..
            } => {
                crate::agent_install::dispatch_ready_on(
                    source, c, tenant, *version, device, *operation,
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
            required: permissions.to_vec(),
            evidence: permissions
                .iter()
                .map(|&p| UserGrant::from_proof(snapshot, proof, device, p))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::User { required, .. }
            | Self::AgentInstall { required, .. }
            | Self::RemoteOperation { required, .. }
            | Self::Policy { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        match self {
            Self::User { required, .. }
            | Self::AgentInstall { required, .. }
            | Self::RemoteOperation { required, .. }
            | Self::Policy { required, .. } => *required = permissions,
        }
    }
    pub fn agent_package(&self) -> Option<&crate::agent_install::Package> {
        match self {
            Self::AgentInstall { package, .. } => Some(package),
            _ => None,
        }
    }
    pub async fn valid(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        now: i64,
    ) -> Result<bool, Error> {
        if permissions.is_empty() {
            return Ok(false);
        }
        let mut permissions = permissions.to_vec();
        permissions.extend_from_slice(self.required());
        permissions.sort();
        permissions.dedup();
        for permission in permissions {
            if !self.valid_one(source, conn, key, permission, now).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn valid_one(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permission: Permission,
        now: i64,
    ) -> Result<bool, Error> {
        match self {
            Self::AgentInstall { .. } => {
                if permission != Permission::SoftwareDeploy {
                    return Ok(false);
                }
                crate::agent_install::authorized_on(source, conn, self, now).await
            }
            Self::User { evidence, .. } => {
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
                ..
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
                ..
            } => {
                let frozen=sqlx::query_scalar::<_,serde_json::Value>("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3").bind(tenant).bind(version).bind(policy).fetch_optional(&mut *conn).await.map_err(db)?;
                let Some(frozen) = frozen else {
                    return Ok(false);
                };
                if *remove && !native_grant(conn, frozen.clone(), device, permission, now).await? {
                    return Ok(false);
                }
                let expected: crate::frozen::Frozen =
                    serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
                let crate::frozen::Frozen::Configuration { native, exit, .. } = expected else {
                    return Ok(false);
                };
                let tenant_id =
                    rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
                let native = native.open(
                    key,
                    tenant_id,
                    crate::configuration::Owner::Policy {
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
                    let rows = source
                        .candidates_on(
                            conn,
                            tenant_id,
                            device,
                            crate::source_authority::CandidateKind::Configuration,
                            after,
                        )
                        .await?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        after = row.policy;
                        let current_frozen: serde_json::Value = sqlx::query_scalar("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3").bind(tenant).bind(row.version).bind(row.policy).fetch_one(&mut *conn).await.map_err(db)?;
                        let current: crate::frozen::Frozen =
                            serde_json::from_value(current_frozen.clone())
                                .map_err(|_| Error::Malformed)?;
                        let crate::frozen::Frozen::Configuration { native: other, .. } = current
                        else {
                            return Ok(false);
                        };
                        let other = other.open(
                            key,
                            tenant_id,
                            crate::configuration::Owner::Policy {
                                policy: after,
                                version: row.version,
                            },
                        )?;
                        if !other
                            .objects()?
                            .iter()
                            .any(|o| expected_objects.iter().any(|expected| o.overlaps(expected)))
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
                        if matches!(
                            row.admission,
                            crate::source_authority::ScopeAdmission::Eligible { .. }
                        ) && native_grant(conn, current_frozen, device, permission, now).await?
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
    let frozen: crate::frozen::Frozen =
        serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
    let crate::frozen::Frozen::Configuration { grants, .. } = frozen else {
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
