//! Durable evidence rechecks the actual authorization rule and revision.
use crate::{Error, context::AuthorizedPrincipal, database::db, *};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationAuthority {
    permission: Permission,
    actor: crate::Actor,
    scope: Scope,
    basis: AuthorityBasis,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AuthorityBasis {
    Account { rules: Vec<Basis> },
    ApiKey { authority_revision: u64 },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Basis {
    id: uuid::Uuid,
    revision: u64,
    expires_at: Option<i64>,
}
impl OperationAuthority {
    /// Stable actor identity for native ownership; this conveys no current authority.
    pub fn actor(&self) -> &crate::Actor {
        &self.actor
    }

    pub fn from_proof(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Self, Error> {
        snapshot.require(proof, permission, Some(device))?;
        let scope = Scope::Device { id: device.into() };
        let basis = if let Some(key) = snapshot.key(proof)? {
            AuthorityBasis::ApiKey {
                authority_revision: key.authority_revision,
            }
        } else {
            AuthorityBasis::Account {
                rules: snapshot.authorization_bases(proof, &scope, permission)?,
            }
        };
        Ok(Self {
            permission,
            actor: proof.actor(),
            scope,
            basis,
        })
    }
    /// Freeze a real tenant permission independently of any device assignment.
    pub fn tenant(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<Self, Error> {
        if permission.device() {
            return Err(Error::Malformed);
        }
        snapshot.require(proof, permission, None)?;
        let scope = Scope::Tenant;
        let basis = if let Some(key) = snapshot.key(proof)? {
            AuthorityBasis::ApiKey {
                authority_revision: key.authority_revision,
            }
        } else {
            AuthorityBasis::Account {
                rules: snapshot.authorization_bases(proof, &scope, permission)?,
            }
        };
        Ok(Self {
            permission,
            actor: proof.actor(),
            scope,
            basis,
        })
    }
    /// Freeze only actual all-device rule evidence; future Scope members need no browser session.
    pub fn all_devices(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<Self, Error> {
        snapshot.require_all_devices(proof, permission)?;
        let scope = Scope::AllDevices;
        let basis = if let Some(key) = snapshot.key(proof)? {
            AuthorityBasis::ApiKey {
                authority_revision: key.authority_revision,
            }
        } else {
            AuthorityBasis::Account {
                rules: snapshot.authorization_bases(proof, &scope, permission)?,
            }
        };
        Ok(Self {
            permission,
            actor: proof.actor(),
            scope,
            basis,
        })
    }
    pub async fn valid(
        &self,
        conn: &mut PgConnection,
        permission: Permission,
        now: i64,
    ) -> Result<bool, Error> {
        if self.permission != permission {
            return Ok(false);
        }
        super::store::lock_shared(conn, self.actor.tenant_id(), self.actor.instance_id()).await?;
        // Typed deserialization still rejects damaged persisted documents. The SQL
        // owner is the single current-authority predicate, also used by bounded queries.
        match (&self.actor, &self.basis) {
            (
                crate::Actor::ApiKey {
                    instance,
                    tenant,
                    id,
                },
                AuthorityBasis::ApiKey { authority_revision },
            ) => {
                if !permission.api_key_allowed() {
                    return Ok(false);
                }
                let raw = sqlx::query_scalar::<_, serde_json::Value>("SELECT metadata FROM mdm_access.api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND authority_revision=$4 AND enabled AND NOT revoked AND (expires_at IS NULL OR expires_at>$5) AND (expires_at IS NULL OR to_timestamp(expires_at)>clock_timestamp())")
                    .bind(tenant).bind(instance).bind(id).bind(i64::try_from(*authority_revision).map_err(|_|Error::Corrupt)?).bind(now).fetch_optional(&mut *conn).await.map_err(db)?;
                if let Some(raw) = raw {
                    serde_json::from_value::<crate::api_key::KeyMetadata>(raw)
                        .map_err(|_| Error::Corrupt)?
                        .validate()?;
                }
            }
            (crate::Actor::Account { user }, AuthorityBasis::Account { rules }) => {
                for basis in rules {
                    if basis.expires_at.is_some_and(|until| now >= until) {
                        continue;
                    }
                    let raw = sqlx::query_scalar::<_, Option<serde_json::Value>>("SELECT document FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND revision=$4")
                        .bind(&user.tenant_id).bind(&user.instance_id).bind(basis.id).bind(i64::try_from(basis.revision).map_err(|_|Error::Corrupt)?).fetch_optional(&mut *conn).await.map_err(db)?.flatten();
                    if let Some(raw) = raw {
                        let rule: Rule =
                            serde_json::from_value(raw).map_err(|_| Error::Forbidden)?;
                        if let Subject::UserGroup { id } = rule.subject {
                            let group = sqlx::query_scalar::<_, Option<serde_json::Value>>("SELECT document FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3")
                                .bind(&user.tenant_id).bind(&user.instance_id).bind(id).fetch_optional(&mut *conn).await.map_err(db)?.flatten();
                            if let Some(raw) = group {
                                let _: UserGroup =
                                    serde_json::from_value(raw).map_err(|_| Error::Forbidden)?;
                            }
                        }
                    }
                }
            }
            _ => return Err(Error::Corrupt),
        }
        let requested = serde_json::to_value(permission).map_err(|_| Error::Corrupt)?;
        sqlx::query_scalar("SELECT mdm_access.operation_authority_valid($1,$2,$3)")
            .bind(serde_json::to_value(self).map_err(|_| Error::Corrupt)?)
            .bind(requested.as_str().ok_or(Error::Corrupt)?)
            .bind(now)
            .fetch_one(conn)
            .await
            .map_err(db)
    }
}
impl Snapshot {
    fn authorization_bases(
        &self,
        proof: &AuthorizedPrincipal,
        scope: &Scope,
        permission: Permission,
    ) -> Result<Vec<Basis>, Error> {
        self.effective(proof).map_err(Error::from).map(|grants| {
            grants
                .into_iter()
                .filter(|g| covers_scope(&g.grant, permission, scope))
                .map(|g| Basis {
                    id: g.rule_id,
                    revision: g.rule_revision,
                    expires_at: g.observation.map(|o| o.expires_at),
                })
                .collect()
        })
    }
}

fn covers_scope(grant: &Grant, permission: Permission, scope: &Scope) -> bool {
    match scope {
        Scope::AllDevices => grant.operation == permission && grant.scope == Scope::AllDevices,
        Scope::Device { id } => grant.covers(permission, Some(id)),
        Scope::Tenant => grant.covers(permission, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn future_device_authority_cannot_be_derived_from_one_device() {
        let device = Scope::Device { id: "one".into() };
        let scoped = Grant {
            operation: Permission::Enrollment,
            scope: device.clone(),
        };
        assert!(!covers_scope(
            &scoped,
            Permission::Enrollment,
            &Scope::AllDevices
        ));
        assert!(covers_scope(&scoped, Permission::Enrollment, &device));
        let all = Grant {
            operation: Permission::Enrollment,
            scope: Scope::AllDevices,
        };
        assert!(covers_scope(
            &all,
            Permission::Enrollment,
            &Scope::AllDevices
        ));
        assert!(covers_scope(&all, Permission::Enrollment, &device));
        assert!(!covers_scope(
            &all,
            Permission::SoftwareDeploy,
            &Scope::AllDevices
        ));
    }
}
