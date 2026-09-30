//! Durable evidence rechecks the actual authorization rule and revision.
use crate::{Error, context::AuthorizedPrincipal, database::db, *};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserGrant {
    permission: Permission,
    user: User,
    scope: Scope,
    rules: Vec<Basis>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Basis {
    id: uuid::Uuid,
    revision: u64,
    expires_at: Option<i64>,
}
impl UserGrant {
    pub fn from_proof(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        permission: Permission,
    ) -> Result<Self, Error> {
        snapshot.require(proof, permission, Some(device))?;
        let scope = Scope::Device { id: device.into() };
        let rules = snapshot.approval_bases(proof, &scope, permission)?;
        Ok(Self {
            permission,
            user: proof.user(),
            scope,
            rules,
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
        let rules = snapshot.approval_bases(proof, &scope, permission)?;
        Ok(Self {
            permission,
            user: proof.user(),
            scope,
            rules,
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
                .any(|g| covers_scope(g, self.permission, &self.scope))
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
