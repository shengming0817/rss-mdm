//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use super::*;
use crate::{Error, access_store::db, identity::Principal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Approval {
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
impl Approval {
    pub(crate) fn from_proof(
        snapshot: &Snapshot,
        proof: &Principal,
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
        proof: &Principal,
        device: &str,
        permission: Permission,
    ) -> Result<Vec<Basis>, Error> {
        self.effective(proof).map(|grants| {
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
