//! Native credential authority is revalidated at dispatch on the initiating connection.
use super::*;
use authorization::{
    Actor, OperationAuthority, Permission, Snapshot, context::AuthorizedPrincipal,
};
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub operation: Uuid,
    pub required: Vec<Permission>,
    pub actor: Actor,
    pub grants: Vec<(Permission, OperationAuthority)>,
}
impl Authority {
    pub fn admitted(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        registration: Uuid,
        generation: i64,
        operation: Uuid,
        permissions: Vec<Permission>,
    ) -> std::result::Result<Self, Error> {
        let grants = permissions
            .iter()
            .map(|p| OperationAuthority::from_proof(snapshot, proof, device, *p).map(|a| (*p, a)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            device: device.into(),
            registration,
            generation,
            operation,
            required: permissions,
            actor: proof.actor(),
            grants,
        })
    }
    pub fn required(&self) -> &[Permission] {
        &self.required
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        self.required = permissions
    }
    pub fn apple_owner(&self, _operation: Uuid) -> std::result::Result<String, Error> {
        Ok(format!(
            "actor:{}:{}",
            self.actor.instance_id(),
            self.actor.subject()
        ))
    }
    pub async fn valid(
        &self,
        _materials: &Materials,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
    ) -> std::result::Result<bool, Error> {
        if self.actor.tenant_id() != tenant.to_string() || self.required.is_empty() {
            return Ok(false);
        }
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND generation=$4 AND state='active')").bind(tenant.to_string()).bind(self.registration).bind(&self.device).bind(self.generation).fetch_one(&mut *c).await.map_err(database::db)?;
        if !active
            || !rss_mdm_registration_service::lifecycle::work_allowed_in(
                c,
                &tenant.to_string(),
                &self.device,
            )
            .await?
        {
            return Ok(false);
        }
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(database::db)?;
        for permission in &self.required {
            let Some((_, grant)) = self.grants.iter().find(|(p, _)| p == permission) else {
                return Ok(false);
            };
            if !grant.valid(c, *permission, now).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
