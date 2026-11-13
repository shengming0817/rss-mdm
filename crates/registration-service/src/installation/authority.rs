use super::*;
use authorization::Permission;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Bootstrap {
        installation: Installation,
        bootstrap: Uuid,
        required: Vec<Permission>,
    },
    Cleanup {
        installation: Installation,
        bootstrap: Uuid,
        operation: Uuid,
        required: Vec<Permission>,
    },
}
impl Authority {
    pub fn installation(&self) -> &Installation {
        match self {
            Self::Bootstrap { installation, .. } | Self::Cleanup { installation, .. } => {
                installation
            }
        }
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Bootstrap { required, .. } | Self::Cleanup { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, value: Vec<Permission>) {
        match self {
            Self::Bootstrap { required, .. } | Self::Cleanup { required, .. } => *required = value,
        }
    }
    pub fn apple_owner(&self, _operation: Uuid) -> std::result::Result<String, Error> {
        Ok(format!(
            "agent-bootstrap:{}",
            match self {
                Self::Bootstrap { bootstrap, .. } | Self::Cleanup { bootstrap, .. } => bootstrap,
            }
        ))
    }
    pub async fn dispatch_ready(
        &self,
        materials: &Materials,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
    ) -> std::result::Result<bool, Error> {
        match self {
            Self::Bootstrap { installation, .. } => materials
                .installations
                .dispatch_ready_on(c, tenant, installation.id)
                .await
                .map_err(Into::into),
            Self::Cleanup { .. } => Ok(true),
        }
    }
    pub async fn valid(
        &self,
        materials: &Materials,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
    ) -> std::result::Result<bool, Error> {
        let i = self.installation();
        let active:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND state = 'active')").bind(tenant.to_string()).bind(i.device.into_uuid()).fetch_one(&mut *c).await.map_err(database::db)?;
        if !active {
            return Ok(false);
        }
        match self {
            Self::Bootstrap{bootstrap,..}=>{
                let current=match materials.installations.authorized_on(c,tenant,i.id).await {Ok(v)=>v,Err(crate::Error::Forbidden|crate::Error::Unauthorized|crate::Error::Conflict)=>return Ok(false),Err(e)=>return Err(e.into())};
                if i!=&current{return Ok(false);}
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 AND installation=$3 AND active AND state IN('prepared','signing','issued','consumed'))").bind(tenant.to_string()).bind(bootstrap).bind(i.id).fetch_one(c).await.map_err(database::db)
            }
            Self::Cleanup{bootstrap,operation,..}=>sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 AND installation=$3 AND cleanup=$4 AND state IN('issued','consumed') AND NOT cleanup_complete)").bind(tenant.to_string()).bind(bootstrap).bind(i.id).bind(operation).fetch_one(c).await.map_err(database::db),
        }
    }
}
