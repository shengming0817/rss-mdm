//! Registration-owned tenant defaults; all new grants read the same persisted settings.
use super::*;
use rss_mdm_authorization_service::Permission;
/// Maximum lifetime of an individual machine grant.
pub const GRANT_MAX_SECONDS: u32 = 604800;
/// Maximum lifetime of a reusable administrator configuration.
pub const CONFIGURATION_MAX_SECONDS: u32 = 31536000;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Values {
    pub grant_seconds: u32,
    pub configuration_default_seconds: u32,
    /// Empty disables new grants without revoking existing authority.
    pub platforms: Vec<runtime::TaskPlatform>,
}
impl Default for Values {
    fn default() -> Self {
        Self {
            grant_seconds: 86400,
            configuration_default_seconds: 86400,
            platforms: vec![runtime::TaskPlatform::Windows, runtime::TaskPlatform::Macos],
        }
    }
}
impl Values {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=GRANT_MAX_SECONDS).contains(&self.grant_seconds)
            || !(1..=CONFIGURATION_MAX_SECONDS).contains(&self.configuration_default_seconds)
            || self.platforms.len() > 2
            || self
                .platforms
                .iter()
                .enumerate()
                .any(|(i, p)| self.platforms[..i].contains(p))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub revision: u64,
    pub values: Values,
    pub grant_max_seconds: u32,
    pub configuration_max_seconds: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Update {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub values: Values,
}
/// Seed one newly registered tenant inside the installation operator's transaction.
/// The caller owns tenant scoping and commit; existing settings are never replaced.
pub async fn initialize_on(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_access.agent_enrollment_settings(tenant_id,revision,document) VALUES($1::uuid,1,$2)")
        .bind(tenant).bind(serde_json::to_value(Values::default()).map_err(|_| Error::Malformed)?)
        .execute(c).await.map_err(db)?;
    Ok(())
}
pub async fn read_on(c: &mut PgConnection, tenant: &str) -> Result<Settings, Error> {
    let row = sqlx::query("SELECT revision,document FROM mdm_access.agent_enrollment_settings WHERE tenant_id=$1::uuid")
        .bind(tenant).fetch_one(c).await.map_err(db)?;
    let values: Values =
        serde_json::from_value(row.try_get("document").map_err(db)?).map_err(|_| Error::Corrupt)?;
    values.validate().map_err(|_| Error::Corrupt)?;
    Ok(Settings {
        revision: u64::try_from(row.try_get::<i64, _>("revision").map_err(db)?)
            .map_err(|_| Error::Corrupt)?,
        values,
        grant_max_seconds: GRANT_MAX_SECONDS,
        configuration_max_seconds: CONFIGURATION_MAX_SECONDS,
    })
}
/// Lock the settings revision against a concurrent administrative disable.
pub async fn admit_on(
    c: &mut PgConnection,
    tenant: &str,
    platform: runtime::TaskPlatform,
) -> Result<Values, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,2674))")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let values = read_on(c, tenant).await?.values;
    if !values.platforms.contains(&platform) {
        return Err(Error::Forbidden);
    }
    Ok(values)
}
impl Service {
    pub async fn settings(&self, p: &AuthorizedPrincipal) -> Result<Settings, Failure> {
        p.manage(Permission::AgentEnrollmentRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize_on(&mut tx, p, Permission::AgentEnrollmentRead).await?;
        let out = read_on(&mut tx, p.tenant_id()).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    pub async fn update_settings(
        &self,
        p: &AuthorizedPrincipal,
        input: &Update,
        a: &RequestAudit,
    ) -> Result<Settings, Failure> {
        self.proof(p, a)?;
        p.manage(Permission::AgentEnrollmentWrite)?;
        version(wire::API_VERSION, input.operation_id)?;
        input.values.validate()?;
        a.operation(input.operation_id, "agent_settings_update");
        let d = digest(&(input.expected_revision, &input.values))?;
        self.write(a,(self,p,input,a,d),|ctx,c|Box::pin(async move {
            let (service,p,input,a,d)=ctx;
            authorize_on(c,p,Permission::AgentEnrollmentWrite).await?;
            let op=crate::operations::Operation{actor:crate::operations::Actor::from_authorized(p),key:input.operation_id,digest:d};
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2674))").bind(service.tenant.to_string()).execute(&mut *c).await.map_err(db)?;
            sqlx::query("SELECT tenant_id FROM mdm_access.agent_enrollment_settings WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(service.tenant.to_string()).fetch_one(&mut *c).await.map_err(db)?;
            if let Some(old)=crate::operations::replay(c,&op).await? {
                return Ok(Change{value:serde_json::from_str(&old).map_err(|_|Error::Corrupt)?,replay:true,digest:d.clone()});
            }
            let current=read_on(c,p.tenant_id()).await?;
            if current.revision!=input.expected_revision || current.revision>=i64::MAX as u64{return Err(Error::Conflict);}
            sqlx::query("UPDATE mdm_access.agent_enrollment_settings SET revision=revision+1,document=$2 WHERE tenant_id=$1::uuid")
                .bind(p.tenant_id()).bind(serde_json::to_value(&input.values).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
            p.manage(Permission::AgentEnrollmentWrite)?;
            let out=read_on(c,p.tenant_id()).await?;
            crate::operations::save(c,&op,&serde_json::to_string(&out).map_err(|_|Error::Corrupt)?,a).await?;
            Ok(Change{value:out,replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
}
