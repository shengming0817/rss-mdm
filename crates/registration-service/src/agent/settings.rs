//! Registration-owned tenant defaults; all new grants read the same persisted settings.
use super::*;
use rss_mdm_authorization_service::Permission;
/// Installer consumer reads this exact UTF-8 JSON basename beside the EXE/PKG.
pub const CONFIGURATION_FILENAME: &str = "rss-agent-enrollment.json";

/// Presentation metadata stays outside persisted immutable settings receipts.
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverySettings {
    #[serde(flatten)]
    pub settings: Settings,
    pub configuration_filename: &'static str,
}
impl From<Settings> for DeliverySettings {
    fn from(settings: Settings) -> Self {
        Self {
            settings,
            configuration_filename: CONFIGURATION_FILENAME,
        }
    }
}
/// Maximum lifetime of an individual machine grant.
pub const GRANT_MAX_SECONDS: u32 = 604800;
/// Maximum lifetime of a reusable administrator configuration.
pub const CONFIGURATION_MAX_SECONDS: u32 = 31536000;
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Values {
    pub grant_seconds: u32,
    pub configuration_default_seconds: u32,
    /// Empty disables new grants without revoking existing authority.
    pub platforms: Vec<runtime::TaskPlatform>,
}
impl Default for Values {
    fn default() -> Self {
        serde_json::from_str(
            crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm)
                .agent_default_values,
        )
        .expect("fixed tenant defaults")
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
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub revision: u64,
    pub values: Values,
    pub grant_max_seconds: u32,
    pub configuration_max_seconds: u32,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Update {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub values: Values,
}
/// Seed one newly registered tenant inside the installation operator's transaction.
/// The caller owns tenant scoping and commit; existing settings are never replaced.
pub async fn initialize_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<(), Error> {
    sqlx::query(crate::storage_profile::sql(profile).agent_settings_initialize_on_1)
        .bind(tenant)
        .bind(serde_json::to_value(Values::default()).map_err(|_| Error::Malformed)?)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// Fresh-install seed SQL shares the persisted default value definition.
pub fn tenant_seed_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    crate::storage_profile::sql(profile).agent_settings_tenant_seed_sql_1
}
pub async fn read_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
) -> Result<Settings, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).agent_settings_read_on_1)
        .bind(tenant)
        .fetch_one(c)
        .await
        .map_err(db)?;
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    platform: runtime::TaskPlatform,
) -> Result<Values, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,2674))")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let values = read_on(profile, c, tenant).await?.values;
    if !values.platforms.contains(&platform) {
        return Err(Error::Forbidden);
    }
    Ok(values)
}
impl Service {
    pub async fn settings(&self, p: &AuthorizedPrincipal) -> Result<Settings, Failure> {
        let profile = self.profile();

        p.manage(Permission::AgentEnrollmentRead)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        authorize_on(profile, &mut tx, p, Permission::AgentEnrollmentRead).await?;
        let out = read_on(profile, &mut tx, p.tenant_id()).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    pub async fn update_settings(
        &self,
        p: &AuthorizedPrincipal,
        input: &Update,
        a: &RequestAudit,
    ) -> Result<Settings, Failure> {
        let profile = self.profile();

        self.proof(p, a)?;
        p.manage(Permission::AgentEnrollmentWrite)?;
        version(wire::API_VERSION, input.operation_id)?;
        input.values.validate()?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            input.operation_id,
            "agent_settings_update",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let d = digest(&(input.expected_revision, &input.values))?;
        self.write(a, (self, p, input, a, d), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, a, d) = ctx;
                authorize_on(profile, c, p, Permission::AgentEnrollmentWrite).await?;
                let op = crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: input.operation_id,
                    digest: d,
                };
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2674))")
                    .bind(service.tenant.to_string())
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                sqlx::query(crate::storage_profile::sql(profile).agent_settings_update_settings_1)
                    .bind(service.tenant.to_string())
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
                if let Some(old) = crate::operations::replay(profile, c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                    });
                }
                let current = read_on(profile, c, p.tenant_id()).await?;
                if current.revision != input.expected_revision
                    || current.revision >= i64::MAX as u64
                {
                    return Err(Error::Conflict);
                }
                sqlx::query(crate::storage_profile::sql(profile).agent_settings_update_settings_2)
                    .bind(p.tenant_id())
                    .bind(serde_json::to_value(&input.values).map_err(|_| Error::Malformed)?)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                p.manage(Permission::AgentEnrollmentWrite)?;
                let out = read_on(profile, c, p.tenant_id()).await?;
                crate::operations::save(
                    profile,
                    c,
                    &op,
                    &serde_json::to_string(&out).map_err(|_| Error::Corrupt)?,
                    a,
                    false,
                )
                .await?;
                Ok(Change {
                    value: out,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_lifetime_rejects_above_seven_days() {
        let mut values = Values {
            grant_seconds: 604800,
            ..Values::default()
        };
        assert!(values.validate().is_ok());
        values.grant_seconds = 604801;
        assert!(matches!(values.validate(), Err(Error::Malformed)));
    }
}
