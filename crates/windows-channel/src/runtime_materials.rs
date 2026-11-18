//! Windows enrollment material snapshots over shared process resources.
use crate::{Error, HttpState, Windows, database::db};
use rss_transactional_messaging::fence::ExecutionBinding;
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc};

/// Typed Windows owner material, installed by the existing maintenance entry.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub provider_id: String,
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub lifetime: rss_mdm_certificate::windows::Lifetime,
    pub entra: Option<crate::entra::Config>,
}
pub struct Runtime {
    #[cfg(feature = "integration")]
    fixture: Option<(u16, reqwest::Certificate)>,
    pub enrollment_origin: String,
    pub management_origin: String,
    pub additional_management_origins: Vec<String>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    authority: rss_identity_postgres::Authority,
    verifier: Arc<dyn rss_mdm_authorization_service::entra::EntraTokenVerifier>,
    clock: Arc<dyn rss_observation::Clock>,
    push: tokio::sync::Mutex<BTreeMap<String, (i64, Arc<crate::push::Push>)>>,
}
impl Runtime {
    pub fn enrollment_username(&self, enrollment: uuid::Uuid) -> Result<String, Error> {
        let origin: axum::http::Uri = self
            .enrollment_origin
            .parse()
            .map_err(|_| Error::Malformed)?;
        Ok(format!(
            "{enrollment}@{}",
            origin.host().ok_or(Error::Malformed)?
        ))
    }

    pub fn new(
        enrollment_origin: String,
        management_origin: String,
        additional_management_origins: Vec<String>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        authority: rss_identity_postgres::Authority,
        verifier: Arc<dyn rss_mdm_authorization_service::entra::EntraTokenVerifier>,
        clock: Arc<dyn rss_observation::Clock>,
    ) -> Self {
        Self {
            enrollment_origin,
            management_origin,
            additional_management_origins,
            protection,
            authority,
            verifier,
            clock,
            #[cfg(feature = "integration")]
            fixture: None,
            push: Default::default(),
        }
    }
    #[cfg(feature = "integration")]
    pub fn with_loopback_provider(mut self, port: u16, root: reqwest::Certificate) -> Self {
        self.fixture = Some((port, root));
        self
    }
    pub fn request_id(&self, username: &str) -> Result<uuid::Uuid, Error> {
        let (local, host) = username.split_once('@').ok_or(Error::Unauthorized)?;
        let expected: axum::http::Uri = self
            .enrollment_origin
            .parse()
            .map_err(|_| Error::Malformed)?;
        let id = uuid::Uuid::parse_str(local).map_err(|_| Error::Unauthorized)?;
        if id.is_nil() || expected.host() != Some(host) || local != id.to_string() {
            return Err(Error::Unauthorized);
        }
        Ok(id)
    }
    pub async fn load(
        &self,
        app: &HttpState,
        execution: ExecutionBinding,
    ) -> Result<Arc<Windows>, Error> {
        let now = app
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(crate::Failure::Clock))?;
        let trust = app
            .pki
            .current(execution, rss_mdm_agent_wire::pki::Purpose::Windows, now)
            .await
            .map_err(|error| match error {
                rss_mdm_pki_service::Error::Storage => Error::Unavailable(crate::Failure::Database),
                _ => Error::Conflict,
            })?;
        if trust.public().map_err(|_| Error::Conflict)?.origin != self.management_origin {
            return Err(Error::Conflict);
        }
        let tenant = execution.tenant().to_string();
        let mut tx = app.access.snapshot(&tenant).await?;
        let row=sqlx::query("SELECT provider_id,poll,lifetime,entra_provider,entra_token,entra_callbacks FROM mdm_windows.enrollment_configuration WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unsupported)?;
        let poll = serde_json::from_value(row.try_get("poll").map_err(db)?)
            .map_err(|_| Error::Conflict)?;
        let lifetime = serde_json::from_value(row.try_get("lifetime").map_err(db)?)
            .map_err(|_| Error::Conflict)?;
        let ca = rss_mdm_device_trust::windows::WindowsDeviceTrust::from_trust(trust)
            .and_then(|ca| ca.with_lifetime(lifetime))
            .map_err(|_| Error::Conflict)?;
        let mut windows = Windows::new(
            self.enrollment_origin.clone(),
            self.management_origin.clone(),
            row.try_get("provider_id").map_err(db)?,
            ca,
            app.providers.clone(),
            self.protection.clone(),
            poll,
        )?;
        windows.additional_management_origins = self.additional_management_origins.clone();
        if let Some(provider) = row
            .try_get::<Option<uuid::Uuid>, _>("entra_provider")
            .map_err(db)?
        {
            let config = crate::entra::Config {
                provider_id: provider,
                token: serde_json::from_value(row.try_get("entra_token").map_err(db)?)
                    .map_err(|_| Error::Conflict)?,
                native_callbacks: row.try_get("entra_callbacks").map_err(db)?,
            };
            let authority = rss_identity_postgres::EntraAuthority::new(
                self.authority.clone(),
                self.verifier.clone(),
                execution.tenant(),
                rss_identity_core::federation::ProviderId::parse(&provider.to_string())
                    .map_err(|_| Error::Conflict)?,
                config.token.clone(),
            )
            .map_err(|_| Error::Conflict)?;
            windows.entra = Some(Arc::new(crate::entra::Entra::new(
                authority, execution, config,
            )?));
        }
        let revision: Option<i64> = sqlx::query_scalar(
            "SELECT desired_revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid",
        )
        .bind(&tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .flatten();
        // WNS only wakes the client; losing its eligibility must preserve client-initiated MDM.
        // Check before either cache reuse or material loading, retaining real storage errors.
        if let Some(revision) = revision
            && crate::wns_materials::is_selected(&mut tx, &tenant, revision).await?
        {
            let mut transports = self.push.lock().await;
            let push = if let Some((old, push)) = transports.get(&tenant)
                && *old == revision
            {
                push.clone()
            } else {
                let push = crate::wns_materials::load(
                    &mut tx,
                    &tenant,
                    revision,
                    &app.protection,
                    self.clock.clone(),
                    true,
                )
                .await?;
                #[cfg(feature = "integration")]
                let push = match &self.fixture {
                    Some((port, root)) => push.with_loopback_provider(*port, root.clone())?,
                    None => push,
                };
                let push = Arc::new(push);
                transports.insert(tenant.clone(), (revision, push.clone()));
                push
            };
            windows.push = Some(push);
        } else {
            self.push.lock().await.remove(&tenant);
        }
        tx.rollback().await.map_err(db)?;
        Ok(Arc::new(windows))
    }
}

pub async fn install_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    input: &Configuration,
) -> Result<(), Error> {
    input.poll.validate().map_err(|_| Error::Malformed)?;
    if input.provider_id.is_empty()
        || input.provider_id.len() > 128
        || matches!(
            input.lifetime,
            rss_mdm_certificate::windows::Lifetime::Development { .. }
        )
    {
        return Err(Error::Malformed);
    }
    let (provider, token, callbacks) = match &input.entra {
        Some(config) => {
            config.token.validate().map_err(|_| Error::Malformed)?;
            (
                Some(config.provider_id),
                Some(serde_json::to_value(&config.token).map_err(|_| Error::Malformed)?),
                config.native_callbacks.clone(),
            )
        }
        None => (None, None, Vec::new()),
    };
    sqlx::query("INSERT INTO mdm_windows.enrollment_configuration(tenant_id,provider_id,poll,lifetime,entra_provider,entra_token,entra_callbacks) VALUES($1::uuid,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id) DO UPDATE SET provider_id=EXCLUDED.provider_id,poll=EXCLUDED.poll,lifetime=EXCLUDED.lifetime,entra_provider=EXCLUDED.entra_provider,entra_token=EXCLUDED.entra_token,entra_callbacks=EXCLUDED.entra_callbacks").bind(tenant.to_string()).bind(&input.provider_id).bind(serde_json::to_value(&input.poll).map_err(|_|Error::Malformed)?).bind(serde_json::to_value(input.lifetime).map_err(|_|Error::Malformed)?).bind(provider).bind(token).bind(callbacks).execute(c).await.map_err(db)?;
    Ok(())
}
