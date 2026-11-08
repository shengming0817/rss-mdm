//! DA diagnostic observations. The original device/audit transaction owns admission and settlement.
//! No observation mutates bindings, factors, native effects, trust acknowledgements or policy.
mod read;
mod storage;
use crate::{Error, Service, service::Change};
pub use read::{Page, Query, Report, View, WINDOW};
use rss_mdm_agent_wire::da;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service::{
    DevicePrincipal,
    device::{self, ConsumerUse, RegistrationKind, endpoints},
};
use rss_mdm_task_trust::configuration::ConfigurationService;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

/// Host-owned intake, freshness and history budgets; high-water survives history pruning.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub history_seconds: u32,
    pub history_count: u32,
    pub stale_seconds: u32,
    pub body_bytes: u32,
    pub reports_per_minute: u32,
    pub bytes_per_minute: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            history_seconds: 30 * 86400,
            history_count: 10000,
            stale_seconds: 900,
            body_bytes: 65536,
            reports_per_minute: 10000,
            bytes_per_minute: 64 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if self.history_seconds == 0
            || self.history_seconds > 366 * 86400
            || self.history_count == 0
            || self.history_count > 100000
            || self.stale_seconds == 0
            || self.body_bytes == 0
            || self.body_bytes > 65536
            || self.reports_per_minute == 0
            || self.bytes_per_minute < self.body_bytes
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
/// Immutable acceptance receipt. Source credibility remains explicitly reported.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub sequence: i64,
    pub received_at: i64,
    pub evidence: da::EvidenceLevel,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Status,
    Application,
}
impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Application => "application",
        }
    }
}

pub(crate) async fn admit(
    c: &mut PgConnection,
    service: &Service,
    p: &DevicePrincipal,
    identity: Option<&da::ReportIdentity>,
) -> Result<(), Error> {
    if p.profile() != StorageProfile::Da
        || p.kind() != RegistrationKind::DaDevice
        || p.installation() != service.service_id()?
        || p.tenant() != service.tenant
    {
        return Err(Error::Forbidden);
    }
    if let Some(i) = identity
        && (i.service_id != p.installation()
            || i.tenant.to_string() != p.tenant().to_string()
            || i.device_id != p.device())
    {
        return Err(Error::Forbidden);
    }
    endpoints::lock_da_in(c, &p.tenant().to_string(), p.device()).await?;
    device::require_use_in(c, p, ConsumerUse::DaConfiguration).await?;
    Ok(())
}
impl Service {
    pub async fn report_status(
        &self,
        p: &DevicePrincipal,
        input: &da::StatusReport,
        a: &RequestAudit,
    ) -> Result<Receipt, Error> {
        input.validate().map_err(|_| Error::Malformed)?;
        a.identify_device(&(p.device()).to_string());
        let document = serde_json::to_value(input).map_err(|_| Error::Malformed)?;
        self.write(a, (self, p, input, document), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, document) = ctx;
                admit(c, service, p, Some(&input.identity)).await?;
                storage::receive(c, service, p, Kind::Status, input.sequence, None, document).await
            })
        })
        .await
    }
    pub async fn report_application(
        &self,
        signing: &ConfigurationService,
        p: &DevicePrincipal,
        input: &da::ApplicationReport,
        a: &RequestAudit,
    ) -> Result<Receipt, Error> {
        input.validate().map_err(|_| Error::Malformed)?;
        a.identify_device(&(p.device()).to_string());
        let document = serde_json::to_value(input).map_err(|_| Error::Malformed)?;
        self.write(a, (self, signing, p, input, document), |ctx, c| {
            Box::pin(async move {
                let (service, signing, p, input, document) = ctx;
                admit(c, service, p, Some(&input.identity)).await?;
                // Historical exact retry remains recoverable after an artifact expires or is withdrawn.
                if let Some(value) = storage::replay(
                    c,
                    p,
                    Kind::Application,
                    input.sequence,
                    Some(input.operation_id),
                    document,
                )
                .await?
                {
                    return Ok(Change {
                        value,
                        replay: true,
                    });
                }
                let artifact = signing.read_on(c, input.artifact).await?;
                if artifact.digest != input.digest {
                    return Err(Error::Conflict);
                }
                let config = artifact.decode().map_err(|_| Error::Corrupt)?;
                if !config.permits(&input.identity, p.device()) {
                    return Err(Error::Forbidden);
                }
                // Reports are observations, including rejection of an expired or withdrawn candidate.
                // Publication/time/key-ACK admission belongs to distribution and trusted application,
                // and cannot be inferred from received/validated/applied labels supplied by a device.
                for source in &input.sources {
                    let value = signing.read_on(c, source.artifact).await?;
                    if value.digest != source.digest {
                        return Err(Error::Conflict);
                    }
                    if !value
                        .decode()
                        .map_err(|_| Error::Corrupt)?
                        .permits(&input.identity, p.device())
                    {
                        return Err(Error::Forbidden);
                    }
                }
                storage::receive(
                    c,
                    service,
                    p,
                    Kind::Application,
                    input.sequence,
                    Some(input.operation_id),
                    document,
                )
                .await
            })
        })
        .await
    }
}
