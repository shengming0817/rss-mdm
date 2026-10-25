//! Product audit necessity, independent of transport method and transaction outcome.
//! Business action labels remain with their producer; this is not a business registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditIntent {
    Routine,
    Management,
    Sensitive(SensitiveAction),
    Security,
}
/// Stable identifiers for disclosures requiring reliable evidence before delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensitiveAction {
    CredentialReveal,
    CertificatePrivateExport,
    AuditHistoryRead,
    ScriptContentRead,
    InventoryBulkExport,
    TelemetryBulkExport,
}
impl SensitiveAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialReveal => "credential.reveal",
            Self::CertificatePrivateExport => "certificate.private_export",
            Self::AuditHistoryRead => "audit.history_read",
            Self::ScriptContentRead => "script.content_read",
            Self::InventoryBulkExport => "inventory.bulk_export",
            Self::TelemetryBulkExport => "telemetry.bulk_export",
        }
    }
}
