//! Business capabilities borrowed by the Apple protocol owner.
use crate::protocol_types::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use uuid::Uuid;
pub struct Admission {
    pub command: AppleCommand,
    pub target: AppleRegistration,
    pub eligible: bool,
    pub dispatch: bool,
}
pub struct ConfigurationArtifact {
    pub artifact: rss_mdm_resource::Artifact,
    pub apple_silicon: bool,
    pub verified: rss_mdm_content_service::Verified,
}
pub trait Business: Send + Sync {
    fn prepare_wake<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        devices: Vec<String>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn wake_commands<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: String,

        after: Uuid,
    ) -> Pending<'a, WakePage>;
    fn software_enabled(&self) -> bool;
    fn settle_failures<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn artifact<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        asset: &'a rss_mdm_apple_mdm::native::ddm::AssetInput,
    ) -> Pending<'a, ConfigurationArtifact>;
    fn asset_authority<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, (rss_mdm_apple_mdm::native::request::Request, Target)>;

    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn authenticated<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()>;
    fn finish<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        collection: Option<Uuid>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn candidates<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        user: &'a str,
        after: Uuid,
    ) -> Pending<'a, Vec<Uuid>>;
    fn command<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, Admission>;
    fn settle<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
        input_version: &'a str,
        fact: rss_mdm_apple_mdm::native::evidence::Settlement,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn synchronized<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        fact: &'a Synchronized,
    ) -> Pending<'a, ()>;
    fn rejected<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        id: Uuid,
        reason: String,
    ) -> Pending<'a, ()>;
    fn declarations<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        user: &'a str,
        ids: Vec<Uuid>,
    ) -> Pending<'a, Vec<Admission>>;
    fn collection_eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> Pending<'a, bool>;
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()>;
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog>;
}
pub struct DetectionCatalog {
    pub bundles: Vec<String>,
    pub complete: bool,
    pub digest: [u8; 32],
}
pub trait Departure: Send + Sync {
    fn departed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        device: String,
    ) -> Pending<'a, ()>;
}

pub struct WakePage {
    pub next: Option<Uuid>,
    pub commands: Vec<(Uuid, String)>,
}
