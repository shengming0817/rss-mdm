//! Apple-owned native command, declaration and wake coordinates.
use crate::Error;
use rss_mdm_audit_integration::Fact;
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
#[derive(Clone)]
pub enum Target {
    Device,
    User { user_id: String },
}
impl Target {
    pub fn user_key(&self) -> &str {
        match self {
            Self::Device => "",
            Self::User { user_id } => user_id,
        }
    }
}
#[derive(Clone, Copy)]
pub enum ControlKind {
    Restart,
    Lock,
    Wipe,
}
pub struct Reply {
    pub bytes: Vec<u8>,
    pub facts: Vec<Fact>,
}

use uuid::Uuid;
pub struct AppleRegistration {
    pub tenant: String,
    pub device: String,
    pub registration: uuid::Uuid,
    pub generation: i64,
}
pub trait AppleProfiles: Send + Sync {
    fn declaration_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user: &'a str,
    ) -> Pending<'a, Vec<Uuid>>;

    fn previous_declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user: String,
        owner: String,
    ) -> Pending<'a, Vec<Uuid>>;

    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        target: AppleRegistration,
        command: AppleCommand,
    ) -> Pending<'a, ()>;
    fn previous_profiles<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
        identifier: String,
    ) -> Pending<'a, Vec<Uuid>>;
}
pub trait AppleCollections: Send + Sync {
    fn prepare_native_collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        id: Uuid,
    ) -> Pending<'a, Vec<Fact>>;
    fn pending_collections<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        user_key: String,
        limit: usize,
    ) -> Pending<'a, Vec<PendingCollection>>;
}
pub trait ApplePush: Send + Sync {
    fn needs_prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool>;
    fn push_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, bool>;
    fn push_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, Vec<PushCandidate>>;
    fn reject_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        user_key: String,
        revision: i64,
        scope: String,
    ) -> Pending<'a, ()>;
    fn defer_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        user_key: String,
    ) -> Pending<'a, ()>;
    fn lease_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Uuid,
        registration: Uuid,
        user_key: String,
        configuration: [u8; 32],
    ) -> Pending<'a, ()>;
    fn settle_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Wake,
        status: Option<u16>,
        outcome: PushOutcome,
    ) -> Pending<'a, Option<u64>>;
    fn maintenance_due<'a>(
        &'a self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, bool>;
}
pub enum AppleEvidence {
    Declarations(Option<Box<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>>),
    Observations(Vec<rss_mdm_apple_mdm::native::evidence::Observation>),
}
pub trait AppleResults: Send + Sync {
    /// Bounded evidence for one authorized page; all native decoding stays with Apple.
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AppleEvidence>>;
    fn declaration_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        generation: i64,
        after: Option<Uuid>,
        limit: usize,
    ) -> Pending<'a, Vec<(Uuid, String)>>;

    /// Check current-registration platform evidence without issuing a command.
    fn control_applicability<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        requests: &'a [AppleControlCheck],
    ) -> Pending<'a, std::collections::BTreeMap<usize, Result<(), rss_mdm_apple_mdm::native::Error>>>;
    /// Server publication withdrawal is distinct from native object absence.
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool>;

    fn declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        native_values: bool,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>>;

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        request: rss_mdm_apple_mdm::native::request::Request,
        native_values: bool,
    ) -> Pending<'a, Vec<rss_mdm_apple_mdm::native::evidence::Observation>>;
}
pub trait AppleAttempt: Send {
    fn operation(&self) -> Option<Uuid>;
    fn settle<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        accepted: bool,
        command: AppleCommand,
        target: AppleRegistration,
    ) -> Pending<'a, rss_mdm_apple_mdm::native::evidence::Settlement>;
}
/// An already decoded protocol request; only the channel can inspect its native content.
pub trait AppleExchange: Send {
    fn user_key(&self) -> &str;
    fn current<'a>(&'a self, c: &'a mut PgConnection, p: &'a DevicePrincipal) -> Pending<'a, ()>;
    fn reception<'a>(
        self: Box<Self>,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, AppleReception>;
}
pub enum AppleReception {
    Idle,
    Replay,
    Collection { facts: Vec<Fact>, run: Option<Uuid> },
    Command(Box<dyn AppleAttempt>),
}
pub struct AppleCommand {
    pub operation: Uuid,
    pub owner: String,
    pub authorized_declarations: Vec<Uuid>,
    pub assets: Vec<rss_mdm_apple_mdm::native::ddm::AssetBinding>,
    pub deadline: i64,
    pub input_version: String,
    pub target: Target,
    pub request: rss_mdm_apple_mdm::native::request::Request,
}
/// Native applicability failures are operation evidence, not a failed device connection.
pub enum AppleDispatch {
    Ready(Vec<u8>),
    Waiting,
    Rejected(rss_mdm_apple_mdm::native::Error),
}
impl From<Option<Vec<u8>>> for AppleDispatch {
    fn from(value: Option<Vec<u8>>) -> Self {
        match value {
            Some(bytes) => Self::Ready(bytes),
            None => Self::Waiting,
        }
    }
}
pub trait Apple: Send + Sync {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        udid: &'a str,
        user_key: &'a str,
    ) -> Pending<'a, ()>;
    fn command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch>;
    fn prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch>;
    /// Deliver device trust maintenance before business commands.
    fn trust<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, Reply>;
    fn collection<'a>(
        &'a self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user_key: &'a str,
    ) -> Pending<'a, Reply>;
}

#[derive(Clone)]
pub struct Wake {
    pub id: Uuid,
    pub registration: Uuid,
    pub revision: i64,
    pub user_key: String,
    pub token: Vec<u8>,
    pub magic: String,
}
pub struct PushCandidate {
    pub generation: i64,
    pub registration: Uuid,
    pub device: String,
    pub revision: i64,
    pub user_key: String,
    pub disposition: PushDisposition,
}
pub enum PushDisposition {
    Ready { token: Vec<u8>, magic: String },
    Inactive,
    Invalid { scope: String },
}
pub struct PendingCollection {
    pub id: Uuid,
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    Accepted,
    Retryable,
    Unregistered,
    Rejected,
}
impl PushOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Retryable => "retryable",
            Self::Unregistered => "unregistered",
            Self::Rejected => "rejected",
        }
    }
}

/// A native check-in participant retains protocol bytes at the channel owner.
pub trait AppleDdmExchange: Send {
    fn user_key(&self) -> &str;
    fn current<'a>(&'a self, c: &'a mut PgConnection, p: &'a DevicePrincipal) -> Pending<'a, ()>;
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Vec<Uuid>>;
    fn respond<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        authorized: Vec<Uuid>,
    ) -> Pending<'a, AppleDdmReply>;
}
pub struct AppleDdmReply {
    pub facts: Vec<Fact>,
    pub status: u16,
    pub bytes: Vec<u8>,
    pub synchronized: Vec<Synchronized>,
}

pub trait AppleAssetRead: Send + Sync {
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::ddm::AssetBinding>>;
}

/// Capability facts are read once for the requested current registration generations.
#[derive(Clone)]
pub struct AppleControlCheck {
    pub id: usize,
    pub registration: Uuid,
    pub generation: i64,
    pub action: ControlKind,
    pub command: rss_mdm_apple_mdm::native::input::CommandInput,
}

/// Committed publication identity carried by a validated native status report.
pub struct Synchronized {
    pub operation: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub user: String,
    pub input_version: String,
    pub publication_version: String,
}

impl ControlKind {
    /// Same platform and native-schema decision for a read and the actual dispatch.
    pub fn applicability(
        self,
        context: &rss_mdm_apple_mdm::applicability::Context,
        command: &rss_mdm_apple_mdm::native::input::CommandInput,
        access_rights: &[&str],
    ) -> Result<(), rss_mdm_apple_mdm::native::Error> {
        use rss_mdm_apple_mdm::{
            applicability::{Channel, Condition, Enrollment, Rejection, Version},
            native::{Error, Target},
        };
        if context.channel != Channel::Device || context.enrollment != Enrollment::Device {
            return Err(Error::Unsupported);
        }
        let minimum = match self {
            Self::Restart => "10.13",
            Self::Lock => match context.apple_silicon {
                Some(true) => "11.5",
                Some(false) => "10.8",
                None => {
                    return Err(Error::Applicability(Rejection::MissingEvidence(
                        Condition::AppleSilicon,
                    )));
                }
            },
            Self::Wipe => match context.apple_silicon {
                Some(true) => "12.0.1",
                Some(false) => return Err(Error::Unsupported),
                None => {
                    return Err(Error::Applicability(Rejection::MissingEvidence(
                        Condition::AppleSilicon,
                    )));
                }
            },
        };
        let version = context
            .version
            .ok_or(Error::Applicability(Rejection::MissingEvidence(
                Condition::Version,
            )))?;
        if version < Version::parse(minimum).expect("fixed minimum version") {
            return Err(Error::Unsupported);
        }
        command
            .compile(&Target {
                context,
                access_rights,
            })
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::ControlKind;
    #[test]
    fn apple_matrix_requires_known_safe_hardware_and_version() {
        use rss_mdm_apple_mdm::applicability::{Channel, Context, Enrollment, Version};
        use rss_mdm_device_service::control::{Task, device_control::Kind};
        let check = |kind: ControlKind, context: &Context| {
            let action = match kind {
                ControlKind::Restart => Kind::Restart,
                ControlKind::Lock => Kind::Lock,
                ControlKind::Wipe => Kind::Wipe,
            };
            let Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command { command },
            } = action
                .native_shape(rss_mdm_inventory::ReportSource::MdmApple)
                .unwrap()
            else {
                panic!("Apple shape")
            };
            kind.applicability(
                context,
                &command,
                &["AllowPasscodeRemovalAndLock", "AllowDeviceErase"],
            )
        };
        let mut context = Context {
            version: Some(Version::parse("15.0.1").unwrap()),
            channel: Channel::Device,
            enrollment: Enrollment::Device,
            supervised: None,
            automated_enrollment: None,
            user_approved: None,
            apple_silicon: Some(true),
        };
        assert_eq!(check(ControlKind::Wipe, &context), Ok(()));
        context.version = Some(Version::parse("12.0.1").unwrap());
        assert_eq!(
            check(ControlKind::Wipe, &context),
            Err(rss_mdm_apple_mdm::native::Error::Unsupported)
        );
        context.version = Some(Version::parse("15.0.1").unwrap());
        context.apple_silicon = Some(false);
        assert!(check(ControlKind::Wipe, &context).is_err());
        assert_eq!(check(ControlKind::Lock, &context), Ok(()));
        context.apple_silicon = None;
        assert!(matches!(
            check(ControlKind::Lock, &context),
            Err(rss_mdm_apple_mdm::native::Error::Applicability(
                rss_mdm_apple_mdm::applicability::Rejection::MissingEvidence(_)
            ))
        ));
        assert!(matches!(
            check(ControlKind::Wipe, &context),
            Err(rss_mdm_apple_mdm::native::Error::Applicability(
                rss_mdm_apple_mdm::applicability::Rejection::MissingEvidence(_)
            ))
        ));
        context.apple_silicon = Some(true);
        context.version = Some(Version::parse("11.4").unwrap());
        assert!(check(ControlKind::Lock, &context).is_err());
        assert!(check(ControlKind::Wipe, &context).is_err());
        context.enrollment = Enrollment::User;
        assert!(check(ControlKind::Restart, &context).is_err());
    }
}
