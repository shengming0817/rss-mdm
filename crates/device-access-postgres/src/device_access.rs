//! Device Access association authority. Registration and local-account generations are distinct.
//! ref: kanidm server/lib/src/idm/credupdatesession.rs (explicit credential ceremony state).
pub mod directory;
pub mod lifecycle;
pub(crate) mod service;
pub mod storage;
use crate::Error;
use rss_mdm_agent_wire::runtime::{
    AccessAccount, AccessConfiguration, AccessEffect, AccessLocalSession, TaskPlatform,
};
use rss_mdm_device_access::{AccountIntent, Person, PolicySelection, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/device-access.sql"),
    "\n",
    include_str!("../schema/device-access-qualification.sql")
);

/// The initiator of a binding generation, distinct from the policy publisher.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Origin {
    SelfEnrollment,
    Administrator {
        actor: rss_mdm_authorization_service::Actor,
    },
}

/// Internal provenance of the last complete deployment-authority observation.
/// Public binding views and the Agent status protocol deliberately omit it.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentApplication {
    pub authority: Uuid,
    pub sequence: i64,
    pub fingerprint: String,
}

/// A configured business target. It does not authenticate an HTTP request or issue a session.
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    /// Operation that owns the current desired revision.
    pub operation_id: Uuid,
    pub account_disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    pub id: Uuid,
    pub tenant: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub person: Person,
    pub origin: Origin,
    pub generation: i64,
    pub factor_generation: i64,
    pub revision: i64,
    pub state: State,
    pub intent: AccountIntent,
    pub account: Option<AccessAccount>,
    pub policy: Uuid,
    pub policy_version: Uuid,
    pub configuration: AccessConfiguration,
    pub received_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub effect: Option<AccessEffect>,
    /// Last verified factors survive later failed configuration observations.
    pub applied_windows: Option<rss_mdm_agent_wire::runtime::AccessWindowsFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_application: Option<DeploymentApplication>,
    pub created_by_rss: bool,
}
impl Binding {
    pub fn status(&self) -> rss_mdm_agent_wire::runtime::AccessBindingStatus {
        rss_mdm_agent_wire::runtime::AccessBindingStatus {
            account_disposition: self.account_disposition,
            id: self.id,
            binding_generation: self.generation,
            factor_generation: self.factor_generation,
            revision: self.revision,
            revoked: self.state == State::Revoked,
            account: self.account.clone(),
            configuration: self.configuration.clone(),
            received_revision: self.received_revision,
            applied_revision: self.applied_revision,
            effect: self.effect.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self
            .deployment_application
            .as_ref()
            .is_some_and(|p| p.authority.is_nil() || p.sequence < 1 || p.fingerprint.len() != 64)
        {
            return Err(Error::Malformed);
        }
        if self.state != State::Revoked
            && self.account_disposition
                != rss_mdm_agent_wire::runtime::AccessAccountDisposition::Keep
        {
            return Err(Error::Malformed);
        }
        self.person.validate()?;
        self.intent.validate()?;
        self.configuration
            .validate()
            .map_err(|_| Error::Malformed)?;
        if self.operation_id.is_nil()
            || self.id.is_nil()
            || self.tenant.is_nil()
            || self.policy.is_nil()
            || self.policy_version.is_nil()
            || self.generation < 1
            || self.factor_generation < 1
            || self.revision < 1
            || self
                .received_revision
                .is_some_and(|r| r < 1 || r > self.revision)
            || self
                .applied_revision
                .is_some_and(|r| r < 1 || r > self.revision)
        {
            return Err(Error::Malformed);
        }
        if let Some(account) = &self.account {
            account.validate().map_err(|_| Error::Malformed)?;
            if account.platform() != self.intent.platform()
                || self.intent.account().is_some_and(|a| a != account)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    /// Desired effect identity, independent of delivery state and observations.
    pub fn definition_digest(&self) -> Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(
            serde_json::to_vec(&(
                "rss-mdm-device-access.v1",
                self.tenant,
                &self.device,
                (self.id, self.operation_id),
                self.generation,
                self.factor_generation,
                self.revision,
                &self.person,
                &self.origin,
                &self.intent,
                self.policy,
                self.policy_version,
                &self.configuration,
                (self.state == State::Revoked, self.account_disposition),
            ))
            .map_err(|_| Error::Malformed)?,
        )
        .into())
    }
    pub fn accepts_login(&self) -> bool {
        self.state == State::Active
            && matches!(self.effect, Some(AccessEffect::Applied { .. }))
            && self.configuration.enabled
            && self.account.is_some()
            && self.applied_revision == Some(self.revision)
            && self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.complete(&self.configuration, self.intent.platform()))
    }
}

/// Product composition checks the current policy and live native interactive context.
pub trait Admission: Send + Sync {
    fn broker_release_query(&self) -> &'static str {
        crate::broker_release_query!(
            "SELECT NULL::uuid AS tenant_id,NULL::uuid AS installation,NULL::uuid AS device,NULL::uuid AS registration,NULL::bigint AS generation,NULL::text AS platform,NULL::jsonb AS capabilities,NULL::jsonb AS execution_context WHERE false"
        )
    }

    fn policies<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        device: &'a rss_mdm_agent_wire::DeviceId,
        after: Option<Uuid>,
        limit: u16,
    ) -> crate::Pending<
        'a,
        (
            Vec<rss_mdm_agent_wire::runtime::AccessPolicyOption>,
            Option<Uuid>,
        ),
    >;

    fn policy<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        device: &'a rss_mdm_agent_wire::DeviceId,
        policy: Uuid,
    ) -> crate::Pending<'a, PolicySelection>;
    fn binding_session<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        binding: &'a Binding,
    ) -> crate::Pending<'a, AccessLocalSession>;
    fn local_session<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        device: &'a rss_mdm_registration_service::DevicePrincipal,
    ) -> crate::Pending<'a, AccessLocalSession>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    Offboard {
        disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    },
    ResetFactors,
    Reinstate {
        person: Person,
        intent: AccountIntent,
        policy: Uuid,
    },
    Put {
        person: Person,
        intent: AccountIntent,
        policy: Uuid,
    },
    Unbind {
        disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition,
    },
}

impl Change {
    /// The one canonical business input. Authentication handles are never part of its digest.
    pub fn step_up_context(
        &self,
        actor: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        binding: Uuid,
        idp_fingerprints: &std::collections::BTreeMap<Uuid, String>,
    ) -> Result<rss_identity_core::step_up::StepUpContext, Error> {
        use sha2::{Digest, Sha256};
        if self.operation_id.is_nil() || binding.is_nil() || self.expected_revision < 0 {
            return Err(Error::Malformed);
        }
        actor.require(
            rss_mdm_authorization_service::Permission::AccountWrite,
            Some(device),
        )?;
        actor.session()?;
        if matches!(
            self.action,
            Action::Offboard { .. } | Action::Reinstate { .. }
        ) {
            actor.require(
                rss_mdm_authorization_service::Permission::IdentityAccountsManage,
                None,
            )?;
        }
        let digest = Sha256::digest(
            serde_json::to_vec(&(
                "mdm.device_access.change.v1",
                actor.tenant_id(),
                actor.instance_id(),
                actor.principal_id(),
                device,
                binding,
                self,
                idp_fingerprints,
            ))
            .map_err(|_| Error::Malformed)?,
        )
        .into();
        rss_identity_core::step_up::StepUpContext::new("mdm.device_access.change".into(), digest)
            .map_err(|_| Error::Malformed)
    }
}

/// Native discovery scans policy identities, including excluded candidates; it is not a management list.
pub static DISCOVERY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "protocol_agent_channel",
    default_limit: 64,
    max_limit: 100,
    order: "policy UUID ascending (bounded live eligibility scan)",
    purpose: rss_mdm_query::window::Purpose::Qualification,
    reason: "The device-scoped discovery scan advances over examined Policy candidates, including ineligible entries",
    context: &[],
};

pub mod execution;
pub mod participants;
