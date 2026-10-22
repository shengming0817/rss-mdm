//! Request-local personnel presentation; Identity remains the only account/profile owner.
//! ref: rss-identity@5e979508 src/operations.rs::list_accounts and src/profiles.rs::latest_profile.
use crate::{Error, Result};
use rss_identity_core::{PrincipalId, account::AccountKey, profile::Attribute};
use rss_identity_postgres::{
    AuthenticatedSession, Authority, AuthorityError, ProfileSource, ProfileStatus, TrustedProfile,
};
use rss_mdm_authorization_service::{
    Permission, context::AuthorizedPrincipal, credential::RequestCredential,
};
use rss_request_context::{Clock, TenantId};
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

const RELATIONS: [&str; 2] = ["registrationUser", "currentUser"];

/// Borrows the original request credential; never stores it beyond the request or renews idle.
pub struct Reader<'a> {
    authority: &'a Authority,
    credential: &'a RequestCredential,
    deadline: Instant,
    clock: &'a dyn Clock,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    source: ProfileSource,
    status: ProfileStatus,
    display_name: Option<String>,
    username: Option<String>,
}
#[derive(Default, Serialize)]
struct Display {
    login: Option<String>,
    profiles: Vec<Profile>,
}

impl<'a> Reader<'a> {
    pub fn new(
        authority: &'a Authority,
        credential: &'a RequestCredential,
        deadline: Instant,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            authority,
            credential,
            deadline,
            clock,
        }
    }
    fn budget(&self) -> Result<OperationDeadline> {
        let remaining = self
            .deadline
            .checked_duration_since(self.clock.now())
            .ok_or(Error::Deadline)?;
        Ok(OperationDeadline::from_remaining(remaining))
    }
    /// Account listing consumes its proof. Passive reinspection supplies a fresh proof per page.
    async fn authenticate(&self, proof: &AuthorizedPrincipal) -> Result<AuthenticatedSession> {
        let tenant = TenantId::parse(proof.tenant_id()).map_err(|_| Error::Storage)?;
        let actor = match self.credential.duplicate()? {
            RequestCredential::Cookie(secret) => {
                self.authority
                    .inspect_session(tenant, secret, self.budget()?)
                    .await
            }
            RequestCredential::Bearer(secret) => {
                self.authority
                    .inspect_bearer(tenant, secret, self.budget()?)
                    .await
            }
            RequestCredential::ApiKey(_) => return Err(Error::Forbidden),
        }
        .map_err(identity_error)?;
        let original = proof.session()?;
        if actor.account() != original.account()
            || actor.instance() != original.instance()
            || actor.view().id != original.view().id
            || actor.view().credential_kind != original.view().credential_kind
        {
            return Err(Error::Unauthorized);
        }
        Ok(actor)
    }
    /// Called once for the entire authorized result set, before filtering and pagination.
    pub(crate) async fn project<'b>(
        &self,
        proof: &AuthorizedPrincipal,
        rows: impl Iterator<Item = &'b mut Value>,
    ) -> Result<()> {
        tokio::time::timeout_at(
            self.deadline.into(),
            self.project_inner(proof, rows.collect()),
        )
        .await
        .map_err(|_| Error::Deadline)?
    }
    async fn project_inner(
        &self,
        proof: &AuthorizedPrincipal,
        mut rows: Vec<&mut Value>,
    ) -> Result<()> {
        let mut targets = BTreeSet::new();
        let sensitive = permits(proof, Permission::InventorySensitiveRead)?;
        for endpoint in &mut rows {
            for key in RELATIONS {
                if let Some(relation) = endpoint.get_mut(key) {
                    relation["display"] = Value::Null;
                    if sensitive && let Some(user) = relation.get("user").filter(|u| !u.is_null()) {
                        if user["tenantId"] != proof.tenant_id()
                            || user["instanceId"] != proof.instance_id()
                        {
                            return Err(Error::Storage);
                        }
                        targets.insert(
                            PrincipalId::parse(user["principalId"].as_str().ok_or(Error::Storage)?)
                                .map_err(|_| Error::Storage)?,
                        );
                    }
                }
            }
        }
        // reason: API keys and initialization proofs have no natural-person profile context.
        if targets.is_empty() || proof.session().is_err() {
            return Ok(());
        }
        let profiles_read = permits(proof, Permission::UserProfilesRead)?;
        let logins_read = permits(proof, Permission::IdentityAccountsManage)?;
        let mut displays = BTreeMap::new();
        let mut observations = BTreeMap::new();
        let own = proof.session()?.account().principal;
        for target in &targets {
            if profiles_read || *target == own {
                let profiles = self.profiles(proof, *target).await?;
                if let Some(profiles) = profiles {
                    observations.insert(*target, profiles);
                    displays.insert(*target, Display::default());
                }
            }
        }
        if logins_read {
            self.logins(proof, &targets, &mut displays).await?;
        }
        for (target, mut profiles) in observations {
            if profiles.iter().any(|profile| profile.view().is_err()) {
                self.authenticate(proof).await?;
                // A target observation can expire while other targets/account pages are read.
                // Reload once to obtain its current expired/unavailable state; never emit a
                // caller authentication error merely because an observation aged out.
                let Some(fresh) = self.profiles(proof, target).await? else {
                    displays.remove(&target);
                    continue;
                };
                profiles = fresh;
            }
            if let Some(display) = displays.get_mut(&target) {
                display.profiles = profiles.iter().map(profile).collect::<Result<_>>()?;
            }
        }
        // Recheck the caller after target failures/reads, without renewing the session.
        if profiles_read || logins_read || targets.contains(&own) {
            self.authenticate(proof).await?;
        }
        for endpoint in rows {
            for key in RELATIONS {
                if let Some(relation) = endpoint.get_mut(key)
                    && let Some(id) = relation["user"]["principalId"].as_str()
                {
                    let id = PrincipalId::parse(id).map_err(|_| Error::Storage)?;
                    relation["display"] =
                        serde_json::to_value(displays.get(&id)).map_err(|_| Error::Storage)?;
                }
            }
        }
        Ok(())
    }
    async fn profiles(
        &self,
        proof: &AuthorizedPrincipal,
        target: PrincipalId,
    ) -> Result<Option<Vec<TrustedProfile>>> {
        let account = AccountKey {
            tenant: TenantId::parse(proof.tenant_id()).map_err(|_| Error::Storage)?,
            principal: target,
        };
        let mut cursor = None;
        let mut profiles = Vec::new();
        loop {
            let result = self
                .authority
                .latest_profile_sources(proof.session()?, account, cursor, self.budget()?)
                .await;
            let Some(page) = self.target_result(proof, result).await? else {
                return Ok(None);
            };
            for source in page.sources {
                let result = self
                    .authority
                    .latest_profile(proof.session()?, account, source, self.budget()?)
                    .await;
                let Some(profile) = self.target_result(proof, result).await? else {
                    return Ok(None);
                };
                profiles.push(profile);
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(Some(profiles))
    }
    async fn target_result<T>(
        &self,
        proof: &AuthorizedPrincipal,
        value: std::result::Result<T, AuthorityError>,
    ) -> Result<Option<T>> {
        match value {
            Ok(value) => Ok(Some(value)),
            Err(AuthorityError::Rejected) => {
                self.authenticate(proof).await?;
                // reason: a live caller may retain a relationship to a removed/inactive target.
                Ok(None)
            }
            Err(error) => Err(identity_error(error)),
        }
    }
    async fn logins(
        &self,
        proof: &AuthorizedPrincipal,
        targets: &BTreeSet<PrincipalId>,
        displays: &mut BTreeMap<PrincipalId, Display>,
    ) -> Result<()> {
        let mut remaining = targets.clone();
        let mut cursor = None;
        while !remaining.is_empty() {
            let actor = self.authenticate(proof).await?;
            let page = self
                .authority
                .list_accounts(actor, cursor, 100, self.budget()?)
                .await
                .map_err(identity_error)?;
            for account in page.accounts {
                if !remaining.remove(&account.principal_id) {
                    continue;
                }
                if account.enabled && account.member_active {
                    displays.entry(account.principal_id).or_default().login = account.login;
                } else {
                    displays.remove(&account.principal_id);
                }
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        for absent in remaining {
            displays.remove(&absent);
        }
        Ok(())
    }
}

fn profile(value: &TrustedProfile) -> Result<Profile> {
    let value = value.view().map_err(|_| Error::Deadline)?;
    let available = matches!(value.status, ProfileStatus::Available);
    let text = |attr: &Attribute<String>| {
        if available {
            attr.value().filter(|s| !s.trim().is_empty()).cloned()
        } else {
            None
        }
    };
    Ok(Profile {
        source: value.source.ok_or(Error::Storage)?,
        status: value.status,
        display_name: value.profile.as_ref().and_then(|p| text(&p.display_name)),
        username: value.profile.as_ref().and_then(|p| text(&p.username)),
    })
}
fn permits(proof: &AuthorizedPrincipal, permission: Permission) -> Result<bool> {
    match proof.require(permission, None) {
        Ok(()) => Ok(true),
        Err(rss_mdm_authorization_service::Error::Forbidden) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn identity_error(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::RuleRejected(_) => Error::Forbidden,
        AuthorityError::DeadlineElapsed => Error::Deadline,
        _ => Error::Storage,
    }
}
