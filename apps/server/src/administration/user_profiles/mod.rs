//! Tenant-owned profile mappings and immediate projections. Values remain in Identity.
use crate::{Error, Failure};
use model::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
pub(crate) mod http;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
pub(crate) mod directory;
pub(crate) mod model;
mod projection;
mod store;
pub(crate) const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
pub(crate) struct Backend {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub identity: rss_identity_postgres::Authority,
    pub tenant: rss_request_context::TenantId,
    pub instance: rss_identity_core::InstanceId,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Database)
}
fn database(e: sqlx::Error) -> Error {
    if e.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505") {
        Error::Conflict
    } else {
        unavailable()
    }
}
fn identity_error(e: rss_identity_postgres::AuthorityError) -> Error {
    match e {
        rss_identity_postgres::AuthorityError::Rejected => Error::Unauthorized,
        rss_identity_postgres::AuthorityError::RuleRejected(_) => Error::Forbidden,
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(8),
    )
}
impl Backend {
    fn authorize(&self, p: &AuthorizedPrincipal, audit: &RequestAudit) -> Result<(), Error> {
        p.check_live()?;
        if p.tenant_id() != self.tenant.to_string() || p.instance_id() != self.instance.to_string()
        {
            return Err(Error::Forbidden);
        }
        p.bind_audit(audit)?;
        audit.set_action(
            "user_profile_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        Ok(())
    }
    pub(crate) async fn definitions(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        query: &rss_mdm_query::directory::Query,
    ) -> Result<Definitions, Error> {
        self.authorize(p, audit)?;
        p.require(Permission::UserAttributeDefinitionsRead, None)?;
        let sources = self
            .identity
            .profile_sources(p.session()?, deadline())
            .await
            .map_err(identity_error)?;
        let page = directory::list(self, p, audit, query).await?;
        p.check_live()?;
        Ok(Definitions {
            items: page.items,
            next_cursor: page.next_cursor,
            sources: sources
                .into_iter()
                .map(|v| SourceView {
                    source: model::source_dto(v.source),
                    provider_config_version: v.provider_config_version,
                    extensions_root: v.extensions_root,
                    max_age_seconds: v.max_age_seconds,
                })
                .collect(),
        })
    }
    pub(crate) async fn definition(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: Uuid,
    ) -> Result<Definition, Error> {
        self.authorize(p, audit)?;
        store::definition(&self.audit, p, audit, id).await
    }
    pub(crate) async fn operation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: Uuid,
    ) -> Result<Receipt, Error> {
        self.authorize(p, audit)?;
        store::operation(&self.audit, p, audit, id).await
    }
    pub(crate) async fn change(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: Uuid,
        input: &Change,
    ) -> Result<Receipt, Error> {
        self.authorize(p, audit)?;
        audit.operation(
            input.operation_id,
            "user_attribute_definition_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        store::change(&self.audit, p, audit, id, input).await
    }
}
impl Backend {
    pub(crate) async fn configured_count(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> Result<usize, Error> {
        Ok(store::definitions(
            &self.audit,
            p,
            audit,
            Some(Permission::UserAttributeDefinitionsRead),
            true,
            None,
        )
        .await?
        .0
        .len())
    }

    pub(crate) async fn profile(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        target: Option<Uuid>,
        query: ProfileQuery,
    ) -> Result<Profile, Error> {
        self.authorize(p, audit)?;
        let session = p.session()?; // API keys never acquire a natural-person profile context.
        let target = target
            .map(|id| {
                rss_identity_core::PrincipalId::parse(&id.to_string()).map_err(|_| Error::Malformed)
            })
            .transpose()?
            .unwrap_or(session.account().principal);
        let own = target == session.account().principal;
        let permission = if !own || query.preview {
            Some(Permission::UserProfilesRead)
        } else {
            None
        };
        if let Some(permission) = permission {
            p.require(permission, None)?;
        }
        let account = rss_identity_core::account::AccountKey {
            tenant: self.tenant,
            principal: target,
        };
        let mut views = vec![];
        match query.view {
            View::Current => views.push(
                self.identity
                    .current_profile(session, deadline())
                    .await
                    .map_err(identity_error)?,
            ),
            View::Latest => {
                let mut cursor = None;
                loop {
                    let page = self
                        .identity
                        .latest_profile_sources(session, account, cursor, deadline())
                        .await
                        .map_err(identity_error)?;
                    for source in page.sources {
                        views.push(
                            self.identity
                                .latest_profile(session, account, source, deadline())
                                .await
                                .map_err(identity_error)?,
                        );
                    }
                    match page.next_cursor {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
            }
        }
        // Re-read grants and definitions after external observations: stopping a mapping or
        // withdrawing profile permission while the reads were in flight takes effect now.
        let (definitions, profiles_read) =
            store::definitions(&self.audit, p, audit, permission, true, None).await?;
        let result = projection::response(target, query, &definitions, &views, own, profiles_read)?;
        p.check_live()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "../../../tests/settings/user_profiles.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/settings/recent_auth.rs"]
mod recent_tests;
