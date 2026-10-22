//! Tenant-owned profile mappings and immediate projections. Values remain in Identity.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure, user_profiles::*};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
mod model;
mod projection;
mod store;
pub(crate) const ACCESS_CONTRACT: &str = include_str!("user_profiles/access-contract.json");
pub(crate) struct Backend {
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
impl Source for Backend {
    fn execute<'a>(
        &'a self,
        p: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Value, Error>> {
        Box::pin(async move {
            p.check_live()?;
            if p.tenant_id() != self.tenant.to_string()
                || p.instance_id() != self.instance.to_string()
            {
                return Err(Error::Forbidden);
            }
            p.bind_audit(&audit)?;
            audit.set_action("user_profile_read");
            match command {
                Command::Definitions(after) => {
                    p.require(Permission::UserAttributeDefinitionsRead, None)?;
                    let sources = self
                        .identity
                        .profile_sources(p.session()?, deadline())
                        .await
                        .map_err(identity_error)?;
                    let (mut definitions, _) = store::definitions(
                        &self.audit,
                        &p,
                        &audit,
                        Some(Permission::UserAttributeDefinitionsRead),
                        false,
                        after,
                    )
                    .await?;
                    let next_cursor = if definitions.len() > 128 {
                        definitions.truncate(128);
                        definitions.last().map(|v| v.field_id)
                    } else {
                        None
                    };
                    p.check_live()?;
                    Ok(
                        json!({"definitions":definitions,"nextCursor":next_cursor,"sources":sources.into_iter().map(|v|json!({"source":model::source_dto(v.source),"providerConfigVersion":v.provider_config_version,"extensionsRoot":v.extensions_root,"maxAgeSeconds":v.max_age_seconds})).collect::<Vec<_>>()}),
                    )
                }
                Command::Definition(id) => store::one(&self.audit, &p, &audit, id, false).await,
                Command::Operation(id) => store::one(&self.audit, &p, &audit, id, true).await,
                Command::Change(id, input) => {
                    audit.operation(input.operation_id, "user_attribute_definition_change");
                    audit.require_request_settlement();
                    store::change(&self.audit, &p, &audit, id, &input).await
                }
                Command::Me(query) => self.profile(&p, &audit, None, query).await,
                Command::Person(id, query) => self.profile(&p, &audit, Some(id), query).await,
            }
        })
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

    async fn profile(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        target: Option<Uuid>,
        query: ProfileQuery,
    ) -> Result<Value, Error> {
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
        let (definitions, _) =
            store::definitions(&self.audit, p, audit, permission, true, None).await?;
        let current = self
            .identity
            .current_profile(session, deadline())
            .await
            .map_err(identity_error)?;
        let mut views = vec![];
        match query.view {
            View::Current => views.push(current),
            View::Latest => {
                let mut sources = vec![ProfileSource::IdentityLocal];
                if let Some(source) = current.view().map_err(identity_error)?.source {
                    sources.push(model::source_dto(source));
                }
                for definition in &definitions {
                    if let Some(value) = &definition.value
                        && !sources.contains(&value.source)
                    {
                        sources.push(value.source.clone());
                    }
                }
                sources.dedup();
                for source in sources {
                    views.push(
                        self.identity
                            .latest_profile(
                                session,
                                rss_identity_core::account::AccountKey {
                                    tenant: self.tenant,
                                    principal: target,
                                },
                                model::source(&source)?,
                                deadline(),
                            )
                            .await
                            .map_err(identity_error)?,
                    );
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
#[path = "../tests/settings/user_profiles.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/settings/recent_auth.rs"]
mod recent_tests;
