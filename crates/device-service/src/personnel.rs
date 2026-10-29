//! Bounded presentation through Identity's fixed, lifetime-scoped read relations.
//! ref: PostgreSQL REL_17_STABLE src/backend/commands/variable.c.
use crate::{Error, Result};
use rss_identity_postgres::{Authority, AuthorityError, PersonnelRevision};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_request_context::{Clock, TenantId};
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::{PgArguments, PgRow};
use std::time::Instant;

/// Current host configuration for the MDM-owned Platform SSO qualification relation.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformConfiguration {
    /// Current configuration and endpoint fingerprint.
    pub configuration: String,
    /// Expected application identifier.
    pub application_id: String,
    /// Expected installed application version.
    pub application_version: String,
    /// Expected native profile identifier.
    pub profile_identifier: String,
}
pub struct Reader<'a> {
    authority: &'a Authority,
    deadline: Instant,
    clock: &'a dyn Clock,
    platform: Option<&'a PlatformConfiguration>,
}
impl<'a> Reader<'a> {
    pub fn new(
        authority: &'a Authority,
        deadline: Instant,
        clock: &'a dyn Clock,
        platform: Option<&'a PlatformConfiguration>,
    ) -> Self {
        Self {
            authority,
            deadline,
            clock,
            platform,
        }
    }
    pub(crate) fn platform_configuration(&self) -> Result<Value> {
        serde_json::to_value(self.platform).map_err(|_| Error::Storage)
    }
    fn budget(&self) -> Result<OperationDeadline> {
        let remaining = self
            .deadline
            .checked_duration_since(self.clock.now())
            .ok_or(Error::Deadline)?;
        Ok(OperationDeadline::from_remaining(remaining))
    }
    /// Refresh only the authenticated caller, with the original request's remaining budget.
    pub(crate) async fn revalidate(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<Option<rss_identity_postgres::RevalidatedSession>> {
        proof.check_live()?;
        let Ok(session) = proof.session() else {
            return Ok(None);
        };
        let reference = session.reference().map_err(identity_error)?;
        self.authority
            .recheck_session_reference(
                TenantId::parse(proof.tenant_id()).map_err(|_| Error::Storage)?,
                &reference,
                self.budget()?,
            )
            .await
            .map(Some)
            .map_err(identity_error)
    }
    /// Static product SELECTs compose fixed relations; no raw Identity table or connection escapes.
    pub(crate) async fn query(
        &self,
        proof: &AuthorizedPrincipal,
        select: &'static str,
        arguments: PgArguments,
        max_rows: usize,
    ) -> Result<(PersonnelRevision, Vec<PgRow>)> {
        proof.check_live()?;
        let result = if let Ok(actor) = proof.session() {
            self.authority
                .with_personnel_read(actor, self.budget()?, move |context| {
                    Box::pin(query_rows(context, select, arguments, max_rows))
                })
                .await
        } else {
            self.authority
                .with_session_references_read(
                    TenantId::parse(proof.tenant_id()).map_err(|_| Error::Storage)?,
                    self.budget()?,
                    move |context| Box::pin(query_rows(context, select, arguments, max_rows)),
                )
                .await
        }
        .map_err(identity_error)?;
        proof.check_live()?;
        Ok(result)
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

async fn query_rows(
    mut context: rss_identity_postgres::PersonnelRead<'_>,
    select: &'static str,
    arguments: PgArguments,
    max_rows: usize,
) -> std::result::Result<(PersonnelRevision, Vec<PgRow>), AuthorityError> {
    let rows = context.query(select, arguments, max_rows).await?;
    rss_mdm_query_postgres::observe_rows("device.personnel", &rows)
        .map_err(|_| AuthorityError::Unavailable)?;
    Ok((context.revision()?, rows))
}
