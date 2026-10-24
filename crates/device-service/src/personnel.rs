//! Bounded presentation through Identity's fixed, lifetime-scoped read relations.
//! ref: PostgreSQL REL_17_STABLE src/backend/commands/variable.c.
use crate::{Error, Result};
use rss_identity_postgres::{Authority, AuthorityError, PersonnelRevision};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_request_context::{Clock, TenantId};
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use serde_json::Value;
use sqlx::{
    Arguments, Row,
    postgres::{PgArguments, PgRow},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use uuid::Uuid;

const RELATIONS: [&str; 2] = ["registrationUser", "currentUser"];

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
    /// Expected native profile UUID.
    pub profile_uuid: Uuid,
}
const CURRENT_USERS: &str = concat!(
    "WITH platform_configuration AS (SELECT $2::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    include_str!("current_users.sql")
);

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
    /// Only the current page's already authorized relationships are hydrated.
    pub(crate) async fn project<'b>(
        &self,
        proof: &AuthorizedPrincipal,
        sensitive: bool,
        rows: impl Iterator<Item = &'b mut Value>,
    ) -> Result<()> {
        let mut rows = rows.collect::<Vec<_>>();
        let mut targets = BTreeSet::new();
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
                            Uuid::parse_str(user["principalId"].as_str().ok_or(Error::Storage)?)
                                .map_err(|_| Error::Storage)?,
                        );
                    }
                }
            }
        }
        if targets.is_empty() || proof.session().is_err() {
            return Ok(());
        }
        if targets.len() > 400 {
            return Err(Error::Storage);
        }
        let mut arguments = PgArguments::default();
        arguments
            .add(targets.into_iter().collect::<Vec<_>>())
            .map_err(|_| Error::Storage)?;
        let (revision, display_rows) = self
            .query(proof, include_str!("personnel_display.sql"), arguments, 400)
            .await?;
        let own = proof.session()?.account().principal.as_uuid();
        let mut displays = BTreeMap::new();
        for row in display_rows {
            let id: Uuid = row.try_get("principal_id")?;
            let profiles = match revision.profiles {
                rss_identity_postgres::PersonnelProfileScope::None => false,
                rss_identity_postgres::PersonnelProfileScope::SelfOnly => id == own,
                rss_identity_postgres::PersonnelProfileScope::All => true,
            };
            if revision.logins || profiles {
                displays.insert(id, row.try_get::<Value, _>("display")?);
            }
        }
        for endpoint in rows {
            for key in RELATIONS {
                if let Some(relation) = endpoint.get_mut(key)
                    && let Some(id) = relation["user"]["principalId"].as_str()
                {
                    let id = Uuid::parse_str(id).map_err(|_| Error::Storage)?;
                    relation["display"] = displays.get(&id).cloned().unwrap_or(Value::Null);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn current_users(
        &self,
        proof: &AuthorizedPrincipal,
        rows: &mut [Value],
        bindings: &crate::presentation::Bindings,
    ) -> Result<()> {
        if rows.len() > 200 {
            return Err(Error::Storage);
        }
        let inputs =
            rows.iter()
                .filter_map(|row| {
                    let id = row["id"].as_str()?;
                    let binding = bindings.get(id)?;
                    (binding.registration_valid)
                        .then(|| {
                            binding.reference.as_ref().map(
                                |reference| serde_json::json!({"device":id,"reference":reference}),
                            )
                        })
                        .flatten()
                })
                .collect::<Vec<_>>();
        let mut arguments = PgArguments::default();
        arguments
            .add(serde_json::json!(inputs))
            .map_err(|_| Error::Storage)?;
        arguments
            .add(self.platform_configuration()?)
            .map_err(|_| Error::Storage)?;
        let (_, valid) = self.query(proof, CURRENT_USERS, arguments, 200).await?;
        let valid = valid
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("device")?,
                    row.try_get::<Value, _>("user")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for row in rows {
            let id = row["id"].as_str().ok_or(Error::Storage)?;
            if let Some(binding) = bindings.get(id) {
                row["currentUser"] = serde_json::json!({
                    "revision":binding.revision,
                    "state":if valid.contains_key(id){"active"}else if binding.reference.is_some(){"invalidated"}else{"unbound"},
                    "user":valid.get(id), "confirmedAt":binding.confirmed_at,
                });
            }
        }
        Ok(())
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
