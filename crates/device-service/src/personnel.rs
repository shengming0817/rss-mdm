//! Bounded presentation through Identity's fixed, lifetime-scoped read relations.
//! ref: PostgreSQL REL_17_STABLE src/backend/commands/variable.c.
use crate::{Error, Result};
use rss_identity_postgres::{Authority, AuthorityError, PersonnelRevision};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_access::deployment::PlatformConfiguration;
use rss_request_context::Clock;
use rss_transactional_messaging::policy::OperationDeadline;
use serde_json::Value;
use sqlx::postgres::{PgArguments, PgRow};
use std::time::Instant;

pub struct Reader<'a> {
    authority: &'a Authority,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    deadline: Instant,
    clock: &'a dyn Clock,
    platform: Option<&'a PlatformConfiguration>,
}
impl<'a> Reader<'a> {
    pub fn new(
        authority: &'a Authority,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        deadline: Instant,
        clock: &'a dyn Clock,
        platform: Option<&'a PlatformConfiguration>,
    ) -> Self {
        Self {
            authority,
            binding,
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
        if proof.tenant_id() != self.binding.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        let Ok(session) = proof.session() else {
            return Ok(None);
        };
        let reference = session.reference().map_err(identity_error)?;
        self.authority
            .recheck_session_reference(self.binding, &reference, self.budget()?)
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
        if proof.tenant_id() != self.binding.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        let result = if let Ok(actor) = proof.session() {
            self.authority
                .with_personnel_read(actor, self.budget()?, move |context| {
                    Box::pin(query_rows(context, select, arguments, max_rows))
                })
                .await
        } else {
            self.authority
                .with_session_references_read(self.binding, self.budget()?, move |context| {
                    Box::pin(query_rows(context, select, arguments, max_rows))
                })
                .await
        }
        .map_err(identity_error)?;
        proof.check_live()?;
        if proof.tenant_id() != self.binding.tenant().to_string() {
            return Err(Error::Forbidden);
        }
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

/// Resolves a bounded inventory page using the same credential and platform qualifications as the device directory.
pub async fn device_subjects(
    authority: &Authority,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    platform: Value,
    devices: &[uuid::Uuid],
    deadline: OperationDeadline,
) -> Result<(PersonnelRevision, Vec<DeviceSubjects>)> {
    use sqlx::{Arguments, Row};
    const SELECT: &str = concat!("WITH platform_configuration AS (SELECT $3::jsonb AS config),",
        include_str!("platform_sessions.sql"),"
        SELECT d.device, CASE WHEN (u.registration_user->>'instanceId')::uuid=$4 AND
        (u.registration_user->>'tenantId')::uuid=$1::uuid THEN (u.registration_user->>'principalId')::uuid END AS registration,
        s.principal_id AS current, coalesce(u.registration_revision,0) AS registration_revision,
        coalesce(u.current_revision,0) AS current_revision,
        least(u.valid_until,s.platform_valid_until) AS current_until
        FROM unnest($2::uuid[]) d(device)
        LEFT JOIN mdm_access.directory_users u ON u.tenant_id=$1::uuid AND u.device=d.device
        LEFT JOIN platform_sessions s ON u.registration_valid AND s.instance_id=$4 AND s.tenant_id=$1::uuid
         AND s.instance_id=(u.session_reference->>'instance')::uuid AND s.tenant_id=(u.session_reference->>'tenant')::uuid
         AND s.principal_id=(u.session_reference->>'principal')::uuid AND s.session_id=(u.session_reference->>'session')::uuid
         AND s.credential_kind=u.session_reference->>'credentialKind' ORDER BY d.device");
    let mut args = PgArguments::default();
    args.add(binding.tenant().to_string())
        .map_err(|_| Error::Storage)?;
    args.add(devices.to_vec()).map_err(|_| Error::Storage)?;
    args.add(platform).map_err(|_| Error::Storage)?;
    args.add(authority.instance().as_uuid())
        .map_err(|_| Error::Storage)?;
    let size = devices.len().max(1);
    let (window, rows) = authority
        .with_session_references_read(binding, deadline, move |ctx| {
            Box::pin(query_rows(ctx, SELECT, args, size))
        })
        .await
        .map_err(identity_error)?;
    let rows = rows
        .into_iter()
        .map(|r| {
            Ok(DeviceSubjects {
                device: r.try_get("device")?,
                registration: r.try_get("registration")?,
                current: r.try_get("current")?,
                registration_revision: r.try_get("registration_revision")?,
                current_revision: r.try_get("current_revision")?,
                current_until: r
                    .try_get::<Option<i64>, _>("current_until")?
                    .map(|end| end.min(window.valid_until)),
            })
        })
        .collect::<std::result::Result<_, sqlx::Error>>()
        .map_err(|_| Error::Storage)?;
    Ok((window, rows))
}

pub struct DeviceSubjects {
    pub device: uuid::Uuid,
    pub registration: Option<uuid::Uuid>,
    pub current: Option<uuid::Uuid>,
    pub registration_revision: i64,
    pub current_revision: i64,
    pub current_until: Option<i64>,
}
