//! Durable rotation reads. A read is evidence, never permission to execute a transition.
//! ref: sqlx v0.9.0 sqlx-postgres/src/transaction.rs (caller-owned read transaction).
pub(crate) mod gates;
use crate::{
    Error,
    registry::{Action, Receipt, Registry, RotationState, purpose},
};
use rss_mdm_agent_wire::pki::{Mode, Purpose, Trust};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_device_trust::DeviceTrust;
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Projection, Query, Schema},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

pub static BLOCKERS: Schema = Schema {
    id: "pki_rotation_blockers",
    keys: &["kind", "id"],
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("kind", Kind::Text),
        Field::scalar("id", Kind::Text),
        Field::output("device"),
        Field::output("registration"),
        Field::output("generation"),
        Field::output("state"),
        Field::output("deadline"),
        Field::output("revocationState"),
    ],
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    MissingAck,
    UnresolvedSigning,
    UnsettledBootstrap,
    UnsettledScep,
    OutstandingCertificate,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Blocker {
    pub kind: BlockerKind,
    pub id: String,
    pub device: Option<String>,
    pub registration: Option<Uuid>,
    pub generation: Option<i64>,
    pub state: String,
    pub deadline: Option<i64>,
    pub revocation_state: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Issuer {
    pub digest: String,
    pub state: String,
}
#[derive(Serialize, schemars::JsonSchema)]
pub struct Operation {
    pub actor: String,
    pub instance: String,
    pub receipt: Receipt,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Precondition {
    TrustInvalid,
    ProviderNotConfigured,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVerification {
    NotEvaluated,
    NotApplicable,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub id: Uuid,
    pub purpose: Purpose,
    pub state: RotationState,
    pub distribution_revision: u64,
    pub trust_revision: u64,
    pub previous: Issuer,
    pub candidate: Issuer,
    pub active_issuer: String,
    pub action: Option<Action>,
    pub blockers: Vec<BlockerKind>,
    pub preconditions: Vec<Precondition>,
    pub provider_verification: ProviderVerification,
    pub operations: Vec<Operation>,
    pub evaluated_at: i64,
}
pub(crate) fn next_trust(
    mut trust: Trust,
    previous: &str,
    candidate: &str,
    state: RotationState,
    action: Action,
    now: i64,
) -> Result<Trust, Error> {
    match (state, action) {
        (RotationState::Distributing, Action::Activate) => {
            for issuer in &mut trust.issuers {
                if issuer.digest == previous {
                    issuer.mode = Mode::VerifyOnly;
                } else if issuer.digest == candidate {
                    issuer.mode = Mode::Active;
                }
            }
        }
        (RotationState::Activated, Action::Retire) => {
            trust.issuers.retain(|v| v.digest != previous)
        }
        _ => return Err(Error::Conflict),
    }
    trust.revision = trust.revision.checked_add(1).ok_or(Error::Conflict)?;
    DeviceTrust::new(trust.clone(), trust.purpose, now).map_err(|_| Error::Request)?;
    Ok(trust)
}
fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Request,
    }
}
impl Registry {
    async fn rotation_snapshot(
        &self,
        p: &AuthorizedPrincipal,
        purpose_value: Purpose,
    ) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, String), Error> {
        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        if self.trust(purpose_value)?.tenant.to_string() != p.tenant_id() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true)").bind(p.tenant_id()).execute(&mut *tx).await.map_err(db)?;
        let auth =
            rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
                .await
                .map_err(|_| Error::Storage)?;
        auth.require_all_devices(p, Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        let binding = auth.query_binding(p).map_err(|_| Error::Forbidden)?;
        Ok((tx, binding))
    }
    async fn confirm_rotation_read(
        &self,
        p: &AuthorizedPrincipal,
        before: &str,
    ) -> Result<(), Error> {
        p.check_live().map_err(|_| Error::Forbidden)?;
        let mut tx = self.begin(p.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(&mut tx, p.tenant_id(), p.instance_id())
            .await
            .map_err(|_| Error::Storage)?;
        let auth =
            rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
                .await
                .map_err(|_| Error::Storage)?;
        auth.require_all_devices(p, Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        if auth.query_binding(p).map_err(|_| Error::Forbidden)? != before {
            return Err(Error::ReadConflict);
        }
        p.check_live().map_err(|_| Error::Forbidden)?;
        tx.rollback().await.map_err(db)
    }
    pub async fn rotation(
        &self,
        p: &AuthorizedPrincipal,
        purpose_value: Purpose,
        id: Option<Uuid>,
        now: i64,
    ) -> Result<Option<View>, Error> {
        let (mut tx, before) = self.rotation_snapshot(p, purpose_value).await?;
        let row=sqlx::query("SELECT r.id,r.previous,r.candidate,r.revision,r.state,t.body,t.revision AS trust_revision,i.state AS previous_state,j.state AS candidate_state FROM mdm_pki.rotations r JOIN mdm_pki.trust t USING(tenant_id,purpose) JOIN mdm_pki.issuers i ON i.tenant_id=r.tenant_id AND i.purpose=r.purpose AND i.digest=r.previous JOIN mdm_pki.issuers j ON j.tenant_id=r.tenant_id AND j.purpose=r.purpose AND j.digest=r.candidate WHERE r.tenant_id=$1::uuid AND r.purpose=$2 AND ($3::uuid IS NULL OR r.id=$3) ORDER BY r.revision DESC,r.id DESC LIMIT 1")
            .bind(p.tenant_id()).bind(purpose(purpose_value)).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
        let value = if let Some(row) = row {
            let id: Uuid = row.try_get("id").map_err(db)?;
            let state = RotationState::parse(row.try_get("state").map_err(db)?)?;
            let previous: String = row.try_get("previous").map_err(db)?;
            let candidate: String = row.try_get("candidate").map_err(db)?;
            let trust: Trust =
                serde_json::from_slice(&row.try_get::<Vec<u8>, _>("body").map_err(db)?)
                    .map_err(|_| Error::Storage)?;
            if i64::try_from(trust.revision).map_err(|_| Error::Storage)?
                != row.try_get::<i64, _>("trust_revision").map_err(db)?
                || trust.purpose != purpose_value
                || trust.tenant.to_string() != p.tenant_id()
            {
                return Err(Error::Storage);
            }
            let active_issuer = trust
                .issuers
                .iter()
                .find(|v| v.mode == Mode::Active)
                .ok_or(Error::Storage)?
                .digest
                .clone();
            let action = match state {
                RotationState::Distributing => Some(Action::Activate),
                RotationState::Activated => Some(Action::Retire),
                RotationState::Retired => None,
            };
            let mut preconditions = vec![];
            if let Some(action) = action {
                if next_trust(trust.clone(), &previous, &candidate, state, action, now).is_err() {
                    preconditions.push(Precondition::TrustInvalid);
                }
                if matches!(action, Action::Activate)
                    && self.providers.get(purpose_value, &candidate).is_err()
                {
                    preconditions.push(Precondition::ProviderNotConfigured);
                }
            }
            let records=sqlx::query("SELECT actor,instance,receipt,phase FROM mdm_pki.operations WHERE tenant_id=$1::uuid AND operation=$2 AND phase IN ('distributing','activated','retired') ORDER BY phase,actor LIMIT 4").bind(p.tenant_id()).bind(id).fetch_all(&mut *tx).await.map_err(db)?;
            if records.len() > 3 {
                return Err(Error::Storage);
            }
            let mut operations = vec![];
            for record in records {
                let receipt: Receipt =
                    serde_json::from_slice(&record.try_get::<Vec<u8>, _>("receipt").map_err(db)?)
                        .map_err(|_| Error::Storage)?;
                if receipt.operation != id
                    || receipt.state.as_str() != record.try_get::<String, _>("phase").map_err(db)?
                {
                    return Err(Error::Storage);
                }
                operations.push(Operation {
                    actor: record.try_get("actor").map_err(db)?,
                    instance: record.try_get("instance").map_err(db)?,
                    receipt,
                });
            }
            Some(View {
                id,
                purpose: purpose_value,
                state,
                distribution_revision: u64::try_from(
                    row.try_get::<i64, _>("revision").map_err(db)?,
                )
                .map_err(|_| Error::Storage)?,
                trust_revision: trust.revision,
                previous: Issuer {
                    digest: previous,
                    state: row.try_get("previous_state").map_err(db)?,
                },
                candidate: Issuer {
                    digest: candidate,
                    state: row.try_get("candidate_state").map_err(db)?,
                },
                active_issuer,
                action,
                blockers: gates::kinds(&mut tx, p.tenant_id(), id, now).await?,
                preconditions,
                provider_verification: if matches!(action, Some(Action::Activate)) {
                    ProviderVerification::NotEvaluated
                } else {
                    ProviderVerification::NotApplicable
                },
                operations,
                evaluated_at: now,
            })
        } else {
            None
        };
        tx.rollback().await.map_err(db)?;
        self.confirm_rotation_read(p, &before).await?;
        Ok(value)
    }
    pub async fn rotation_blockers(
        &self,
        p: &AuthorizedPrincipal,
        purpose_value: Purpose,
        id: Uuid,
        now: i64,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<Projection<Blocker>>, Error> {
        q.require_schema(&BLOCKERS).map_err(query_error)?;
        let (mut tx, before) = self.rotation_snapshot(p, purpose_value).await?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.rotations WHERE tenant_id=$1::uuid AND purpose=$2 AND id=$3)").bind(p.tenant_id()).bind(purpose(purpose_value)).bind(id).fetch_one(&mut *tx).await.map_err(db)?;
        if !exists {
            return Err(Error::NotFound);
        }
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.principal_id(),
                p.instance_id(),
                purpose(purpose_value),
                id,
                &before,
            ))
            .map_err(query_error)?;
        let page = gates::page(&mut tx, p.tenant_id(), id, now, q, codec, &binding).await?;
        tx.rollback().await.map_err(db)?;
        self.confirm_rotation_read(p, &before).await?;
        Ok(page)
    }
}
