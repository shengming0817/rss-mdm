//! Tenant registration admission. It never changes active device authority.
//! ref: PostgreSQL src/backend/utils/adt/lockfuncs.c@REL_17_6.
use crate::{Error, Store, database::db, quotas::Channel};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Allowed,
    Paused,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Setting {
    pub channel: Channel,
    pub revision: u64,
    pub admission: State,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub expected_revision: u64,
    pub admission: State,
}

/// The same tenant lock precedes business rows even when no setting exists yet.
/// Tenant-wide serialization also orders cross-channel enrollment consistently.
pub async fn lock_in(c: &mut PgConnection, tenant: &str) -> Result<(), Error> {
    crate::quotas::lock_on(c, tenant).await
}
pub async fn read_in(
    c: &mut PgConnection,
    tenant: &str,
    channel: Channel,
) -> Result<Setting, Error> {
    let row = sqlx::query("SELECT revision,paused FROM mdm_access.registration_admission WHERE tenant_id=$1::uuid AND channel=$2")
        .bind(tenant).bind(channel.as_str()).fetch_optional(c).await.map_err(db)?;
    let (revision, paused) = match row {
        None => (0, false),
        Some(r) => (
            u64::try_from(r.try_get::<i64, _>("revision").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            r.try_get("paused").map_err(db)?,
        ),
    };
    Ok(Setting {
        channel,
        revision,
        admission: if paused {
            State::Paused
        } else {
            State::Allowed
        },
    })
}
pub async fn require_new_in(
    c: &mut PgConnection,
    tenant: &str,
    channel: Channel,
) -> Result<(), Error> {
    lock_in(c, tenant).await?;
    if read_in(c, tenant, channel).await?.admission == State::Paused {
        return Err(Error::EnrollmentPaused);
    }
    Ok(())
}
/// A bound Apple request is created at Authenticate; Windows binds at signing,
/// so Windows additionally needs the first authenticated management transaction.
pub async fn require_request_in(
    c: &mut PgConnection,
    tenant: &str,
    request: Uuid,
    channel: Channel,
) -> Result<(), Error> {
    lock_in(c, tenant).await?;
    let established: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND q.id=$2 AND r.state='active' AND (r.first_authenticated_at IS NOT NULL OR (q.source='mdm.apple' AND q.state='bound')))")
        .bind(tenant).bind(request).fetch_one(&mut *c).await.map_err(db)?;
    if !established {
        require_new_in(c, tenant, channel).await?;
    }
    Ok(())
}

pub struct Admission {
    store: Arc<Store>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl Admission {
    pub fn new(store: Arc<Store>, audit: Arc<rss_mdm_audit_integration::AuditStore>) -> Self {
        Self { store, audit }
    }
    pub async fn read(&self, p: &AuthorizedPrincipal) -> Result<Vec<Setting>, Error> {
        p.check_live()?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let mut values = Vec::new();
        for channel in Channel::ALL {
            values.push(read_in(&mut tx, p.tenant_id(), channel).await?);
        }
        tx.commit().await.map_err(db)?;
        Ok(values)
    }
    pub async fn change(
        &self,
        p: &AuthorizedPrincipal,
        channel: Channel,
        change: &Change,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<Setting, Error> {
        use crate::operations::{Actor, Operation};
        p.manage(Permission::RegistrationConfigurationWrite)?;
        if key.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        p.bind_audit(audit)?;
        audit.operation(key, "registration_admission_change");
        let digest = crate::enrollment::digest(&(
            "registration.admission.v1",
            channel,
            change.expected_revision,
            change.admission,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let control = budget.control();
        let result=self.audit.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_|Error::Malformed)?,&control,(&self.audit,p,channel,change,&op,audit),|ctx,tx|Box::pin(async move {
            let (store,p,channel,change,op,audit)=*ctx;
            let (revision,replayed)=tx.with_connection_context(&mut (p,channel,change,op,audit),|ctx,c|Box::pin(async move {
                let (p,channel,change,op,audit)=*ctx;
                lock_in(c,p.tenant_id()).await?;
                if let Some(old)=crate::operations::replay(c,op).await? {return Ok::<_,Error>((serde_json::from_str::<u64>(&old).map_err(|_|Error::Corrupt)?,true));}
                let current=read_in(c,p.tenant_id(),channel).await?;
                if current.revision!=change.expected_revision {return Err(Error::Conflict);}
                let revision=current.revision+1;
                sqlx::query("INSERT INTO mdm_access.registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,channel) DO UPDATE SET revision=EXCLUDED.revision,paused=EXCLUDED.paused")
                    .bind(p.tenant_id()).bind(channel.as_str()).bind(revision as i64).bind(change.admission==State::Paused).execute(&mut *c).await.map_err(db)?;
                p.manage(Permission::RegistrationConfigurationWrite)?;
                crate::operations::save(c,op,&revision.to_string(),audit).await?;
                Ok((revision,false))
            })).await?;
            let fact=Fact::business(audit,&format!("registration-admission:{}:{}",p.principal_id(),op.key),op.digest.as_bytes(),200,"success",None)?;
            store.append(tx,&fact,replayed).await.map_err(Error::from)?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();
            Ok(Setting{channel,revision,admission:change.admission})
        })).await;
        crate::operations::settle(result, audit)
    }
}

/// First Windows management admission uses durable authentication, not certificate issuance.
pub async fn require_windows_in(
    c: &mut PgConnection,
    p: &crate::DevicePrincipal,
) -> Result<(), Error> {
    let tenant = p.tenant().to_string();
    lock_in(c, &tenant).await?;
    let authenticated: bool = sqlx::query_scalar("SELECT first_authenticated_at IS NOT NULL FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if !authenticated {
        require_new_in(c, &tenant, Channel::WindowsMdm).await?;
    }
    Ok(())
}
