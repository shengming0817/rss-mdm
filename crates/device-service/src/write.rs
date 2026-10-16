use crate::*;
use rss_mdm_audit_integration::{Fact, ManagementResult, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_inventory::Channel;
use rss_mdm_registration_service::device::endpoints;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

#[derive(serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Change<'a> {
    Confirm(&'a Confirm),
    Revoke { id: Uuid, request: &'a Revoke },
}
impl Change<'_> {
    fn operation(&self) -> Uuid {
        match self {
            Self::Confirm(r) => r.operation_id,
            Self::Revoke { request, .. } => request.operation_id,
        }
    }
    fn action(&self) -> &'static str {
        match self {
            Self::Confirm(_) => "device_association_confirm",
            Self::Revoke { .. } => "device_association_revoke",
        }
    }
}
impl Associations {
    pub async fn confirm(
        &self,
        proof: &AuthorizedPrincipal,
        request: &Confirm,
        audit: &RequestAudit,
    ) -> Result<Association> {
        validate_confirm(request)?;
        self.change(proof, Change::Confirm(request), audit).await
    }
    pub async fn revoke(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        request: &Revoke,
        audit: &RequestAudit,
    ) -> Result<Association> {
        if id.is_nil()
            || request.operation_id.is_nil()
            || request.expected_version < 1
            || !model::text(&request.reason)
        {
            return Err(Error::Malformed);
        }
        self.change(proof, Change::Revoke { id, request }, audit)
            .await
    }
    async fn change(
        &self,
        proof: &AuthorizedPrincipal,
        change: Change<'_>,
        audit: &RequestAudit,
    ) -> Result<Association> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        proof.bind_audit(audit)?;
        audit.operation(change.operation(), change.action());
        let digest: Vec<u8> =
            Sha256::digest(serde_json::to_vec(&change).map_err(|_| Error::Malformed)?).to_vec();
        let budget = AuditBudget::new(Duration::from_secs(8));
        let attempt = self
            .audit
            .write(
                self.tenant,
                &budget.control(),
                (self, proof, &change, audit, &digest),
                |(service, proof, change, audit, digest), tx| {
                    Box::pin(
                        async move { service.change_in(tx, proof, change, audit, digest).await },
                    )
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v.into_value())
            },
            |e| Err(model::transaction_error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(model::transaction_error(e))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |e| Err(model::transaction_error(e)),
        )
    }
    async fn change_in<T: rss_request_context::ExecutionTimer>(
        &self,
        tx: &mut rss_audit_postgres::WriteAuditTransaction<'_, '_, '_, T>,
        proof: &AuthorizedPrincipal,
        change: &Change<'_>,
        audit: &RequestAudit,
        digest: &[u8],
    ) -> Result<Association> {
        let (result, replayed) = tx
            .with_connection_context(
                &mut (proof, change, audit, digest),
                |(proof, change, audit, digest), c| {
                    Box::pin(write_on(c, proof, change, audit, digest))
                },
            )
            .await?;
        audit.target(&result.id.to_string());
        let fact = Fact::business(
            audit,
            &format!("device_association:{}", change.operation()),
            digest,
            200,
            "success",
            None,
        )?
        .with_details(serde_json::json!({"association":result}))?;
        self.audit.append(tx, &fact, replayed).await?;
        if replayed {
            audit.management_result(ManagementResult::Replayed);
        }
        proof.check_live()?;
        audit.mark_commit_started();
        Ok(result)
    }
}
async fn write_on(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
    change: &Change<'_>,
    _audit: &RequestAudit,
    digest: &[u8],
) -> Result<(Association, bool)> {
    let snapshot = read::authorization(c, proof).await?;
    // Audit lock is already held. Operation identity is tenant-wide and never transferable.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2578))")
        .bind(format!("{}:{}", proof.tenant_id(), change.operation()))
        .execute(&mut *c)
        .await?;
    let prior=sqlx::query("SELECT actor,instance,digest,result::text FROM mdm_devices.operations WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(proof.tenant_id()).bind(change.operation()).fetch_optional(&mut *c).await?;
    if let Some(row) = prior {
        if row.try_get::<String, _>("actor")? != proof.principal_id()
            || row.try_get::<String, _>("instance")? != proof.instance_id()
            || row.try_get::<Vec<u8>, _>("digest")? != digest
        {
            return Err(Error::Conflict);
        }
        let result: Association = serde_json::from_str(&row.try_get::<String, _>("result")?)
            .map_err(|_| Error::Storage)?;
        read::authorize(&snapshot, proof, &result.members, true)?;
        return Ok((result, true));
    }
    let members = match change {
        Change::Confirm(r) => vec![r.mdm.clone(), r.agent.clone()],
        Change::Revoke { id, .. } => read::load(c, proof.tenant_id(), *id).await?.members,
    };
    read::authorize(&snapshot, proof, &members, true)?;
    let world = identity::world(
        c,
        TenantId::parse(proof.tenant_id()).map_err(|_| Error::Malformed)?,
    )
    .await?;
    read::lock_members(c, proof.tenant_id(), &members).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    let id = match change {
        Change::Confirm(r) => {
            persist(
                c,
                proof.tenant_id(),
                proof.principal_id(),
                r,
                &identity::evidence(&world, &members),
                State::Confirmed,
            )
            .await?
            .id
        }
        Change::Revoke { id, request } => {
            let changed=sqlx::query("UPDATE mdm_devices.associations SET version=version+1,state='revoked',revoked_by=$4,revoked_at=$5,reason=$6 WHERE tenant_id=$1::uuid AND id=$2 AND version=$3 AND state<>'revoked'")
                .bind(proof.tenant_id()).bind(id).bind(request.expected_version).bind(proof.principal_id()).bind(now).bind(&request.reason).execute(&mut *c).await?.rows_affected();
            if changed != 1 {
                return Err(Error::Conflict);
            }
            sqlx::query("UPDATE mdm_devices.members SET released=true WHERE tenant_id=$1::uuid AND association_id=$2").bind(proof.tenant_id()).bind(id).execute(&mut *c).await?;
            *id
        }
    };
    let result = read::load(c, proof.tenant_id(), id).await?;
    sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,$3,$4,$5,$6::jsonb)")
        .bind(proof.tenant_id()).bind(change.operation()).bind(proof.principal_id()).bind(proof.instance_id()).bind(digest).bind(serde_json::to_string(&result).map_err(|_|Error::Storage)?).execute(c).await?;
    Ok((result, false))
}

/// One CAS and membership implementation for administrator and automatic decisions.
pub(crate) async fn persist(
    c: &mut PgConnection,
    tenant: &str,
    actor: &str,
    r: &Confirm,
    hardware: &std::collections::BTreeMap<String, Hardware>,
    state: State,
) -> Result<Association> {
    let members = [r.mdm.clone(), r.agent.clone()];
    read::lock_members(c, tenant, &members).await?;
    if state == State::Confirmed {
        for m in &members {
            if endpoints::current_in(c, tenant, &m.device, m.channel)
                .await?
                .as_ref()
                != Some(m)
            {
                return Err(Error::Conflict);
            }
        }
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    let state = match state {
        State::Confirmed => "confirmed",
        State::NeedsVerification => "needs_verification",
        State::Revoked => return Err(Error::Malformed),
    };
    let hardware = serde_json::to_value(hardware).map_err(|_| Error::Storage)?;
    let id = r.association_id.unwrap_or_else(Uuid::new_v4);
    if let Some(id) = r.association_id {
        let old = read::load(c, tenant, id).await?;
        if old.version != r.expected_version
            || old.members.iter().any(|m| {
                !members
                    .iter()
                    .any(|n| n.device == m.device && n.channel == m.channel)
            })
        {
            return Err(Error::Conflict);
        }
        let changed=sqlx::query("UPDATE mdm_devices.associations SET version=version+1,state=$7,evidence=CASE WHEN $7='confirmed' THEN $4 ELSE evidence END,hardware=$8,confirmed_by=CASE WHEN $7='confirmed' THEN $5 ELSE confirmed_by END,confirmed_at=CASE WHEN $7='confirmed' THEN $6 ELSE confirmed_at END,revoked_by=NULL,revoked_at=NULL,reason=NULL WHERE tenant_id=$1::uuid AND id=$2 AND version=$3")
            .bind(tenant).bind(id).bind(r.expected_version).bind(&r.evidence).bind(actor).bind(now).bind(state).bind(&hardware).execute(&mut *c).await?.rows_affected();
        if changed != 1 {
            return Err(Error::Conflict);
        }
        for m in &members {
            sqlx::query("UPDATE mdm_devices.members SET registration_id=$4,generation=$5,released=false WHERE tenant_id=$1::uuid AND association_id=$2 AND channel=$3")
            .bind(tenant).bind(id).bind(m.channel.as_str()).bind(m.registration_id).bind(m.generation).execute(&mut *c).await?;
        }
    } else {
        sqlx::query("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7)")
            .bind(tenant).bind(id).bind(state).bind(&r.evidence).bind(&hardware).bind(actor).bind(now).execute(&mut *c).await?;
        for m in &members {
            sqlx::query("INSERT INTO mdm_devices.members(tenant_id,association_id,device,channel,registration_id,generation) VALUES($1::uuid,$2,$3,$4,$5,$6)")
            .bind(tenant).bind(id).bind(&m.device).bind(m.channel.as_str()).bind(m.registration_id).bind(m.generation).execute(&mut *c).await?;
        }
    }
    read::load(c, tenant, id).await
}

fn validate_confirm(request: &Confirm) -> Result<()> {
    if request.operation_id.is_nil()
        || request.expected_version < 0
        || request.association_id.is_none() != (request.expected_version == 0)
        || request.mdm.channel != Channel::Mdm
        || request.agent.channel != Channel::Agent
        || request.mdm.device == request.agent.device
        || !model::text(&request.evidence)
        || [&request.mdm, &request.agent]
            .iter()
            .any(|m| !model::text(&m.device) || m.registration_id.is_nil() || m.generation <= 0)
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

#[cfg(feature = "integration")]
#[path = "confirmation_history.rs"]
mod confirmation_history;
