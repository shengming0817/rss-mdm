use super::*;
use crate::{
    database::db,
    operations::{Actor, Operation},
};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};

fn uuid(row: &PgRow, name: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(&row.try_get::<String, _>(name).map_err(db)?)
        .map_err(|_| Error::Unavailable(Failure::Database))
}
fn digest(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("closed operation"))
    )
}
fn locator(proof: &VerifiedChannelCredential) -> String {
    proof.locator.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) async fn lock_channel(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<(), Error> {
    let key = serde_json::to_string(&(tenant, device, channel)).expect("closed identity");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(key)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(())
}
pub(crate) async fn task_capable(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bindings WHERE tenant_id=$1::uuid AND registration=$2::uuid AND wire_version=2 AND capabilities='[\"inventory.basic.v2\",\"task.execute.v2\"]')")
        .bind(tenant)
        .bind(registration)
        .fetch_one(tx)
        .await
}
impl DeviceService {
    #[cfg(test)]
    pub(super) async fn bind_inner(
        &self,
        admin: &AuthorizedPrincipal,
        credential: &VerifiedChannelCredential,
        command: &BindRegistration,
        audit: &RequestAudit,
    ) -> Result<RegistrationReceipt, Error> {
        if command.operation_id.is_nil()
            || command.request_id.is_nil()
            || command.expected_generation < 0
        {
            return Err(Error::Malformed);
        }
        if admin.tenant_id() != self.tenant
            || admin.tenant_id() != credential.tenant.to_string()
            || command.source != credential.source
        {
            return Err(Error::Forbidden);
        }
        let budget = self.retirement_budget();
        let operation_control = budget.operation_control();
        let attempt = self
            .audit_store
            .execute_with_operation(
                rss_request_context::TenantId::parse(admin.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &operation_control,
                (
                    &self.audit_store,
                    BindingInputs {
                        admin,
                        credential,
                        command,
                        audit,
                        facts: Vec::new(),
                    },
                ),
                |(store, inputs), tx| {
                    Box::pin(async move {
                        let (receipt, replayed, digest) = tx
                            .with_connection_context(inputs, |inputs, c| {
                                Box::pin(bind_on(c, inputs))
                            })
                            .await?;
                        for fact in &inputs.facts {
                            store.append(tx, fact, false).await.map_err(Error::from)?;
                        }
                        let fact = rss_mdm_audit_integration::Fact::business(
                            inputs.audit,
                            &format!(
                                "registration_bind:{}:{}",
                                inputs.admin.principal_id(),
                                inputs.command.operation_id
                            ),
                            digest.as_bytes(),
                            200,
                            "success",
                            Some(inputs.command.request_id),
                        )
                        .map_err(Error::from)?;
                        store
                            .append(tx, &fact, replayed)
                            .await
                            .map_err(Error::from)?;
                        if replayed {
                            inputs.audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        inputs.audit.mark_commit_started();
                        Ok(receipt)
                    })
                },
            )
            .await;
        crate::operations::settle(attempt, audit)
    }
    pub(crate) async fn revoke_inner(
        &self,
        admin: &AuthorizedPrincipal,
        device: &str,
        registration: Uuid,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<RevocationReceipt, Error> {
        if key.is_nil() || registration.is_nil() || Id::new(device).is_err() {
            return Err(Error::Malformed);
        }
        if admin.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        admin.credentials(device)?;
        let digest = digest(&("credential_revoke", device, registration));
        let operation = Operation {
            actor: Actor::from_authorized(admin),
            key,
            digest: &digest,
        };
        let budget = self.retirement_budget();
        let operation_control = budget.operation_control();
        let attempt = self
            .audit_store
            .execute_with_operation(
                rss_request_context::TenantId::parse(admin.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &operation_control,
                (
                    &self.audit_store,
                    RevokeInputs {
                        admin,
                        device,
                        registration,
                        key,
                        audit,
                        operation: &operation,
                        facts: Vec::new(),
                    },
                ),
                |(store, inputs), tx| {
                    Box::pin(async move {
                        let (receipt, replayed) = tx
                            .with_connection_context(inputs, |inputs, c| {
                                Box::pin(revoke_on(c, inputs))
                            })
                            .await?;
                        for fact in &inputs.facts {
                            store.append(tx, fact, false).await.map_err(Error::from)?;
                        }
                        let fact = rss_mdm_audit_integration::Fact::business(
                            inputs.audit,
                            &format!(
                                "credential_revoke:{}:{}",
                                inputs.admin.principal_id(),
                                inputs.key
                            ),
                            inputs.operation.digest.as_bytes(),
                            200,
                            "success",
                            None,
                        )
                        .map_err(Error::from)?;
                        store
                            .append(tx, &fact, replayed)
                            .await
                            .map_err(Error::from)?;
                        if replayed {
                            inputs.audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        inputs.audit.mark_commit_started();
                        Ok(receipt)
                    })
                },
            )
            .await;
        crate::operations::settle(attempt, audit)
    }
    pub(crate) async fn authorize_report(
        &self,
        credential: &VerifiedChannelCredential,
        source: ReportSource,
    ) -> Result<(DevicePrincipal, Scope), Error> {
        if source != credential.source || self.tenant != credential.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let tenant = credential.tenant.to_string();
        let mut tx = self.access.begin(&tenant).await?;
        // Probe the immutable locator, then lock only the registration first. Replacement uses
        // the same order; post-lock reads recheck credential and source state.
        let row=sqlx::query("SELECT registration::text AS id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3")
            .bind(&tenant).bind(credential.channel.as_str()).bind(locator(credential)).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
        let registration = uuid(&row, "id")?;
        let row=sqlx::query("SELECT device,generation,channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND channel=$3 AND state='active' FOR SHARE")
            .bind(&tenant).bind(registration.to_string()).bind(credential.channel.as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
        if credential.channel == Channel::Agent {
            let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bindings WHERE tenant_id=$1::uuid AND registration=$2::uuid AND wire_version=2 AND capabilities IN ('[\"inventory.basic.v2\"]','[\"inventory.basic.v2\",\"task.execute.v2\"]'))")
                .bind(&tenant).bind(registration.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
            if !current {
                return Err(Error::Unauthorized);
            }
        }
        let child=sqlx::query("SELECT c.id::text AS id,s.epoch::text AS epoch FROM mdm_access.credentials c JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(c.tenant_id,c.registration) WHERE c.tenant_id=$1::uuid AND c.registration=$2::uuid AND c.channel=$3 AND c.locator=$4 AND c.state='active' AND s.source=$5 AND s.coverage=$6 AND s.enabled FOR SHARE OF c,s")
            .bind(&tenant).bind(registration.to_string()).bind(credential.channel.as_str()).bind(locator(credential)).bind(source.as_str()).bind(coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
        let principal = DevicePrincipal {
            tenant: credential.tenant,
            device: row.try_get("device").map_err(db)?,
            registration,
            generation: row.try_get("generation").map_err(db)?,
            channel: channel(&row)?,
            credential: uuid(&child, "id")?,
        };
        let scope = scope(
            credential.tenant,
            registration,
            source.as_str(),
            uuid(&child, "epoch")?,
        )?;
        tx.commit().await.map_err(db)?;
        Ok((principal, scope))
    }
    pub(crate) async fn authorize_task(
        &self,
        credential: &VerifiedChannelCredential,
    ) -> Result<DevicePrincipal, Error> {
        let (principal, _) = self
            .authorize_report(credential, ReportSource::AgentBuiltin)
            .await?;
        let mut tx = self.access.begin(&self.tenant).await?;
        let allowed = task_capable(&mut tx, &self.tenant, &principal.registration().to_string())
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        if !allowed {
            return Err(Error::Forbidden);
        }
        Ok(principal)
    }
    pub(crate) async fn current_scope(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        coordinates: Coordinates,
    ) -> Result<Scope, Error> {
        if proof.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        // Recheck current MDM resource permission. Requested coordinates only choose a source.
        let _permission = proof.inventory(
            device,
            Coordinates {
                source: coordinates.source,
            },
        )?;
        let mut tx = self.access.begin(proof.tenant_id()).await?;
        let row=sqlx::query("SELECT r.id::text AS id,s.epoch::text AS epoch FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.state='active' AND c.state='active' AND s.source=$4 AND s.coverage=$5 AND s.enabled")
            .bind(proof.tenant_id()).bind(device).bind(coordinates.source.channel().as_str()).bind(coordinates.source.as_str()).bind(coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
        let scope = scope(
            TenantId::parse(proof.tenant_id()).map_err(|_| Error::Unauthorized)?,
            uuid(&row, "id")?,
            coordinates.source.as_str(),
            uuid(&row, "epoch")?,
        )?;
        tx.commit().await.map_err(db)?;
        Ok(scope)
    }
}
fn channel(row: &PgRow) -> Result<Channel, Error> {
    match row.try_get::<String, _>("channel").map_err(db)?.as_str() {
        "agent" => Ok(Channel::Agent),
        "mdm" => Ok(Channel::Mdm),
        _ => Err(Error::Unavailable(Failure::Database)),
    }
}
fn unique_or_db(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        Error::Conflict
    } else {
        db(error)
    }
}
pub(crate) async fn retire_state_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    state: &str,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE mdm_access.registrations SET state=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid",
    )
    .bind(tenant)
    .bind(registration.to_string())
    .bind(state)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE mdm_access.credentials SET state=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).bind(state).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

/// Borrow the Database transaction; the caller commits binding, certificate and audit together.
pub(crate) async fn bind_in(
    tx: &mut sqlx::PgConnection,
    admin: &AuthorizedPrincipal,
    credential: &VerifiedChannelCredential,
    command: &BindRegistration,
    device: String,
    ids: [Uuid; 3],
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<RegistrationReceipt, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(format!(
            "request:{}:{}",
            admin.tenant_id(),
            command.request_id
        ))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid)")
            .bind(admin.tenant_id()).bind(command.request_id.to_string()).fetch_one(&mut *tx).await.map_err(db)? { return Err(Error::Conflict); }
    let request_source: String = sqlx::query_scalar(
        "SELECT source FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2::uuid",
    )
    .bind(admin.tenant_id())
    .bind(command.request_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .ok_or(Error::Forbidden)?;
    if request_source != command.source.as_str() || command.source != credential.source {
        return Err(Error::Forbidden);
    }
    lock_channel(tx, admin.tenant_id(), &device, credential.channel).await?;
    let current:i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3")
            .bind(admin.tenant_id()).bind(&device).bind(credential.channel.as_str()).fetch_one(&mut *tx).await.map_err(db)?;
    if current != command.expected_generation {
        return Err(Error::Conflict);
    }
    let generation = current.checked_add(1).ok_or(Error::Conflict)?;
    if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3)")
            .bind(admin.tenant_id()).bind(credential.channel.as_str()).bind(locator(credential)).fetch_one(&mut *tx).await.map_err(db)? { return Err(Error::Conflict); }
    // Registration row locks serialize authorization and replacement in a consistent order.
    let active = sqlx::query("SELECT id::text AS id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3 AND state='active' FOR UPDATE")
            .bind(admin.tenant_id()).bind(&device).bind(credential.channel.as_str()).fetch_optional(&mut *tx).await.map_err(db)?;
    if let Some(row) = active {
        crate::registration_lifecycle::retire(
            tx,
            facts,
            admin.tenant_id(),
            uuid(&row, "id")?,
            "superseded",
        )
        .await?;
    }
    sqlx::query(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING",
    )
    .bind(admin.tenant_id())
    .bind(&device)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    let receipt = RegistrationReceipt {
        operation_id: command.operation_id,
        request_id: command.request_id,
        device,
        registration: ids[0],
        generation,
        channel: credential.channel,
        credential: ids[1],
        epoch: ids[2],
    };
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,'active')")
            .bind(admin.tenant_id()).bind(receipt.registration.to_string()).bind(&receipt.device).bind(receipt.channel.as_str()).bind(generation).bind(command.request_id.to_string()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,'active')")
            .bind(admin.tenant_id()).bind(receipt.credential.to_string()).bind(receipt.registration.to_string()).bind(receipt.channel.as_str()).bind(locator(credential)).execute(&mut *tx).await.map_err(unique_or_db)?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,true)")
            .bind(admin.tenant_id()).bind(receipt.registration.to_string()).bind(command.source.as_str()).bind(receipt.epoch.to_string()).bind(coverage_key()).execute(&mut *tx).await.map_err(db)?;
    enterprise_sources(tx, admin.tenant_id(), &receipt).await?;
    Ok(receipt)
}

async fn enterprise_sources(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    receipt: &RegistrationReceipt,
) -> Result<(), Error> {
    if receipt.channel == Channel::Agent {
        for source in [
            rss_mdm_inventory::Source::AgentScript,
            rss_mdm_inventory::Source::AgentOsquery,
        ] {
            sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES($1::uuid,$2::uuid,$3,$4::uuid,'enterprise-task-v1',true)")
                .bind(tenant).bind(receipt.registration.to_string()).bind(source.as_str()).bind(Uuid::new_v4().to_string()).execute(&mut *tx).await.map_err(db)?;
        }
    }
    Ok(())
}

pub(crate) async fn bind_agent_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    capabilities: &str,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_access.agent_bindings(tenant_id,registration,wire_version,capabilities) VALUES($1::uuid,$2::uuid,2,$3)").bind(tenant).bind(registration.to_string()).bind(capabilities).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}
pub(crate) async fn replace_mdm_credential_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
    locator: &str,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_access.credentials SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active'").bind(tenant).bind(registration).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm',$4,'active')").bind(tenant).bind(Uuid::new_v4().to_string()).bind(registration).bind(locator).execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

pub(crate) async fn revalidate(
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
) -> Result<Scope, Error> {
    revalidate_source(tx, principal, rss_mdm_inventory::ReportSource::MdmWindows).await
}
pub(crate) async fn revalidate_source(
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Scope, Error> {
    if principal.channel() != source.channel() {
        return Err(Error::Forbidden);
    }
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    crate::device::store::lock_channel(tx, &tenant, principal.device(), principal.channel())
        .await?;
    let live = sqlx::query("SELECT device,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND channel=$3 AND state='active'")
        .bind(&tenant).bind(&registration).bind(principal.channel().as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if live.try_get::<String, _>("device").map_err(db)? != principal.device()
        || live.try_get::<i64, _>("generation").map_err(db)? != principal.generation()
    {
        return Err(Error::Unauthorized);
    }
    sqlx::query("SELECT id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND registration=$2::uuid AND id=$3::uuid AND state='active'")
        .bind(&tenant).bind(&registration).bind(principal.credential().to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let row = sqlx::query("SELECT epoch::text FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled AND coverage=$4 FOR UPDATE")
        .bind(&tenant).bind(&registration).bind(source.as_str()).bind(crate::device::coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
    crate::device::scope(
        principal.tenant(),
        principal.registration(),
        source.as_str(),
        Uuid::parse_str(&row.try_get::<String, _>("epoch").map_err(db)?)
            .map_err(|_| Error::Unavailable(Failure::Database))?,
    )
    .map_err(Into::into)
}

struct RevokeInputs<'a> {
    admin: &'a AuthorizedPrincipal,
    device: &'a str,
    registration: Uuid,
    key: Uuid,
    audit: &'a RequestAudit,
    operation: &'a Operation<'a>,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn revoke_on(
    tx: &mut sqlx::PgConnection,
    inputs: &mut RevokeInputs<'_>,
) -> Result<(RevocationReceipt, bool), Error> {
    let RevokeInputs {
        admin,
        device,
        registration,
        key,
        audit,
        operation,
        facts,
    } = inputs;
    let device = *device;
    let admin = *admin;
    let audit = *audit;
    let operation = *operation;
    let registration = *registration;
    let key = *key;
    if let Some(old) = crate::operations::replay(tx, operation).await? {
        let receipt =
            serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::Database))?;
        audit.registration(registration);
        admin.credentials(device)?;
        return Ok((receipt, true));
    }
    let row = sqlx::query("SELECT channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND device=$3")
            .bind(admin.tenant_id()).bind(registration.to_string()).bind(device).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
    let channel = channel(&row)?;
    lock_channel(tx, admin.tenant_id(), device, channel).await?;
    let row = sqlx::query("SELECT state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
            .bind(admin.tenant_id()).bind(registration.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
    if row.try_get::<String, _>("state").map_err(db)? != "active" {
        return Err(Error::Conflict);
    }
    crate::registration_lifecycle::retire(tx, facts, admin.tenant_id(), registration, "revoked")
        .await?;
    admin.credentials(device)?;
    audit.registration(registration);
    let receipt = RevocationReceipt {
        operation_id: key,
        registration,
    };
    crate::operations::save(
        tx,
        operation,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false))
}

#[cfg(test)]
struct BindingInputs<'a> {
    admin: &'a AuthorizedPrincipal,
    credential: &'a VerifiedChannelCredential,
    command: &'a BindRegistration,
    audit: &'a RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
#[cfg(test)]
async fn bind_on(
    tx: &mut sqlx::PgConnection,
    inputs: &mut BindingInputs<'_>,
) -> Result<(RegistrationReceipt, bool, String), Error> {
    let BindingInputs {
        admin,
        credential,
        command,
        audit,
        facts,
    } = inputs;
    let admin = *admin;
    let credential = *credential;
    let command = *command;
    let audit = *audit;
    // The accepted request supplies the target; its UUID alone never authorizes binding.
    let request = sqlx::query("SELECT g.device,r.source FROM mdm_access.requests r JOIN mdm_access.grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND g.actor=$3 AND g.instance=$4 AND g.state='consumed' AND r.state<>'cancelled'")
            .bind(admin.tenant_id()).bind(command.request_id.to_string()).bind(admin.principal_id()).bind(admin.instance_id()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
    let device: String = request.try_get("device").map_err(db)?;
    if request.try_get::<String, _>("source").map_err(db)? != command.source.as_str() {
        return Err(Error::Forbidden);
    }
    let _permission = admin.enrollment(&device)?;
    audit.target(&device);
    let digest = digest(&(
        "registration_bind",
        command,
        credential.channel,
        locator(credential),
    ));
    let operation = Operation {
        actor: Actor::from_authorized(admin),
        key: command.operation_id,
        digest: &digest,
    };
    if let Some(old) = crate::operations::replay(tx, &operation).await? {
        let receipt: RegistrationReceipt =
            serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::Database))?;
        audit.registration(receipt.registration);
        admin.enrollment(&device)?;
        return Ok((receipt, true, digest));
    }
    let receipt = bind_in(
        tx,
        admin,
        credential,
        command,
        device,
        [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
        facts,
    )
    .await?;
    audit.registration(receipt.registration);
    crate::operations::save(
        tx,
        &operation,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((receipt, false, digest))
}
