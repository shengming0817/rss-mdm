use super::*;
use crate::access_store::{Actor, Operation, db};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
fn actor(proof: &VerifiedIdentity) -> Actor<'_> {
    Actor {
        tenant: proof.tenant_id(),
        subject: proof.subject(),
        client: proof.client_id(),
    }
}
fn uuid(row: &PgRow, name: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(&row.try_get::<String, _>(name).map_err(db)?)
        .map_err(|_| Error::Unavailable(Failure::AccessStore))
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
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    device: &str,
    channel: Channel,
) -> Result<(), Error> {
    let key = serde_json::to_string(&(tenant, device, channel)).expect("closed identity");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
impl DeviceService {
    pub(super) async fn bind_inner(
        &self,
        admin: &VerifiedIdentity,
        credential: &VerifiedChannelCredential,
        command: &BindRegistration,
        audit: &Audit,
    ) -> Result<RegistrationReceipt, Error> {
        if command.operation_id.is_nil()
            || command.request_id.is_nil()
            || command.expected_generation < 0
        {
            return Err(Error::Malformed);
        }
        if admin.tenant_id() != credential.tenant.to_string()
            || command.source.channel() != credential.channel
        {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(admin.tenant_id()).await?;
        // The accepted request supplies the target; its UUID alone never authorizes binding.
        let request = sqlx::query("SELECT g.device FROM mdm_access.requests r JOIN mdm_access.grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND g.actor=$3 AND g.client=$4 AND g.state='consumed' AND r.state<>'cancelled'")
            .bind(admin.tenant_id()).bind(command.request_id.to_string()).bind(admin.subject()).bind(admin.client_id()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
        let device: String = request.try_get("device").map_err(db)?;
        let _permission = self.policy.enrollment(admin, &device)?;
        audit.target(&device);
        let digest = digest(&(
            "registration_bind",
            command,
            credential.channel,
            locator(credential),
        ));
        let operation = Operation {
            actor: actor(admin),
            key: command.operation_id,
            digest: &digest,
        };
        if let Some(old) = AccessStore::replay(&mut tx, &operation).await? {
            let receipt: RegistrationReceipt =
                serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::AccessStore))?;
            audit.registration(receipt.registration);
            tx.rollback().await.map_err(db)?;
            return Ok(receipt);
        }
        let receipt = bind_in(
            &mut tx,
            admin,
            credential,
            command,
            device,
            [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
        )
        .await?;
        audit.registration(receipt.registration);
        self.access
            .finish(
                tx,
                &operation,
                &serde_json::to_string(&receipt).expect("closed receipt"),
                audit,
                Some(command.request_id),
            )
            .await?;
        Ok(receipt)
    }
    pub(crate) async fn revoke_inner(
        &self,
        admin: &VerifiedIdentity,
        device: &str,
        registration: Uuid,
        key: Uuid,
        audit: &Audit,
    ) -> Result<RevocationReceipt, Error> {
        if key.is_nil() || registration.is_nil() || Id::new(device).is_err() {
            return Err(Error::Malformed);
        }
        self.policy.credentials(admin, device)?;
        let digest = digest(&("credential_revoke", device, registration));
        let operation = Operation {
            actor: actor(admin),
            key,
            digest: &digest,
        };
        let mut tx = self.access.begin(admin.tenant_id()).await?;
        if let Some(old) = AccessStore::replay(&mut tx, &operation).await? {
            let receipt =
                serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::AccessStore))?;
            audit.registration(registration);
            tx.rollback().await.map_err(db)?;
            return Ok(receipt);
        }
        let row = sqlx::query("SELECT channel FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND device=$3")
            .bind(admin.tenant_id()).bind(registration.to_string()).bind(device).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
        let channel = channel(&row)?;
        lock_channel(&mut tx, admin.tenant_id(), device, channel).await?;
        let row = sqlx::query("SELECT state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
            .bind(admin.tenant_id()).bind(registration.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if row.try_get::<String, _>("state").map_err(db)? != "active" {
            return Err(Error::Conflict);
        }
        retire(&mut tx, admin.tenant_id(), registration, "revoked").await?;
        audit.registration(registration);
        let receipt = RevocationReceipt {
            operation_id: key,
            registration,
        };
        self.access
            .finish(
                tx,
                &operation,
                &serde_json::to_string(&receipt).expect("closed receipt"),
                audit,
                None,
            )
            .await?;
        Ok(receipt)
    }
    pub(super) async fn authorize_report(
        &self,
        credential: &VerifiedChannelCredential,
        source: ReportSource,
    ) -> Result<(DevicePrincipal, ReportAuthority), Error> {
        if source.channel() != credential.channel
            || self.policy.tenant() != credential.tenant.to_string()
        {
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
        Ok((principal, ReportAuthority { scope }))
    }
    pub(crate) async fn current_scope(
        &self,
        proof: &VerifiedIdentity,
        device: &str,
        coordinates: Coordinates,
    ) -> Result<Scope, Error> {
        // Recheck current MDM resource permission. Requested coordinates only choose a source.
        let _permission = self.policy.inventory(
            proof,
            device,
            Coordinates {
                channel: coordinates.channel,
                source: coordinates.source.clone(),
            },
        )?;
        let mut tx = self.access.begin(proof.tenant_id()).await?;
        let row=sqlx::query("SELECT r.id::text AS id,s.epoch::text AS epoch FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.state='active' AND c.state='active' AND s.source=$4 AND s.coverage=$5 AND s.enabled")
            .bind(proof.tenant_id()).bind(device).bind(coordinates.channel.as_str()).bind(&coordinates.source).bind(coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
        let scope = scope(
            TenantId::parse(proof.tenant_id()).map_err(|_| Error::Unauthorized)?,
            uuid(&row, "id")?,
            &coordinates.source,
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
        _ => Err(Error::Unavailable(Failure::AccessStore)),
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
async fn retire(
    tx: &mut Transaction<'_, Postgres>,
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
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE mdm_access.credentials SET state=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).bind(state).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

/// Borrow the AccessStore transaction; the caller commits binding, certificate and audit together.
pub(crate) async fn bind_in(
    tx: &mut Transaction<'_, Postgres>,
    admin: &VerifiedIdentity,
    credential: &VerifiedChannelCredential,
    command: &BindRegistration,
    device: String,
    ids: [Uuid; 3],
) -> Result<RegistrationReceipt, Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(format!(
            "request:{}:{}",
            admin.tenant_id(),
            command.request_id
        ))
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid)")
            .bind(admin.tenant_id()).bind(command.request_id.to_string()).fetch_one(&mut **tx).await.map_err(db)? { return Err(Error::Conflict); }
    lock_channel(tx, admin.tenant_id(), &device, credential.channel).await?;
    let current:i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3")
            .bind(admin.tenant_id()).bind(&device).bind(credential.channel.as_str()).fetch_one(&mut **tx).await.map_err(db)?;
    if current != command.expected_generation {
        return Err(Error::Conflict);
    }
    let generation = current.checked_add(1).ok_or(Error::Conflict)?;
    if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND channel=$2 AND locator=$3)")
            .bind(admin.tenant_id()).bind(credential.channel.as_str()).bind(locator(credential)).fetch_one(&mut **tx).await.map_err(db)? { return Err(Error::Conflict); }
    // Registration row locks serialize authorization and replacement in a consistent order.
    let active = sqlx::query("SELECT id::text AS id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3 AND state='active' FOR UPDATE")
            .bind(admin.tenant_id()).bind(&device).bind(credential.channel.as_str()).fetch_optional(&mut **tx).await.map_err(db)?;
    if let Some(row) = active {
        retire(tx, admin.tenant_id(), uuid(&row, "id")?, "superseded").await?;
    }
    sqlx::query(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING",
    )
    .bind(admin.tenant_id())
    .bind(&device)
    .execute(&mut **tx)
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
            .bind(admin.tenant_id()).bind(receipt.registration.to_string()).bind(&receipt.device).bind(receipt.channel.as_str()).bind(generation).bind(command.request_id.to_string()).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,'active')")
            .bind(admin.tenant_id()).bind(receipt.credential.to_string()).bind(receipt.registration.to_string()).bind(receipt.channel.as_str()).bind(locator(credential)).execute(&mut **tx).await.map_err(unique_or_db)?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,true)")
            .bind(admin.tenant_id()).bind(receipt.registration.to_string()).bind(command.source.as_str()).bind(receipt.epoch.to_string()).bind(coverage_key()).execute(&mut **tx).await.map_err(db)?;
    Ok(receipt)
}
