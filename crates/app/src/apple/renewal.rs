//! Replace the enrollment profile before expiry; switch authority only on new-key mTLS proof.
//! ref: Apple Managing certificates for device management services and devices (2026-09-23)
use super::{Apple, attempt, certificate, enrollment, profile, protocol};
use crate::{
    AccessStore, Error, access_store::db, api::App, audit::Audit, device::DevicePrincipal,
};
use rss_mdm_inventory::Channel;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

// A short-lived certificate renews after two thirds of its lifetime; long-lived
// certificates enter the window seven days before expiry. No immediate renewal loop.
pub(super) fn due(before: i64, after: i64, now: i64) -> bool {
    now < after && now >= after - ((after - before) / 3).min(7 * 86400)
}
pub(super) async fn maintain(
    apple: &Apple,
    access: &AccessStore,
    tenant: &str,
    now: i64,
) -> Result<(), Error> {
    let mut tx = access.begin(tenant).await?;
    let health = sqlx::query("WITH due AS (SELECT a.registration,s.not_after,CASE WHEN s.not_after<=$2 THEN 2 WHEN s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 THEN 1 ELSE 0 END AS level FROM mdm_apple.devices a JOIN mdm_apple.scep_attempts s ON (s.tenant_id,s.registration)=(a.tenant_id,a.registration) WHERE a.tenant_id=$1::uuid AND a.state='active' AND s.state='bound' AND a.identity_health<>CASE WHEN s.not_after<=$2 THEN 2 WHEN s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 THEN 1 ELSE 0 END ORDER BY s.not_after,a.registration LIMIT 32) UPDATE mdm_apple.devices a SET identity_health=due.level FROM due WHERE a.tenant_id=$1::uuid AND a.registration=due.registration RETURNING a.registration::text,due.not_after,due.level")
        .bind(tenant).bind(now).fetch_all(&mut *tx).await.map_err(db)?;
    let candidates = sqlx::query("SELECT s.id::text,s.not_before,s.not_after,r.device FROM mdm_apple.scep_attempts s JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE s.tenant_id=$1::uuid AND s.state='bound' AND r.state='active' AND a.state='active' AND s.configuration=$3 AND s.not_after>$2 AND s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 AND EXISTS(SELECT 1 FROM mdm_access.report_sources p WHERE (p.tenant_id,p.registration)=(r.tenant_id,r.id) AND p.source='mdm.apple' AND p.enabled) AND NOT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts pending WHERE pending.tenant_id=s.tenant_id AND pending.renewal_of=s.id AND pending.state IN ('prepared','consumed') AND pending.expires_at>clock_timestamp()) ORDER BY s.not_after,s.id LIMIT 32")
        .bind(tenant).bind(now).bind(apple.configuration.as_slice()).fetch_all(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    for row in health {
        let level: i32 = row.try_get("level").map_err(db)?;
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_identity_health","registration":row.try_get::<String,_>("registration").map_err(db)?,"expires_at":row.try_get::<i64,_>("not_after").map_err(db)?,"state":match level {0=>"valid",1=>"renewal_due",_=>"expired"}})
        );
    }
    for candidate in candidates {
        prepare(apple, access, tenant, now, candidate).await?;
    }
    Ok(())
}
async fn prepare(
    apple: &Apple,
    access: &AccessStore,
    tenant: &str,
    now: i64,
    candidate: PgRow,
) -> Result<(), Error> {
    let mut tx = access.begin(tenant).await?;
    let device: String = candidate.try_get("device").map_err(db)?;
    crate::device::store::lock_channel(&mut tx, tenant, &device, Channel::Mdm).await?;
    let old = sqlx::query("SELECT s.id::text,s.enrollment::text,s.registration::text,s.not_before,s.not_after,r.generation FROM mdm_apple.scep_attempts s JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.state='bound' AND r.state='active' AND a.state='active' AND s.configuration=$3 AND EXISTS(SELECT 1 FROM mdm_access.report_sources p WHERE (p.tenant_id,p.registration)=(r.tenant_id,r.id) AND p.source='mdm.apple' AND p.enabled) FOR UPDATE OF s,r,a")
        .bind(tenant).bind(candidate.try_get::<String,_>("id").map_err(db)?).bind(apple.configuration.as_slice()).fetch_optional(&mut *tx).await.map_err(db)?;
    let Some(old) = old else {
        return Ok(());
    };
    let before = old.try_get("not_before").map_err(db)?;
    let after = old.try_get("not_after").map_err(db)?;
    if !due(before, after, now) {
        return Ok(());
    }
    let old_id: String = old.try_get("id").map_err(db)?;
    let pending = sqlx::query("SELECT id::text,expires_at>clock_timestamp() AS live FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND renewal_of=$2::uuid AND state IN ('prepared','consumed') FOR UPDATE")
        .bind(tenant).bind(&old_id).fetch_optional(&mut *tx).await.map_err(db)?;
    if let Some(pending) = pending {
        if pending.try_get::<bool, _>("live").map_err(db)? {
            return Ok(());
        }
        let expired: String = pending.try_get("id").map_err(db)?;
        sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(&expired).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE mdm_apple.attempts SET state='superseded' WHERE tenant_id=$1::uuid AND certificate=$2::uuid").bind(tenant).bind(expired).execute(&mut *tx).await.map_err(db)?;
    }
    let id = Uuid::new_v4();
    let enrollment = crate::enrollment::store::uuid(&old, "enrollment")?;
    let secret = zeroize::Zeroizing::new(crate::enrollment::random());
    let signed = apple.signer.sign(
        &profile::enrollment(&apple.config, enrollment, id, &secret)?,
        now,
    )?;
    let request = protocol::command(
        id,
        protocol::dictionary([
            ("RequestType", "InstallProfile".into()),
            ("Payload", plist::Value::Data(signed)),
        ]),
    )?;
    let registration: String = old.try_get("registration").map_err(db)?;
    let generation: i64 = old.try_get("generation").map_err(db)?;
    let deadline = after.min(now + 3600);
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,password_version,configuration,state,issuer,expires_at,registration,renewal_of,generation,challenge_hash) SELECT $1::uuid,$2::uuid,$3::uuid,coalesce(max(password_version),0)+1,$4,'prepared',$5,to_timestamp($6),$7::uuid,$8::uuid,$9,$10 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$3::uuid")
        .bind(tenant).bind(id.to_string()).bind(enrollment.to_string()).bind(apple.configuration.as_slice()).bind(apple.authority.issuer_fingerprint.as_slice()).bind(deadline as f64).bind(&registration).bind(&old_id).bind(generation).bind(Sha256::digest(secret.as_bytes()).as_slice()).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,certificate,phase,request,state,deadline) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$2::uuid,'renew',$5,'pending',to_timestamp($6))")
        .bind(tenant).bind(id.to_string()).bind(&registration).bind(generation).bind(request).bind(deadline as f64).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp() WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(&registration).execute(&mut *tx).await.map_err(db)?;
    let audit = Audit::new(tenant.into(), "apple_renewal");
    audit.target(&device);
    audit.registration(
        Uuid::parse_str(&registration)
            .map_err(|_| Error::Unavailable(crate::Failure::AppleInvariant))?,
    );
    access
        .commit_audited_status(tx, &audit, Some(id), 202)
        .await?;
    audit.finalize(None);
    eprintln!(
        "{}",
        serde_json::json!({"event":"apple_identity_renewal","registration":registration,"generation":generation,"expires_at":after,"attempt":id})
    );

    Ok(())
}

/// Lock in the same order as revocation, then prove the active predecessor and generation.
async fn current(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: Uuid,
) -> Result<Option<PgRow>, Error> {
    let device = sqlx::query_scalar::<_,String>("SELECT r.device FROM mdm_apple.scep_attempts s JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.renewal_of IS NOT NULL")
        .bind(tenant).bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?;
    let Some(device) = device else {
        return Ok(None);
    };
    crate::device::store::lock_channel(tx, tenant, &device, Channel::Mdm).await?;
    let row = sqlx::query("SELECT s.state,s.enrollment::text,s.registration::text,s.renewal_of::text,s.configuration,s.challenge_hash,s.transaction_id,s.csr_digest,s.spki,s.fingerprint,s.generation,a.udid,r.device,old.spki AS old_spki FROM mdm_apple.scep_attempts s JOIN mdm_apple.scep_attempts old ON (old.tenant_id,old.id)=(s.tenant_id,s.renewal_of) JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.state IN ('prepared','consumed') AND s.expires_at>clock_timestamp() AND old.state='bound' AND old.not_after>extract(epoch FROM clock_timestamp()) AND r.state='active' AND r.generation=s.generation AND a.state='active' AND EXISTS(SELECT 1 FROM mdm_apple.attempts delivery WHERE (delivery.tenant_id,delivery.certificate)=(s.tenant_id,s.id) AND delivery.phase='renew' AND delivery.state IN ('sent','not_now','acknowledged') AND delivery.deadline>clock_timestamp()) AND EXISTS(SELECT 1 FROM mdm_access.report_sources p WHERE (p.tenant_id,p.registration)=(r.tenant_id,r.id) AND p.source='mdm.apple' AND p.enabled) FOR UPDATE OF s,old,r,a")
        .bind(tenant).bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    Ok(Some(row))
}
pub(super) async fn challenge(
    app: &App,
    csr: &certificate::Csr,
    secret: &str,
    transaction: &str,
    audit: &Audit,
) -> Result<bool, Error> {
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let Some(row) = current(&mut tx, &tenant, csr.attempt).await? else {
        return Ok(false);
    };
    if row.try_get::<String, _>("state").map_err(db)? != "prepared"
        || crate::enrollment::store::uuid(&row, "enrollment")? != csr.enrollment
        || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != app.apple()?.configuration
        || row.try_get::<Vec<u8>, _>("old_spki").map_err(db)? == csr.spki
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            row.try_get::<Vec<u8>, _>("challenge_hash")
                .map_err(db)?
                .as_slice(),
            Sha256::digest(secret.as_bytes()).as_slice(),
        ))
    {
        return Err(Error::Unauthorized);
    }
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$3,csr_digest=$4,spki=$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(csr.attempt.to_string()).bind(transaction).bind(csr.digest.as_slice()).bind(csr.spki.as_slice()).execute(&mut *tx).await.map_err(db)?;
    app.access
        .commit_audited_status(tx, audit, Some(csr.attempt), 200)
        .await?;
    Ok(true)
}
pub(super) async fn notify(
    app: &App,
    leaf: &certificate::CheckedLeaf,
    csr: &certificate::Csr,
    transaction: &str,
    audit: &Audit,
) -> Result<bool, Error> {
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    let Some(row) = current(&mut tx, &tenant, leaf.attempt).await? else {
        return Ok(false);
    };
    verify(app, &row, leaf)?;
    if row.try_get::<String, _>("transaction_id").map_err(db)? != transaction
        || row.try_get::<Vec<u8>, _>("csr_digest").map_err(db)? != csr.digest
    {
        return Err(Error::Unauthorized);
    }
    enrollment::persist_leaf(&mut tx, &tenant, leaf).await?;
    app.access
        .commit_audited_status(tx, audit, Some(leaf.attempt), 200)
        .await?;
    Ok(true)
}
fn verify(app: &App, row: &PgRow, leaf: &certificate::CheckedLeaf) -> Result<(), Error> {
    if row.try_get::<String, _>("state").map_err(db)? != "consumed"
        || crate::enrollment::store::uuid(row, "enrollment")? != leaf.enrollment
        || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != app.apple()?.configuration
        || row.try_get::<Vec<u8>, _>("spki").map_err(db)? != leaf.spki
        || row
            .try_get::<Option<Vec<u8>>, _>("fingerprint")
            .map_err(db)?
            .is_some_and(|fp| fp != leaf.fingerprint)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(super) async fn activate(
    app: &App,
    leaf: &certificate::CheckedLeaf,
    udid: &str,
) -> Result<(), Error> {
    let tenant = app.identity.tenant.to_string();
    let mut tx = app.access.begin(&tenant).await?;
    // Already-bound certificates continue through the normal admission checks.
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND renewal_of IS NOT NULL AND state<>'bound')")
        .bind(&tenant).bind(leaf.attempt.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
    if !pending {
        return Ok(());
    }
    let row = current(&mut tx, &tenant, leaf.attempt)
        .await?
        .ok_or(Error::Unauthorized)?;
    verify(app, &row, leaf)?;
    if row.try_get::<String, _>("udid").map_err(db)? != udid {
        return Err(Error::Unauthorized);
    }
    let registration: String = row.try_get("registration").map_err(db)?;
    let old: String = row.try_get("renewal_of").map_err(db)?;
    // New credential ID fences principals authenticated before this transaction.
    sqlx::query("UPDATE mdm_access.credentials SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active'").bind(&tenant).bind(&registration).execute(&mut *tx).await.map_err(db)?;
    let locator = leaf
        .fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm',$4,'active')").bind(&tenant).bind(Uuid::new_v4().to_string()).bind(&registration).bind(locator).execute(&mut *tx).await.map_err(db)?;
    enrollment::persist_leaf(&mut tx, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state=CASE WHEN id=$2::uuid THEN 'bound' ELSE 'superseded' END WHERE tenant_id=$1::uuid AND id IN ($2::uuid,$3::uuid)").bind(&tenant).bind(leaf.attempt.to_string()).bind(old).execute(&mut *tx).await.map_err(db)?;
    let audit = Audit::new(tenant.clone(), "apple_renewal");
    audit.target(&row.try_get::<String, _>("device").map_err(db)?);
    audit.registration(Uuid::parse_str(&registration).map_err(|_| Error::Unauthorized)?);
    app.access
        .commit_audited_status(tx, &audit, Some(leaf.attempt), 200)
        .await?;
    audit.finalize(None);
    Ok(())
}

pub(super) async fn management(
    app: &App,
    p: &DevicePrincipal,
    d: &plist::Dictionary,
    bytes: &[u8],
    audit: &Audit,
) -> Result<Option<Vec<u8>>, Error> {
    let message = protocol::management(d)?;
    let tenant = p.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    crate::device::store::lock_channel(&mut tx, &tenant, p.device(), p.channel()).await?;
    let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.generation=$3 AND r.state='active' AND c.id=$4::uuid AND c.state='active' AND a.state='active' AND a.udid=$5 AND EXISTS(SELECT 1 FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration)=(r.tenant_id,r.id) AND s.source='mdm.apple' AND s.enabled))")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).bind(p.credential().to_string()).bind(message.udid).fetch_one(&mut *tx).await.map_err(db)?;
    if !live {
        return Err(Error::Unauthorized);
    }
    if let Some(id) = message.command {
        match attempt::lock(&mut tx, p, id, attempt::Owner::Certificate, bytes).await? {
            None => return Ok(None),
            Some(attempt::Reception::Replay) => {}
            Some(attempt::Reception::Ready(a)) => a.settle(&mut tx, message.status).await?,
        }
    }
    let next=sqlx::query("SELECT a.id::text,a.request FROM mdm_apple.attempts a JOIN mdm_apple.scep_attempts s ON (s.tenant_id,s.id)=(a.tenant_id,a.certificate) WHERE a.tenant_id=$1::uuid AND a.registration=$2::uuid AND a.generation=$3 AND a.phase='renew' AND a.state IN ('pending','sent','not_now') AND s.state IN ('prepared','consumed') AND a.next_attempt<=clock_timestamp() AND a.deadline>clock_timestamp() ORDER BY a.id LIMIT 1 FOR UPDATE OF a")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).fetch_optional(&mut *tx).await.map_err(db)?;
    let result = if let Some(row) = next {
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(row.try_get::<String,_>("id").map_err(db)?).execute(&mut *tx).await.map_err(db)?;
        Some(row.try_get("request").map_err(db)?)
    } else {
        message.command.map(|_| Vec::new())
    };
    if result.is_none() {
        return Ok(None);
    }
    app.access
        .commit_audited_status(tx, audit, None, 200)
        .await?;
    Ok(result)
}
