//! Replace the enrollment profile before expiry; switch authority only on new-key mTLS proof.
//! ref: Apple Managing certificates for device management services and devices (2026-09-23)
use super::{Apple, attempt, certificate, enrollment, profile, protocol};
use crate::HttpState;
use crate::{Error, Store as Database, database::db, device::DevicePrincipal};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

// A short-lived certificate renews after two thirds of its lifetime; long-lived
// certificates enter the window seven days before expiry. No immediate renewal loop.
pub fn due(before: i64, after: i64, now: i64) -> bool {
    now < after && now >= after - ((after - before) / 3).min(7 * 86400)
}
pub async fn maintain(
    apple: &Apple,
    access: &Database,
    audit_store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
    now: i64,
) -> Result<usize, Error> {
    let mut tx = access.begin(tenant).await?;
    let health = sqlx::query("WITH due AS (SELECT a.registration,s.not_after,CASE WHEN s.not_after<=$2 THEN 2 WHEN s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 THEN 1 ELSE 0 END AS level FROM mdm_apple.devices a JOIN mdm_apple.scep_attempts s ON (s.tenant_id,s.registration)=(a.tenant_id,a.registration) WHERE a.tenant_id=$1::uuid AND a.state='active' AND s.state='bound' AND a.identity_health<>CASE WHEN s.not_after<=$2 THEN 2 WHEN s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 THEN 1 ELSE 0 END ORDER BY s.not_after,a.registration LIMIT 32) UPDATE mdm_apple.devices a SET identity_health=due.level FROM due WHERE a.tenant_id=$1::uuid AND a.registration=due.registration RETURNING a.registration::text,due.not_after,due.level")
        .bind(tenant).bind(now).fetch_all(&mut *tx).await.map_err(db)?;
    let mut candidates = Vec::new();
    let mut offset = 0i64;
    while candidates.len() < 32 {
        let rows=sqlx::query("SELECT s.id,s.registration FROM mdm_apple.scep_attempts s JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.state='bound' AND a.state='active' AND s.configuration=$3 AND s.not_after>$2 AND s.not_after-least((s.not_after-s.not_before)/3,604800)<=$2 AND NOT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts pending WHERE pending.tenant_id=s.tenant_id AND pending.renewal_of=s.id AND pending.state IN ('prepared','consumed') AND pending.expires_at>clock_timestamp()) ORDER BY s.not_after,s.id LIMIT 64 OFFSET $4").bind(tenant).bind(now).bind(apple.configuration.as_slice()).bind(offset).fetch_all(&mut *tx).await.map_err(db)?;
        let ids = rows
            .iter()
            .map(|r| r.try_get::<Uuid, _>("registration"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        let active = crate::device::read::active_sources_in(
            &mut tx,
            tenant,
            &ids,
            rss_mdm_inventory::ReportSource::MdmApple,
        )
        .await?;
        for row in &rows {
            let registration = row.try_get("registration").map_err(db)?;
            if active.contains_key(&registration) {
                candidates.push(Candidate {
                    id: row.try_get("id").map_err(db)?,
                    registration,
                });
                if candidates.len() == 32 {
                    break;
                }
            }
        }
        if rows.len() < 64 {
            break;
        }
        offset += 64;
    }
    tx.commit().await.map_err(db)?;
    let progress = health.len() + candidates.len();
    for row in health {
        let level: i32 = row.try_get("level").map_err(db)?;
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_identity_health","registration":row.try_get::<String,_>("registration").map_err(db)?,"expires_at":row.try_get::<i64,_>("not_after").map_err(db)?,"state":match level {0=>"valid",1=>"renewal_due",_=>"expired"}})
        );
    }
    for candidate in candidates {
        prepare(apple, audit_store, tenant, now, candidate).await?;
    }
    Ok(progress)
}
struct Candidate {
    id: Uuid,
    registration: Uuid,
}
async fn prepare(
    apple: &Apple,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
    now: i64,
    candidate: Candidate,
) -> Result<(), Error> {
    let audit = RequestAudit::new(tenant.into(), "apple_renewal");
    audit.identify_service("service:certificate-renewal");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = store
        .write(
            rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &control,
            (store, apple, tenant, now, &candidate, &audit),
            |(store, apple, tenant, now, candidate, audit), tx| {
                Box::pin(async move {
                    let prepared = tx
                        .with_connection_context(
                            &mut (*apple, *tenant, *now, *candidate, *audit),
                            |(apple, tenant, now, candidate, audit), c| {
                                Box::pin(prepare_on(c, apple, tenant, *now, candidate, audit))
                            },
                        )
                        .await?;
                    let Some((prepared, replayed)) = prepared else {
                        return Ok(None);
                    };
                    let fingerprint = rss_mdm_registration_service::enrollment::digest(&prepared);
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-renewal:{}:prepare", prepared.attempt),
                        fingerprint.as_bytes(),
                        202,
                        "success",
                        Some(prepared.enrollment),
                    )
                    .and_then(|fact| {
                        fact.with_details(
                            serde_json::to_value(&prepared).expect("closed renewal coordinates"),
                        )
                    })
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    audit.mark_commit_started();
                    Ok(Some(prepared))
                })
            },
        )
        .await;
    let result = crate::operations::settle(outcome, &audit);
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    if let Some(prepared) = result? {
        eprintln!(
            "{}",
            serde_json::json!({"event":"apple_identity_renewal","coordinates":prepared})
        );
    }
    Ok(())
}
#[derive(serde::Serialize)]
struct PreparedRenewal {
    attempt: Uuid,
    enrollment: Uuid,
    registration: Uuid,
    generation: i64,
    deadline: i64,
    renewal_of: String,
}
async fn prepare_on(
    c: &mut sqlx::PgConnection,
    apple: &Apple,
    tenant: &str,
    now: i64,
    candidate: &Candidate,
    audit: &RequestAudit,
) -> Result<Option<(PreparedRenewal, bool)>, Error> {
    let Some((device, generation)) = crate::device::read::lock_active_source_in(
        c,
        tenant,
        candidate.registration,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?
    else {
        return Ok(None);
    };
    let old=sqlx::query("SELECT s.id::text,s.enrollment::text,s.registration::text,s.not_before,s.not_after FROM mdm_apple.scep_attempts s JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.registration=$4::uuid AND s.state='bound' AND a.state='active' AND s.configuration=$3 FOR UPDATE OF s,a").bind(tenant).bind(candidate.id).bind(apple.configuration.as_slice()).bind(candidate.registration).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(old) = old else { return Ok(None) };
    let before = old.try_get("not_before").map_err(db)?;
    let after = old.try_get("not_after").map_err(db)?;
    if !due(before, after, now) {
        return Ok(None);
    }
    let old_id: String = old.try_get("id").map_err(db)?;
    let pending = sqlx::query("SELECT id::text,expires_at>clock_timestamp() AS live,floor(extract(epoch FROM expires_at))::bigint AS deadline FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND renewal_of=$2::uuid AND state IN ('prepared','consumed') FOR UPDATE")
        .bind(tenant).bind(&old_id).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(pending) = pending {
        if pending.try_get::<bool, _>("live").map_err(db)? {
            let prepared = PreparedRenewal {
                attempt: rss_mdm_registration_service::enrollment::store::uuid(&pending, "id")?,
                enrollment: rss_mdm_registration_service::enrollment::store::uuid(
                    &old,
                    "enrollment",
                )?,
                registration: rss_mdm_registration_service::enrollment::store::uuid(
                    &old,
                    "registration",
                )?,
                generation,
                deadline: pending.try_get("deadline").map_err(db)?,
                renewal_of: old_id,
            };
            audit.target(&device);
            audit.registration(prepared.registration);
            return Ok(Some((prepared, true)));
        }
        let expired: String = pending.try_get("id").map_err(db)?;
        sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(&expired).execute(&mut *c).await.map_err(db)?;
        sqlx::query("UPDATE mdm_apple.attempts SET state='superseded' WHERE tenant_id=$1::uuid AND certificate=$2::uuid").bind(tenant).bind(expired).execute(&mut *c).await.map_err(db)?;
    }
    let id = Uuid::new_v4();
    let enrollment = rss_mdm_registration_service::enrollment::store::uuid(&old, "enrollment")?;
    let secret = zeroize::Zeroizing::new(rss_mdm_registration_service::enrollment::random());
    let signed = apple.signer.sign(
        &profile::enrollment(
            &profile::EnrollmentProfile {
                access_rights: apple.access_rights() as u16,
                scep_url: &apple.config.scep_url,
                scep_provisioner: &apple.config.scep_provisioner,
                apns_topic: &apple.config.apns_topic,
                management_origin: &apple.config.management.origin,
                subject: &certificate::subject(enrollment, id),
            },
            enrollment,
            id,
            &secret,
        )?,
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
    let deadline = after.min(now + 3600);
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(tenant_id,id,enrollment,password_version,configuration,state,issuer,expires_at,registration,renewal_of,generation,challenge_hash,access_rights) SELECT $1::uuid,$2::uuid,$3::uuid,coalesce(max(password_version),0)+1,$4,'prepared',$5,to_timestamp($6),$7::uuid,$8::uuid,$9,$10,$11 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND enrollment=$3::uuid")
        .bind(tenant).bind(id.to_string()).bind(enrollment.to_string()).bind(apple.configuration.as_slice()).bind(apple.authority.issuer_fingerprint().as_slice()).bind(deadline as f64).bind(&registration).bind(&old_id).bind(generation).bind(Sha256::digest(secret.as_bytes()).as_slice()).bind(apple.access_rights()).execute(&mut *c).await.map_err(db)?;
    let request = crate::protection::seal(
        &apple.protection,
        tenant,
        Uuid::parse_str(&registration).map_err(|_| Error::Malformed)?,
        generation,
        id,
        crate::protection::Part::Request,
        &request,
    )?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,certificate,phase,request,state,deadline) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$2::uuid,'renew',$5,'pending',to_timestamp($6))")
        .bind(tenant).bind(id.to_string()).bind(&registration).bind(generation).bind(request).bind(deadline as f64).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp() WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(&registration).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    let registration = Uuid::parse_str(&registration)
        .map_err(|_| Error::Unavailable(crate::Failure::AppleInvariant))?;
    audit.target(&device);
    audit.registration(registration);
    Ok(Some((
        PreparedRenewal {
            attempt: id,
            enrollment,
            registration,
            generation,
            deadline,
            renewal_of: old_id,
        },
        false,
    )))
}

/// Lock in the same order as revocation, then prove the active predecessor and generation.
async fn current(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Option<PgRow>, Error> {
    let registration=sqlx::query_scalar::<_,Uuid>("SELECT registration FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND renewal_of IS NOT NULL").bind(tenant).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
    let Some(registration) = registration else {
        return Ok(None);
    };
    let (device, generation) = crate::device::read::lock_active_source_in(
        tx,
        tenant,
        registration,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?
    .ok_or(Error::Unauthorized)?;
    let row=sqlx::query("SELECT s.state,s.enrollment::text,s.registration::text,s.renewal_of::text,s.configuration,s.challenge_hash,s.transaction_id,s.csr_digest,s.spki,s.fingerprint,s.generation,a.udid,$3::text AS device,old.spki AS old_spki FROM mdm_apple.scep_attempts s JOIN mdm_apple.scep_attempts old ON (old.tenant_id,old.id)=(s.tenant_id,s.renewal_of) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.state IN ('prepared','consumed') AND s.expires_at>clock_timestamp() AND old.state='bound' AND old.not_after>extract(epoch FROM clock_timestamp()) AND s.generation=$4 AND a.state='active' AND EXISTS(SELECT 1 FROM mdm_apple.attempts delivery WHERE (delivery.tenant_id,delivery.certificate)=(s.tenant_id,s.id) AND delivery.phase='renew' AND delivery.state IN ('sent','not_now','acknowledged') AND delivery.deadline>clock_timestamp()) FOR UPDATE OF s,old,a").bind(tenant).bind(id).bind(device).bind(generation).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    Ok(Some(row))
}
pub async fn challenge(
    app: &HttpState,
    csr: &certificate::Csr,
    secret: &str,
    transaction: &str,
    audit: &RequestAudit,
) -> Result<bool, Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control, (app, csr, secret, transaction, audit),
        |(app, csr, secret, transaction, audit), tx| Box::pin(async move {
            let replayed = tx.with_connection_context(&mut (*app, *csr, *secret, *transaction, *audit), |(app, csr, secret, transaction, audit), c| Box::pin(async move {
                let app = *app; let csr = *csr; let secret = *secret; let transaction = *transaction; let audit = *audit;
    let tenant = app.identity.tenant().to_string();
    let Some(row) = current(c, &tenant, csr.attempt()).await? else {
        return Ok::<_, Error>(None);
    };
    if row.try_get::<String, _>("state").map_err(db)? != "prepared"
        || rss_mdm_registration_service::enrollment::store::uuid(&row, "enrollment")? != csr.enrollment()
        || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != app.apple()?.configuration
        || row.try_get::<Vec<u8>, _>("old_spki").map_err(db)? == csr.spki()
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            row.try_get::<Vec<u8>, _>("challenge_hash")
                .map_err(db)?
                .as_slice(),
            Sha256::digest(secret.as_bytes()).as_slice(),
        ))
    {
        return Err(Error::Unauthorized);
    }
    audit.identify_service("service:scep-renewal");
    audit.target(&row.try_get::<String, _>("device").map_err(db)?);
    audit.registration(rss_mdm_registration_service::enrollment::store::uuid(&row, "registration")?);
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$3,csr_digest=$4,spki=$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(csr.attempt().to_string()).bind(transaction).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).execute(&mut *c).await.map_err(db)?;
    Ok::<_, Error>(Some(false))

            })).await?;
            let Some(replayed) = replayed else { return Ok(false); };
            let fingerprint = rss_mdm_registration_service::enrollment::digest(&(csr.attempt(), csr.digest(), csr.spki(), transaction));
            let fact = rss_mdm_audit_integration::Fact::business(audit, &format!("apple-renewal:{}:challenge", csr.attempt()),
                fingerprint.as_bytes(), 200, "success", Some(csr.enrollment())).map_err(Error::from)?;
            app.audit_store.append(tx, &fact, replayed).await.map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(true)
        }),
    ).await;
    crate::operations::settle(outcome, audit)
}

pub async fn notify(
    app: &HttpState,
    leaf: &certificate::CheckedLeaf,
    csr: &certificate::Csr,
    transaction: &str,
    audit: &RequestAudit,
) -> Result<bool, Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (app, leaf, csr, transaction, audit),
            |(app, leaf, csr, transaction, audit), tx| {
                Box::pin(async move {
                    let replayed = tx
                        .with_connection_context(
                            &mut (*app, *leaf, *csr, *transaction, *audit),
                            |(app, leaf, csr, transaction, audit), c| {
                                Box::pin(async move {
                                    let app = *app;
                                    let leaf = *leaf;
                                    let csr = *csr;
                                    let transaction = *transaction;
                                    let audit = *audit;
                                    let tenant = app.identity.tenant().to_string();
                                    let Some(row) = current(c, &tenant, leaf.attempt()).await?
                                    else {
                                        return Ok::<_, Error>(None);
                                    };
                                    verify(app, &row, leaf)?;
                                    if row.try_get::<String, _>("transaction_id").map_err(db)?
                                        != transaction
                                        || row.try_get::<Vec<u8>, _>("csr_digest").map_err(db)?
                                            != csr.digest()
                                    {
                                        return Err(Error::Unauthorized);
                                    }
                                    audit.identify_service("service:scep-renewal");
                                    audit.target(&row.try_get::<String, _>("device").map_err(db)?);
                                    audit.registration(
                                        rss_mdm_registration_service::enrollment::store::uuid(
                                            &row,
                                            "registration",
                                        )?,
                                    );
                                    let replayed = row
                                        .try_get::<Option<Vec<u8>>, _>("fingerprint")
                                        .map_err(db)?
                                        .is_some();
                                    enrollment::persist_leaf(c, &tenant, leaf).await?;
                                    Ok::<_, Error>(Some(replayed))
                                })
                            },
                        )
                        .await?;
                    let Some(replayed) = replayed else {
                        return Ok(false);
                    };
                    let fingerprint = rss_mdm_registration_service::enrollment::digest(&(
                        leaf.attempt(),
                        leaf.fingerprint(),
                        csr.digest(),
                        transaction,
                    ));
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-renewal:{}:notify", leaf.attempt()),
                        fingerprint.as_bytes(),
                        200,
                        "success",
                        Some(leaf.attempt()),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    audit.mark_commit_started();
                    Ok(true)
                })
            },
        )
        .await;
    crate::operations::settle(outcome, audit)
}

fn verify(app: &HttpState, row: &PgRow, leaf: &certificate::CheckedLeaf) -> Result<(), Error> {
    if row.try_get::<String, _>("state").map_err(db)? != "consumed"
        || rss_mdm_registration_service::enrollment::store::uuid(row, "enrollment")?
            != leaf.enrollment()
        || row.try_get::<Vec<u8>, _>("configuration").map_err(db)? != app.apple()?.configuration
        || row.try_get::<Vec<u8>, _>("spki").map_err(db)? != leaf.spki()
        || row
            .try_get::<Option<Vec<u8>>, _>("fingerprint")
            .map_err(db)?
            .is_some_and(|fp| fp != leaf.fingerprint())
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub async fn activate(
    app: &HttpState,
    leaf: &certificate::CheckedLeaf,
    udid: &str,
) -> Result<(), Error> {
    let audit = RequestAudit::new(app.identity.tenant().to_string(), "apple_renewal");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control, (app, leaf, udid, &audit),
        |(app, leaf, udid, audit), tx| Box::pin(async move {
            let changed = tx.with_connection_context(&mut (*app, *leaf, *udid, *audit),
                |(app, leaf, udid, audit), c| Box::pin(async move {
                    let app = *app; let leaf = *leaf; let udid = *udid; let audit = *audit;
    let tenant = app.identity.tenant().to_string();
    // Already-bound certificates continue through the normal admission checks.
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND renewal_of IS NOT NULL AND state<>'bound')")
        .bind(&tenant).bind(leaf.attempt().to_string()).fetch_one(&mut *c).await.map_err(db)?;
    if !pending {
        return Ok::<_, Error>(false);
    }
    let row = current(c, &tenant, leaf.attempt())
        .await?
        .ok_or(Error::Unauthorized)?;
    verify(app, &row, leaf)?;
    if row.try_get::<String, _>("udid").map_err(db)? != udid {
        return Err(Error::Unauthorized);
    }
    let registration: String = row.try_get("registration").map_err(db)?;
    let old: String = row.try_get("renewal_of").map_err(db)?;
    // New credential ID fences principals authenticated before this transaction.
    let locator = leaf
        .fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    crate::device::store::replace_mdm_credential_in(c, &tenant, &registration, &locator)
        .await?;
    enrollment::persist_leaf(c, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state=CASE WHEN id=$2::uuid THEN 'bound' ELSE 'superseded' END WHERE tenant_id=$1::uuid AND id IN ($2::uuid,$3::uuid)").bind(&tenant).bind(leaf.attempt().to_string()).bind(old).execute(&mut *c).await.map_err(db)?;
    audit.identify_device(Uuid::parse_str(&registration).map_err(|_| Error::Unauthorized)?);
    audit.target(&row.try_get::<String, _>("device").map_err(db)?);
    audit.registration(Uuid::parse_str(&registration).map_err(|_| Error::Unauthorized)?);
    Ok::<_, Error>(true)

                })).await?;
            if changed {
                let fingerprint = rss_mdm_registration_service::enrollment::digest(&(leaf.attempt(), leaf.fingerprint(), udid));
                let fact = rss_mdm_audit_integration::Fact::business(audit, &format!("apple-renewal:{}:activate", leaf.attempt()),
                    fingerprint.as_bytes(), 200, "success", Some(leaf.enrollment())).map_err(Error::from)?;
                app.audit_store.append(tx, &fact, false).await.map_err(Error::from)?;
                audit.mark_commit_started();
            }
            Ok(())
        }),
    ).await;
    let result = crate::operations::settle(outcome, &audit);
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}

pub async fn management(
    app: &HttpState,
    p: &DevicePrincipal,
    d: &plist::Dictionary,
    bytes: &[u8],
    audit: &RequestAudit,
) -> Result<Option<Vec<u8>>, Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app.audit_store.write(app.identity.tenant(), &control, (app, p, d, bytes, audit),
        |(app, p, d, bytes, audit), tx| Box::pin(async move {
            let result = tx.with_connection_context(&mut (*p, *d, *bytes, app.protection.clone()), |(p, d, bytes, protection), c| Box::pin(async move {
                let p = *p; let d = *d; let bytes = *bytes;
    let message = protocol::management(d)?;
    let tenant = p.tenant().to_string();
    crate::device::store::lock_channel(c, &tenant, p.device(), p.channel()).await?;
    crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::MdmApple).await?;
    let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='active' AND udid=$3)").bind(&tenant).bind(p.registration()).bind(message.udid).fetch_one(&mut *c).await.map_err(db)?;
    if !live {
        return Err(Error::Unauthorized);
    }
    if let Some(id) = message.command {
        match attempt::lock(c, protection, p, id, attempt::Owner::Certificate, bytes).await? {
            None => return Ok(None),
            Some(attempt::Reception::Replay) => {}
            Some(attempt::Reception::Ready(a)) => a.settle(c, message.status).await?,
        }
    }
    let next=sqlx::query("SELECT a.id::text,a.request FROM mdm_apple.attempts a JOIN mdm_apple.scep_attempts s ON (s.tenant_id,s.id)=(a.tenant_id,a.certificate) WHERE a.tenant_id=$1::uuid AND a.registration=$2::uuid AND a.generation=$3 AND a.phase='renew' AND a.state IN ('pending','sent','not_now') AND s.state IN ('prepared','consumed') AND a.next_attempt<=clock_timestamp() AND a.deadline>clock_timestamp() ORDER BY a.id LIMIT 1 FOR UPDATE OF a")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let result = if let Some(row) = next {
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(row.try_get::<String,_>("id").map_err(db)?).execute(&mut *c).await.map_err(db)?;
        crate::notify(c, "apple").await.map_err(db)?;
        let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
        let id = Uuid::parse_str(&row.try_get::<String,_>("id").map_err(db)?).map_err(|_| Error::Malformed)?;
        Some(crate::protection::open(protection,&tenant,p.registration(),p.generation(),id,crate::protection::Part::Request,&sealed)?.expose().to_vec())
    } else {
        message.command.map(|_| Vec::new())
    };
    if result.is_none() {
        return Ok(None);
    }
    Ok::<_, Error>(result)
            })).await?;
            if result.is_some() {
                app.audit_store.append_request(tx, audit, 200, "success").await.map_err(Error::from)?;
                audit.mark_commit_started();
            }
            Ok(result)
        }),
    ).await;
    crate::operations::settle(outcome, audit)
}

use rss_mdm_audit_integration::RequestAudit;

/// The next future maintenance boundary is a scheduling hint, never certificate authority.
pub async fn next_maintenance(
    access: &Database,
    tenant: &str,
) -> Result<Option<std::time::Duration>, Error> {
    let mut tx = access.begin_read(tenant).await?;
    let millis: Option<i64> = sqlx::query_scalar("SELECT ceil(extract(epoch FROM min(due)-clock_timestamp())*1000)::bigint FROM (SELECT next_push AS due FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active' UNION ALL SELECT push_lease_until FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active' UNION ALL SELECT to_timestamp(not_after) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state='bound' UNION ALL SELECT to_timestamp(not_after-least((not_after-not_before)/3,604800)) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state='bound' UNION ALL SELECT expires_at FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state IN ('prepared','consumed') UNION ALL SELECT next_attempt FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND state IN ('pending','sent','not_now') UNION ALL SELECT deadline FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND state IN ('pending','sent','not_now')) times WHERE due>clock_timestamp()")
        .bind(tenant).fetch_one(&mut *tx).await.map_err(db)?;
    tx.rollback().await.map_err(db)?;
    Ok(millis.map(|ms| std::time::Duration::from_millis(ms.max(1) as u64)))
}
