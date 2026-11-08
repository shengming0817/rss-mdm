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
    let health = sqlx::query("WITH due AS (SELECT a.device, s.not_after, CASE WHEN s.not_after <= $2 THEN 2 WHEN s.not_after - LEAST((s.not_after - s.not_before) / 3, 604800) <= $2 THEN 1 ELSE 0 END AS level FROM mdm_apple.devices AS a INNER JOIN mdm_apple.scep_attempts AS s ON (s.tenant_id, s.device) = (a.tenant_id, a.device) WHERE a.tenant_id = CAST($1 AS uuid) AND a.state = 'active' AND s.state = 'bound' AND a.identity_health <> CASE WHEN s.not_after <= $2 THEN 2 WHEN s.not_after - LEAST((s.not_after - s.not_before) / 3, 604800) <= $2 THEN 1 ELSE 0 END ORDER BY s.not_after, a.device LIMIT 32) UPDATE mdm_apple.devices AS a SET identity_health = due.level FROM due WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = due.device RETURNING CAST(a.device AS text), due.not_after, due.level")
        .bind(tenant).bind(now).fetch_all(&mut *tx).await.map_err(db)?;
    let mut candidates = Vec::new();
    let mut offset = 0i64;
    while candidates.len() < 32 {
        let rows=sqlx::query("SELECT s.id, s.device FROM mdm_apple.scep_attempts AS s INNER JOIN mdm_apple.devices AS a ON (a.tenant_id, a.device) = (s.tenant_id, s.device) WHERE s.tenant_id = CAST($1 AS uuid) AND s.state = 'bound' AND a.state = 'active' AND s.configuration = $3 AND s.not_after > $2 AND s.not_after - LEAST((s.not_after - s.not_before) / 3, 604800) <= $2 AND NOT EXISTS (SELECT 1 FROM mdm_apple.scep_attempts AS pending WHERE pending.tenant_id = s.tenant_id AND pending.renewal_of = s.id AND pending.state IN ('prepared', 'consumed') AND pending.expires_at > clock_timestamp()) ORDER BY s.not_after, s.id LIMIT 64 OFFSET $4").bind(tenant).bind(now).bind(apple.configuration.as_slice()).bind(offset).fetch_all(&mut *tx).await.map_err(db)?;
        let ids = rows
            .iter()
            .map(|r| r.try_get::<String, _>("device"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        let active = crate::device::read::active_sources_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            tenant,
            &ids,
            rss_mdm_inventory::ReportSource::MdmApple,
        )
        .await?;
        for row in &rows {
            let device: String = row.try_get("device").map_err(db)?;
            if active.contains(&device) {
                candidates.push(Candidate {
                    id: row.try_get("id").map_err(db)?,
                    device: device.to_string(),
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
            serde_json::json!({"event":"apple_identity_health","device":row.try_get::<String,_>("device").map_err(db)?,"expires_at":row.try_get::<i64,_>("not_after").map_err(db)?,"state":match level {0=>"valid",1=>"renewal_due",_=>"expired"}})
        );
    }
    for candidate in candidates {
        prepare(apple, audit_store, tenant, now, candidate).await?;
    }
    Ok(progress)
}
struct Candidate {
    id: Uuid,
    device: String,
}
async fn prepare(
    apple: &Apple,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
    now: i64,
    candidate: Candidate,
) -> Result<(), Error> {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        tenant.into(),
        "apple_renewal",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("service:certificate-renewal");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = store
        .write(
            rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),
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

                    let fact = rss_mdm_audit_integration::Fact::observation(
                        audit,
                        &format!("apple-renewal:{}:prepare", prepared.attempt),
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
                    (if replayed {
                        Ok(())
                    } else {
                        store.append(tx, &fact).await
                    })
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
    device: String,
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
    let device = &candidate.device;
    if !crate::device::read::lock_active_source_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        &candidate.device,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?
    {
        return Ok(None);
    }
    let old=sqlx::query("SELECT CAST(s.id AS text), CAST(s.enrollment AS text), CAST(s.device AS text), s.not_before, s.not_after FROM mdm_apple.scep_attempts AS s INNER JOIN mdm_apple.devices AS a ON (a.tenant_id, a.device) = (s.tenant_id, s.device) WHERE s.tenant_id = CAST($1 AS uuid) AND s.id = CAST($2 AS uuid) AND s.device = CAST($4 AS text) AND s.state = 'bound' AND a.state = 'active' AND s.configuration = $3 FOR UPDATE OF s, a").bind(tenant).bind(candidate.id).bind(apple.configuration.as_slice()).bind(&candidate.device).fetch_optional(&mut *c).await.map_err(db)?;
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
                device: old.try_get("device").map_err(db)?,

                deadline: pending.try_get("deadline").map_err(db)?,
                renewal_of: old_id,
            };
            audit.target_device(&device);
            audit.target_device(&prepared.device);
            return Ok(Some((prepared, true)));
        }
        let expired: String = pending.try_get("id").map_err(db)?;
        sqlx::query("UPDATE mdm_apple.scep_attempts SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(&expired).execute(&mut *c).await.map_err(db)?;
        sqlx::query("UPDATE mdm_apple.attempts SET state='superseded' WHERE tenant_id=$1::uuid AND certificate=$2::uuid").bind(tenant).bind(expired).execute(&mut *c).await.map_err(db)?;
    }
    let id = Uuid::new_v4();
    let enrollment = rss_mdm_registration_service::enrollment::store::uuid(&old, "enrollment")?;
    let secret = zeroize::Zeroizing::new(rss_mdm_registration_service::enrollment::random());
    // The assigned account is an immutable enrollment attribute, independent of
    // current browser sessions and control-plane binding revisions.
    let (authority, assigned): (String, Option<String>) = sqlx::query_as(
        "SELECT q.authority_kind,(SELECT f.account FROM mdm_apple.account_flows f WHERE f.tenant_id=q.tenant_id AND f.enrollment=q.id AND f.account IS NOT NULL ORDER BY f.authorization_version,f.id LIMIT 1) FROM mdm_access.requests q WHERE q.tenant_id=$1::uuid AND q.id=$2 AND q.source='mdm.apple'",
    )
    .bind(tenant)
    .bind(enrollment)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let ade_removable: Option<bool> = if authority == "apple_ade" {
        sqlx::query_scalar("SELECT (machine->>'removable')::boolean FROM mdm_apple.ade_enrollments WHERE tenant_id=$1::uuid AND enrollment=$2 AND NOT revoked").bind(tenant).bind(enrollment).fetch_optional(&mut *c).await.map_err(db)?
    } else {
        None
    };
    let mode = match (authority.as_str(), assigned.as_deref()) {
        ("apple_account", Some(managed_account)) => {
            profile::EnrollmentMode::Account { managed_account }
        }
        ("password", None) => profile::EnrollmentMode::Profile,
        ("apple_ade", None) => profile::EnrollmentMode::Ade {
            removable: ade_removable.ok_or(Error::Unavailable(crate::Failure::AppleInvariant))?,
        },
        _ => return Err(Error::Unavailable(crate::Failure::AppleInvariant)),
    };
    let (issuer, scep_url, scep_provisioner) = apple.active_scep(c, tenant).await?;
    let signed = apple.signer.sign(
        &profile::enrollment(
            &profile::EnrollmentProfile {
                mode,
                access_rights: apple.access_rights() as u16,
                scep_url: &scep_url,
                scep_provisioner: &scep_provisioner,
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
    let device: String = old.try_get("device").map_err(db)?;
    let deadline = after.min(now + 3600);
    sqlx::query("INSERT INTO mdm_apple.scep_attempts (tenant_id, id, enrollment, authorization_version, configuration, state, issuer, expires_at, device, renewal_of, challenge_hash, access_rights, scep_url, scep_provisioner) SELECT CAST($1 AS uuid), CAST($2 AS uuid), CAST($3 AS uuid), COALESCE(max(authorization_version), 0) + 1, $4, 'prepared', $5, to_timestamp($6), CAST($7 AS text), CAST($8 AS uuid), $9, $10, $11, $12 FROM mdm_apple.scep_attempts WHERE tenant_id = CAST($1 AS uuid) AND enrollment = CAST($3 AS uuid)")
        .bind(tenant).bind(id.to_string()).bind(enrollment.to_string()).bind(apple.configuration.as_slice()).bind(issuer).bind(deadline as f64).bind(&device).bind(&old_id).bind(Sha256::digest(secret.as_bytes()).as_slice()).bind(apple.access_rights()).bind(scep_url).bind(scep_provisioner).execute(&mut *c).await.map_err(db)?;
    let request = crate::protection::seal(
        &apple.protection,
        tenant,
        &device,
        id,
        crate::protection::Part::Request,
        &request,
    )?;
    sqlx::query("INSERT INTO mdm_apple.attempts (tenant_id, id, device, certificate, phase, request, state, deadline) VALUES (CAST($1 AS uuid), CAST($2 AS uuid), CAST($3 AS text), CAST($2 AS uuid), 'renew', $4, 'pending', to_timestamp($5))")
        .bind(tenant).bind(id.to_string()).bind(&device).bind(request).bind(deadline as f64).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.channels SET next_push = clock_timestamp() WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text)").bind(tenant).bind(&device).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    audit.target_device(&device);
    Ok(Some((
        PreparedRenewal {
            attempt: id,
            enrollment,
            device: device.to_string(),

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
    let device=sqlx::query_scalar::<_,String>("SELECT device FROM mdm_apple.scep_attempts WHERE tenant_id = CAST($1 AS uuid) AND id = CAST($2 AS uuid) AND renewal_of IS NOT NULL").bind(tenant).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
    let Some(device) = device else {
        return Ok(None);
    };
    if !crate::device::read::lock_active_source_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        tx,
        tenant,
        &device,
        rss_mdm_inventory::ReportSource::MdmApple,
    )
    .await?
    {
        return Err(Error::Unauthorized);
    }
    let row=sqlx::query("SELECT s.state, s.issuer, s.scep_provisioner, CAST(s.enrollment AS text), CAST(s.device AS text), CAST(s.renewal_of AS text), s.configuration, s.challenge_hash, s.transaction_id, s.csr_digest, s.spki, s.fingerprint, a.udid, old.spki AS old_spki FROM mdm_apple.scep_attempts AS s INNER JOIN mdm_apple.scep_attempts AS old ON (old.tenant_id, old.id) = (s.tenant_id, s.renewal_of) INNER JOIN mdm_apple.devices AS a ON (a.tenant_id, a.device) = (s.tenant_id, s.device) WHERE s.tenant_id = CAST($1 AS uuid) AND s.id = CAST($2 AS uuid) AND s.device=$3 AND s.state IN ('prepared', 'consumed') AND s.expires_at > clock_timestamp() AND old.state = 'bound' AND old.not_after > EXTRACT(EPOCH FROM clock_timestamp()) AND a.state = 'active' AND EXISTS (SELECT 1 FROM mdm_apple.attempts AS delivery WHERE (delivery.tenant_id, delivery.certificate) = (s.tenant_id, s.id) AND delivery.phase = 'renew' AND delivery.state IN ('sent', 'not_now', 'acknowledged') AND delivery.deadline > clock_timestamp()) FOR UPDATE OF s, old, a").bind(tenant).bind(id).bind(&device).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    Ok(Some(row))
}
pub async fn challenge(
    app: &HttpState,
    csr: &certificate::Csr,
    secret: &str,
    transaction: &str,
    provisioner: &str,
    issuer: &str,
    audit: &RequestAudit,
) -> Result<bool, Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app.audit_store.write(app.identity.tenant(),
            &budget.source_control(), (app, csr, secret, transaction, provisioner, issuer, audit),
        |(app, csr, secret, transaction, provisioner, issuer, audit), tx| Box::pin(async move {
            let replayed = tx.with_connection_context(&mut (*app, *csr, *secret, *transaction, *provisioner, *issuer, *audit), |(app, csr, secret, transaction, provisioner, issuer, audit), c| Box::pin(async move {
                let app = *app; let csr = *csr; let secret = *secret; let transaction = *transaction; let provisioner=*provisioner; let issuer=*issuer; let audit = *audit;
    let tenant = app.identity.tenant().to_string();
    let Some(row) = current(c, &tenant, csr.attempt()).await? else {
        return Ok::<_, Error>(None);
    };
    let frozen=row.try_get::<Vec<u8>,_>("issuer").map_err(db)?.iter().map(|b|format!("{b:02x}")).collect::<String>();
    if frozen!=issuer || row.try_get::<Option<String>,_>("scep_provisioner").map_err(db)?.as_deref()!=Some(provisioner)
        || row.try_get::<String, _>("state").map_err(db)? != "prepared"
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
    audit.target_device(&row.try_get::<String, _>("device").map_err(db)?);

    sqlx::query("UPDATE mdm_apple.scep_attempts SET state='consumed',transaction_id=$3,csr_digest=$4,spki=$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(&tenant).bind(csr.attempt().to_string()).bind(transaction).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).execute(&mut *c).await.map_err(db)?;
    Ok::<_, Error>(Some(false))

            })).await?;
            let Some(replayed) = replayed else { return Ok(false); };

            let fact = rss_mdm_audit_integration::Fact::observation(audit, &format!("apple-renewal:{}:challenge", csr.attempt()), 200, "success", Some(csr.enrollment())).map_err(Error::from)?;
            (if replayed { Ok(()) } else { app.audit_store.append(tx, &fact).await }).map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(true)
        }),
    ).await;
    crate::operations::settle(outcome, audit)
}

pub async fn notify(
    app: &HttpState,
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
    csr: &certificate::Csr,
    transaction: &str,
    audit: &RequestAudit,
) -> Result<bool, Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.source_control(),
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
                                    audit.target_device(
                                        &row.try_get::<String, _>("device").map_err(db)?,
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

                    let fact = rss_mdm_audit_integration::Fact::observation(
                        audit,
                        &format!("apple-renewal:{}:notify", leaf.attempt()),
                        200,
                        "success",
                        Some(leaf.attempt()),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        app.audit_store.append(tx, &fact).await
                    })
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

fn verify(
    app: &HttpState,
    row: &PgRow,
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
) -> Result<(), Error> {
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
    leaf: &rss_mdm_device_trust::apple::CheckedLeaf,
    udid: &str,
) -> Result<(), Error> {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        app.identity.tenant().to_string(),
        "apple_renewal",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app.audit_store.write(app.identity.tenant(),
            &budget.source_control(), (app, leaf, udid, &audit),
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
    let device: String = row.try_get("device").map_err(db)?;
    let old: String = row.try_get("renewal_of").map_err(db)?;
    let predecessor: Uuid = sqlx::query_scalar("SELECT k.id FROM mdm_apple.scep_attempts s JOIN mdm_access.credentials k ON(k.tenant_id,k.device)=(s.tenant_id,s.device) AND k.locator=encode(s.fingerprint,'hex') WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND k.purpose='primary' AND k.state='active'")
        .bind(&tenant).bind(&old).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    // New credential ID fences principals authenticated before this transaction.
    let locator = leaf
        .fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    crate::device::store::replace_mdm_credential_in(rss_mdm_install_support::StorageProfile::Mdm, c, &tenant, &device, predecessor, &locator)
        .await?;
    enrollment::persist_leaf(c, &tenant, leaf).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET state=CASE WHEN id=$2::uuid THEN 'bound' ELSE 'superseded' END WHERE tenant_id=$1::uuid AND id IN ($2::uuid,$3::uuid)").bind(&tenant).bind(leaf.attempt().to_string()).bind(old).execute(&mut *c).await.map_err(db)?;
    audit.identify_device(&device);
    audit.target_device(&row.try_get::<String, _>("device").map_err(db)?);
    Ok::<_, Error>(true)

                })).await?;
            if changed {

                let fact = rss_mdm_audit_integration::Fact::observation(audit, &format!("apple-renewal:{}:activate", leaf.attempt()), 200, "success", Some(leaf.enrollment())).map_err(Error::from)?;
                app.audit_store.append(tx, &fact).await.map_err(Error::from)?;
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
    let outcome = app.audit_store.write(app.identity.tenant(),
            &budget.source_control(), (app, p, d, bytes, audit),
        |(app, p, d, bytes, audit), tx| Box::pin(async move {
            let result = tx.with_connection_context(&mut (*p, *d, *bytes, app.protection.clone()), |(p, d, bytes, protection), c| Box::pin(async move {
                let p = *p; let d = *d; let bytes = *bytes;
    let message = protocol::management(d)?;
    let tenant = p.tenant().to_string();
    crate::device::store::lock_channel(rss_mdm_install_support::StorageProfile::Mdm, c, &tenant, p.device(), p.require_channel()?).await?;
    crate::device::store::revalidate_source(rss_mdm_install_support::StorageProfile::Mdm, c,p,rss_mdm_inventory::ReportSource::MdmApple).await?;
    let live:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_apple.devices WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) AND state = 'active' AND udid = $3)").bind(&tenant).bind(p.device()).bind(message.udid).fetch_one(&mut *c).await.map_err(db)?;
    if !live {
        return Err(Error::Unauthorized);
    }
    if let Some(id) = message.command {
        match attempt::lock(c, protection, p, id, attempt::Owner::Certificate, bytes).await? {
            None => return Ok(None),
            Some(attempt::Reception::Replay) => {}
            Some(attempt::Reception::Ready(a)) => a.settle(c, message.status, true).await?,
        }
    }
    let next=sqlx::query("SELECT CAST(a.id AS text), a.request FROM mdm_apple.attempts AS a INNER JOIN mdm_apple.scep_attempts AS s ON (s.tenant_id, s.id) = (a.tenant_id, a.certificate) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = CAST($2 AS text) AND a.phase = 'renew' AND a.state IN ('pending', 'sent', 'not_now') AND s.state IN ('prepared', 'consumed') AND a.next_attempt <= clock_timestamp() AND a.deadline > clock_timestamp() ORDER BY a.id LIMIT 1 FOR UPDATE OF a")
        .bind(&tenant).bind(p.device().to_string()).fetch_optional(&mut *c).await.map_err(db)?;
    let result = if let Some(row) = next {
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(row.try_get::<String,_>("id").map_err(db)?).execute(&mut *c).await.map_err(db)?;
        crate::notify(c, "apple").await.map_err(db)?;
        let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
        let id = Uuid::parse_str(&row.try_get::<String,_>("id").map_err(db)?).map_err(|_| Error::Malformed)?;
        Some(crate::protection::open(protection,&tenant,p.device(),id,crate::protection::Part::Request,&sealed)?.expose().to_vec())
    } else {
        message.command.map(|_| Vec::new())
    };
    if result.is_none() {
        return Ok(None);
    }
    Ok::<_, Error>(result)
            })).await?;
            if result.is_some() {
                audit.require_final_request();
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
    let millis: Option<i64> = sqlx::query_scalar("SELECT ceil(extract(epoch FROM min(due)-clock_timestamp())*1000)::bigint FROM (SELECT next_push AS due FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND state='active' UNION ALL SELECT push_lease_until FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND state='active' UNION ALL SELECT to_timestamp(not_after) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state='bound' UNION ALL SELECT to_timestamp(not_after-least((not_after-not_before)/3,604800)) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state='bound' UNION ALL SELECT expires_at FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state IN ('prepared','consumed') UNION ALL SELECT next_attempt FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND state IN ('pending','sent','not_now') UNION ALL SELECT deadline FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND state IN ('pending','sent','not_now')) times WHERE due>clock_timestamp()")
        .bind(tenant).fetch_one(&mut *tx).await.map_err(db)?;
    tx.rollback().await.map_err(db)?;
    Ok(millis.map(|ms| std::time::Duration::from_millis(ms.max(1) as u64)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn renewal_window_is_bounded_by_lifetime_and_expiry() {
        for (before, after, opens) in [(0, 90, 60), (0, 90 * 86400, 83 * 86400)] {
            assert!(!super::due(before, after, opens - 1));
            assert!(super::due(before, after, opens));
            assert!(super::due(before, after, after - 1));
            assert!(!super::due(before, after, after));
        }
    }
}
