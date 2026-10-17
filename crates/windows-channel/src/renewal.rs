//! A pending certificate is an issuance fact. Registration remains the credential authority.
use crate::{
    Error, Failure, HttpState, RequestAudit, certificate, database::db, device::DevicePrincipal,
};
use rss_mdm_windows_mdm::{
    CodecLimits,
    provisioning::{self, EnrollmentType},
};
use sqlx::Row;
use uuid::Uuid;

fn enrollment(value: &str) -> Result<EnrollmentType, Error> {
    match value {
        "Full" => Ok(EnrollmentType::Full),
        "Device" => Ok(EnrollmentType::Device),
        _ => Err(Error::Conflict),
    }
}
fn provision(
    app: &HttpState,
    certificate: &[u8],
    kind: &str,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<Vec<u8>, Error> {
    let thumbprint = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, certificate)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    provisioning::renewal(
        certificate,
        &thumbprint,
        &app.windows()?.provider(purpose),
        enrollment(kind)?,
        &CodecLimits::default(),
    )
    .map_err(|_| Error::Malformed)
}

pub(crate) async fn issue(
    app: &HttpState,
    peer: &rss_mdm_certificate::HandshakePeer,
    cms: &[u8],
    audit: &RequestAudit,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<Vec<u8>, Error> {
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    let proof = app.windows()?.ca.renewal(
        cms,
        peer.chain().first().ok_or(Error::Unauthorized)?.as_ref(),
        now,
    )?;
    let principal = app
        .devices
        .management_principal(
            &crate::device::ChannelMount::new(
                app.identity.tenant(),
                rss_mdm_inventory::ReportSource::MdmWindows,
                purpose,
            )
            .credential(proof.fingerprint())?,
        )
        .await?;
    if let Some((parent, _)) = principal.parent() {
        crate::linked::current_parent(app, parent).await?;
    }
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    let digest = app
        .protection
        .mac(
            proof.csr(),
            &crate::protection::native_aad(
                principal.tenant(),
                "windows.renewal.csr",
                &(
                    principal.registration(),
                    principal.generation(),
                    principal.credential(),
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    let pending = prepare(app, &principal, &proof, &digest).await?;
    let profile = certificate::IssuanceProfile::decode(&pending.profile)?;
    let certificate = crate::issuance::sign_profile(
        app,
        &principal.tenant().to_string(),
        pending.id,
        proof.csr(),
        &profile,
        now,
    )
    .await?;
    let leaf = app.windows()?.ca.validate_issued(
        &profile,
        &certificate::Csr::verify(proof.csr())?,
        &[certificate.clone().into()],
        now,
    )?;
    let issued = PendingCertificate {
        id: pending.id,
        certificate,
        fingerprint: leaf.fingerprint(),
    };
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            principal.tenant(),
            &control,
            (app, &principal, &proof, &digest, audit, &issued),
            |(app, p, proof, digest, audit, issued), tx| {
                Box::pin(async move {
                    let (id, certificate, kind, replayed) = tx
                        .with_connection_context(
                            &mut (*app, *p, *proof, *digest, *issued),
                            |(app, p, proof, digest, issued), c| {
                                Box::pin(issue_on(c, app, p, proof, digest.as_slice(), issued))
                            },
                        )
                        .await?;
                    if !replayed {
                        let fact = rss_mdm_audit_integration::Fact::business(
                            audit,
                            &format!("windows-renewal:{id}:issued"),
                            digest.as_slice(),
                            200,
                            "success",
                            None,
                        )
                        .map_err(Error::from)?;
                        app.audit_store
                            .append(tx, &fact, false)
                            .await
                            .map_err(Error::from)?;
                    }
                    app.audit_store
                        .append_request(tx, audit, 200, if replayed { "replay" } else { "success" })
                        .await
                        .map_err(Error::from)?;
                    let response = provision(app, &certificate, &kind, purpose)?;
                    audit.mark_commit_started();
                    Ok(response)
                })
            },
        )
        .await;
    crate::operations::settle(outcome, audit)
}
async fn issue_on(
    c: &mut sqlx::PgConnection,
    app: &HttpState,
    p: &DevicePrincipal,
    proof: &rss_mdm_device_trust::windows::RenewalProof,
    digest: &[u8],
    issued: &PendingCertificate,
) -> Result<(Uuid, Vec<u8>, String, bool), Error> {
    let tenant = p.tenant().to_string();
    crate::device::store::lock_channel(c, &tenant, p.device(), p.channel()).await?;
    crate::device::store::revalidate_management(c, p).await?;
    let windows = app.windows()?;
    if let Some(old)=sqlx::query("SELECT n.id,n.proof_digest,n.certificate,q.windows_profile AS enrollment_type,n.configuration FROM mdm_windows.renewals n JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(n.tenant_id,n.registration) JOIN mdm_access.requests q ON (q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE n.tenant_id=$1::uuid AND n.registration=$2 AND n.generation=$3 AND n.previous_credential=$4 FOR UPDATE OF n")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).fetch_optional(&mut *c).await.map_err(db)? {
        if old.try_get::<Vec<u8>,_>("proof_digest").map_err(db)?!=digest || old.try_get::<String,_>("configuration").map_err(db)?!=windows.configuration {return Err(Error::Conflict)}
        return Ok((old.try_get("id").map_err(db)?,old.try_get("certificate").map_err(db)?,old.try_get("enrollment_type").map_err(db)?,true));
    }
    let original=sqlx::query("SELECT q.windows_profile AS enrollment_type,i.configuration FROM mdm_access.enrollment_intents i JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid AND i.registration=$2")
        .bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
    if original.try_get::<String, _>("configuration").map_err(db)? != windows.configuration {
        return Err(Error::Conflict);
    }
    let kind: String = original.try_get("enrollment_type").map_err(db)?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    if now >= proof.expires() {
        return Err(Error::Unauthorized);
    }
    let certificate = &issued.certificate;
    let id = issued.id;
    sqlx::query("INSERT INTO mdm_windows.renewals(tenant_id,id,registration,generation,previous_credential,proof_digest,certificate,fingerprint,configuration) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(digest).bind(certificate).bind(issued.fingerprint.as_slice()).bind(&windows.configuration).execute(&mut *c).await.map_err(db)?;
    let profile: Vec<u8> = sqlx::query_scalar(
        "SELECT profile FROM mdm_windows.renewal_intents WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(&tenant)
    .bind(id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let issuer = certificate::IssuanceProfile::decode(&profile)?
        .issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    rss_mdm_pki_service::certificates::record_in(
        c,
        &tenant,
        "windows",
        p.registration(),
        &issuer,
        certificate,
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    Ok((id, certificate.clone(), kind, false))
}

struct Pending {
    id: Uuid,
    profile: Vec<u8>,
}
struct PendingCertificate {
    id: Uuid,
    certificate: Vec<u8>,
    fingerprint: [u8; 32],
}
async fn prepare(
    app: &HttpState,
    p: &DevicePrincipal,
    proof: &rss_mdm_device_trust::windows::RenewalProof,
    digest: &[u8],
) -> Result<Pending, Error> {
    let tenant = p.tenant().to_string();
    let mut tx = app.access.begin(&tenant).await?;
    crate::device::store::lock_channel(&mut tx, &tenant, p.device(), p.channel()).await?;
    crate::device::store::revalidate_management(&mut tx, p).await?;
    let windows = app.windows()?;
    if let Some(row) = sqlx::query("SELECT id,proof_digest,profile,configuration FROM mdm_windows.renewal_intents WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND previous_credential=$4")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential())
        .fetch_optional(&mut *tx).await.map_err(db)? {
        if row.try_get::<Vec<u8>,_>("proof_digest").map_err(db)? != digest
            || row.try_get::<String,_>("configuration").map_err(db)? != windows.configuration {
            return Err(Error::Conflict);
        }
        return Ok(Pending { id: row.try_get("id").map_err(db)?, profile: row.try_get("profile").map_err(db)? });
    }
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    if now >= proof.expires() {
        return Err(Error::Unauthorized);
    }
    let original: String = sqlx::query_scalar("SELECT configuration FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(&tenant).bind(p.registration()).fetch_one(&mut *tx).await.map_err(db)?;
    if original != windows.configuration {
        return Err(Error::Conflict);
    }
    let profile = windows
        .ca
        .profile(
            &certificate::Csr::verify(proof.csr())?,
            p.registration(),
            now,
        )?
        .encode()?;
    let id = Uuid::new_v4();
    crate::issuance::authorize_profile(
        &mut tx,
        windows,
        &tenant,
        id,
        proof.csr(),
        &certificate::IssuanceProfile::decode(&profile)?,
    )
    .await?;
    sqlx::query("INSERT INTO mdm_windows.renewal_intents(tenant_id,id,registration,generation,previous_credential,proof_digest,profile,configuration) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(p.credential())
        .bind(digest).bind(&profile).bind(&windows.configuration).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(|_| Error::CommitUnknown)?;
    Ok(Pending { id, profile })
}

pub(crate) async fn activate(
    app: &HttpState,
    leaf: &rss_mdm_device_trust::windows::CheckedLeaf,
    device: &str,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<(), Error> {
    let tenant = app.identity.tenant();
    // A hint avoids an empty write/ledger transaction for every ordinary certificate.
    // Activation still rechecks the pending row and current credential under the channel lock.
    let mut hint = app.access.begin_read(&tenant.to_string()).await?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_windows.renewals WHERE tenant_id=$1::uuid AND fingerprint=$2 AND activated_at IS NULL)")
        .bind(tenant.to_string()).bind(leaf.fingerprint().as_slice()).fetch_one(&mut *hint).await.map_err(db)?;
    hint.rollback().await.map_err(db)?;
    if !pending {
        return Ok(());
    }
    let audit = RequestAudit::new(tenant.to_string(), "windows_renewal");
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            tenant,
            &control,
            (app, leaf, device, &audit, purpose),
            |(app, leaf, device, audit, purpose), tx| {
                Box::pin(async move {
                    let id = tx
                        .with_connection_context(
                            &mut (*app, *leaf, *device, *audit, *purpose),
                            |(app, leaf, device, audit, purpose), c| {
                                Box::pin(activate_on(c, app, leaf, device, audit, *purpose))
                            },
                        )
                        .await?;
                    if let Some(id) = id {
                        let fact = rss_mdm_audit_integration::Fact::business(
                            audit,
                            &format!("windows-renewal:{id}:activated"),
                            &leaf.fingerprint(),
                            200,
                            "success",
                            None,
                        )
                        .map_err(Error::from)?;
                        app.audit_store
                            .append(tx, &fact, false)
                            .await
                            .map_err(Error::from)?;
                        audit.mark_commit_started();
                    }
                    Ok(())
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
    result
}
async fn activate_on(
    c: &mut sqlx::PgConnection,
    app: &HttpState,
    leaf: &rss_mdm_device_trust::windows::CheckedLeaf,
    device: &str,
    audit: &RequestAudit,
    purpose: rss_mdm_registration_service::Purpose,
) -> Result<Option<Uuid>, Error> {
    let tenant = app.identity.tenant().to_string();
    let original: Option<(Uuid,String)> = sqlx::query_as("SELECT r.id,r.device FROM mdm_windows.renewals n JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(n.tenant_id,n.registration) WHERE n.tenant_id=$1::uuid AND n.fingerprint=$2 AND n.activated_at IS NULL")
        .bind(&tenant).bind(leaf.fingerprint().as_slice()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some((registration, internal_device)) = original else {
        return Ok(None);
    };
    if crate::protocol_device::on(c, &tenant, registration, &internal_device).await? != device {
        return Err(Error::Forbidden);
    };
    let device = internal_device.as_str();
    crate::device::store::lock_channel(c, &tenant, device, rss_mdm_inventory::Channel::Mdm).await?;
    let row=sqlx::query("SELECT id,registration,generation,previous_credential,configuration FROM mdm_windows.renewals WHERE tenant_id=$1::uuid AND fingerprint=$2 AND activated_at IS NULL FOR UPDATE")
        .bind(&tenant).bind(leaf.fingerprint().as_slice()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<String, _>("configuration").map_err(db)? != app.windows()?.configuration {
        return Err(Error::Unauthorized);
    }
    let registration: Uuid = row.try_get("registration").map_err(db)?;
    let id: Uuid = row.try_get("id").map_err(db)?;
    crate::device::store::activate_renewed_mdm_in(
        c,
        &tenant,
        device,
        registration,
        row.try_get("generation").map_err(db)?,
        row.try_get("previous_credential").map_err(db)?,
        &crate::device::ChannelMount::new(
            app.identity.tenant(),
            rss_mdm_inventory::ReportSource::MdmWindows,
            purpose,
        )
        .credential(leaf.fingerprint())?,
    )
    .await?;
    sqlx::query(
        "UPDATE mdm_windows.renewals SET activated_at=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(&tenant)
    .bind(id)
    .bind(
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )
    .execute(c)
    .await
    .map_err(db)?;
    audit.identify_device(registration);
    audit.registration(registration);
    audit.target(device);
    Ok(Some(id))
}
