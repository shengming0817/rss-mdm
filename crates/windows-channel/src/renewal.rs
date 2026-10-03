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
fn provision(app: &HttpState, certificate: &[u8], kind: &str) -> Result<Vec<u8>, Error> {
    let thumbprint = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, certificate)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    provisioning::renewal(
        certificate,
        &thumbprint,
        &app.windows()?.provider_id,
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
        .management_principal(&app.mount.credential(proof.fingerprint()))
        .await?;
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
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            principal.tenant(),
            &control,
            (app, &principal, &proof, &digest, audit),
            |(app, p, proof, digest, audit), tx| {
                Box::pin(async move {
                    let (id, certificate, kind, replayed) = tx
                        .with_connection_context(
                            &mut (*app, *p, *proof, *digest),
                            |(app, p, proof, digest), c| {
                                Box::pin(issue_on(c, app, p, proof, digest.as_slice()))
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
                    let response = provision(app, &certificate, &kind)?;
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
    proof: &certificate::RenewalProof,
    digest: &[u8],
) -> Result<(Uuid, Vec<u8>, String, bool), Error> {
    let tenant = p.tenant().to_string();
    crate::device::store::lock_channel(c, &tenant, p.device(), p.channel()).await?;
    crate::device::store::revalidate_source(c, p, rss_mdm_inventory::ReportSource::MdmWindows)
        .await?;
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
    let csr = certificate::Csr::verify(proof.csr())?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    if now >= proof.expires() {
        return Err(Error::Unauthorized);
    }
    let certificate = windows
        .ca
        .sign(&windows.ca.intent(&csr, p.registration(), now)?)?;
    let leaf = windows.ca.verify(&[certificate.clone().into()], now)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_windows.renewals(tenant_id,id,registration,generation,previous_credential,proof_digest,certificate,fingerprint,configuration) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(digest).bind(&certificate).bind(leaf.fingerprint().as_slice()).bind(&windows.configuration).execute(c).await.map_err(db)?;
    Ok((id, certificate, kind, false))
}

pub(crate) async fn activate(
    app: &HttpState,
    leaf: &certificate::CheckedLeaf,
    device: &str,
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
            (app, leaf, device, &audit),
            |(app, leaf, device, audit), tx| {
                Box::pin(async move {
                    let id = tx
                        .with_connection_context(
                            &mut (*app, *leaf, *device, *audit),
                            |(app, leaf, device, audit), c| {
                                Box::pin(activate_on(c, app, leaf, device, audit))
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
    leaf: &certificate::CheckedLeaf,
    device: &str,
    audit: &RequestAudit,
) -> Result<Option<Uuid>, Error> {
    let tenant = app.identity.tenant().to_string();
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
        &app.mount.credential(leaf.fingerprint()),
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
