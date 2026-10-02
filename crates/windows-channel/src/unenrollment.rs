//! Microsoft DMClient disconnect notification retires server authority, not proof of device cleanup.
use crate::database::db;
use crate::{Error, HttpState, RequestAudit, device::DevicePrincipal};
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use sqlx::Row;
use uuid::Uuid;

pub(crate) async fn requested(
    app: &HttpState,
    principal: &DevicePrincipal,
    message: &s::Message,
    bytes: &[u8],
    audit: &RequestAudit,
) -> Result<Vec<u8>, Error> {
    if message.header.message_id != 1
        || !message.final_message
        || message.commands.iter().any(|c| {
            !matches!(
                c,
                s::Command::Alert {
                    alert: s::Alert::UnenrollmentRequested,
                    ..
                } | s::Command::DevInfo { .. }
            )
        })
    {
        return Err(Error::Malformed);
    }
    let mut response = s::Message {
        header: s::Header {
            session_id: message.header.session_id,
            message_id: 1,
            target: message.header.source.clone(),
            source: message.header.target.clone(),
            credential: None,
            meta: None,
        },
        commands: Vec::new(),
        final_message: true,
    };
    let references = std::iter::once((0, s::CommandName::SyncHdr)).chain(
        message.commands.iter().map(|command| {
            (
                command.id(),
                match command {
                    s::Command::Alert { .. } => s::CommandName::Alert,
                    _ => s::CommandName::Replace,
                },
            )
        }),
    );
    for (id, kind) in references {
        response.commands.push(s::Command::Status(s::Status {
            id: response.commands.len() as u32 + 1,
            message_ref: 1,
            command_ref: id,
            command: kind,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }));
    }
    let response = s::encode(&response, &CodecLimits::default()).map_err(|_| Error::Malformed)?;
    let digest = app
        .protection
        .mac(
            bytes,
            &crate::protection::native_aad(
                principal.tenant(),
                "windows.unenrollment",
                &(
                    principal.registration(),
                    principal.generation(),
                    principal.credential(),
                    message.header.session_id,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    let sealed = app
        .protection
        .seal_bytes(
            &response,
            &crate::protection::native_aad(
                principal.tenant(),
                "windows.unenrollment.response",
                &(
                    principal.registration(),
                    principal.generation(),
                    principal.credential(),
                    message.header.session_id,
                    &digest,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let mut facts = Vec::new();
    let outcome = app.audit_store.write(principal.tenant(), &control,
        (app, principal, audit, &mut facts, &digest, &sealed, message.header.session_id),
        |(app,p,audit,facts,digest,sealed,session),tx| Box::pin(async move {
            let replay = tx.with_connection_context(&mut (*app,*p,&mut **facts,*digest,*sealed,*session),
                |(app,p,facts,digest,sealed,session),c| Box::pin(async move {
                    let tenant = p.tenant().to_string();
                    crate::device::store::lock_channel(c,&tenant,p.device(),p.channel()).await?;
                    if let Some(row) = sqlx::query("SELECT digest,response FROM mdm_windows.unenrollment_receipts WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND credential=$4 AND session=$5")
                        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(*session)).fetch_optional(&mut *c).await.map_err(db)? {
                        if row.try_get::<Vec<u8>,_>("digest").map_err(db)? != **digest { return Err(Error::Conflict); }
                        return Ok::<_,Error>(Some(row.try_get::<Vec<u8>,_>("response").map_err(db)?));
                    }
                    crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::MdmWindows).await?;
                    rss_mdm_registration_service::retire(c,facts,&tenant,p.registration(),"revoked",app.devices.retirement()).await?;
                    sqlx::query("INSERT INTO mdm_windows.unenrollment_receipts(tenant_id,registration,generation,credential,session,digest,response) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
                        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(*session))
                        .bind(digest.as_slice()).bind(sealed.as_slice()).execute(c).await.map_err(db)?;
                    Ok::<_,Error>(None)
                })).await?;
            if replay.is_none() {
            let fact = rss_mdm_audit_integration::Fact::business(audit,&format!("windows-unenrollment:{}:{}",p.registration(),p.generation()),digest.as_slice(),200,"success",None)
                .and_then(|f|f.with_details(serde_json::json!({"nativeType":"com.microsoft:mdm.unenrollment.userrequest","registrationState":"revoked","deviceCleanup":"unverified"}))).map_err(Error::from)?;
            facts.push(fact);
            } else { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            for fact in facts.iter() { app.audit_store.append(tx,fact,false).await.map_err(Error::from)?; }
            if replay.is_none() { app.audit_store.append_request(tx,audit,200,"success").await.map_err(Error::from)?; }
            audit.mark_commit_started();
            Ok(replay)
        })).await;
    if let Some(sealed) = crate::operations::settle(outcome, audit)? {
        let stored = app
            .protection
            .open_bytes(
                &sealed,
                &crate::protection::native_aad(
                    principal.tenant(),
                    "windows.unenrollment.response",
                    &(
                        principal.registration(),
                        principal.generation(),
                        principal.credential(),
                        message.header.session_id,
                        &digest,
                    ),
                )?,
            )
            .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
        return Ok(stored.expose().to_vec());
    }
    Ok(response)
}

/// Historical response access never constructs an active device principal.
pub(crate) async fn replay(
    app: &HttpState,
    leaf: &crate::certificate::CheckedLeaf,
    message: &s::Message,
    bytes: &[u8],
    audit: &RequestAudit,
) -> Result<Option<Vec<u8>>, Error> {
    let tenant = app.mount.tenant();
    let locator = leaf
        .fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut tx = app.access.begin_read(&tenant.to_string()).await?;
    let row = sqlx::query("SELECT u.registration,u.generation,u.credential,u.session,u.digest,u.response,r.device FROM mdm_windows.unenrollment_receipts u JOIN mdm_access.credentials c ON (c.tenant_id,c.registration,c.id)=(u.tenant_id,u.registration,u.credential) JOIN mdm_access.registrations r ON (r.tenant_id,r.id,r.generation)=(u.tenant_id,u.registration,u.generation) WHERE u.tenant_id=$1::uuid AND c.channel='mdm' AND c.locator=$2 AND c.state='revoked' AND r.state='revoked'")
        .bind(tenant.to_string()).bind(locator).fetch_optional(&mut *tx).await.map_err(db)?;
    tx.rollback().await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let registration: Uuid = row.try_get("registration").map_err(db)?;
    let generation: i64 = row.try_get("generation").map_err(db)?;
    let credential: Uuid = row.try_get("credential").map_err(db)?;
    let session: i64 = row.try_get("session").map_err(db)?;
    let device: String = row.try_get("device").map_err(db)?;
    if device != message.header.source
        || session != i64::from(message.header.session_id)
        || message.header.message_id != 1
    {
        return Err(Error::Conflict);
    }
    let digest = app
        .protection
        .mac(
            bytes,
            &crate::protection::native_aad(
                tenant,
                "windows.unenrollment",
                &(
                    registration,
                    generation,
                    credential,
                    message.header.session_id,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    if row.try_get::<Vec<u8>, _>("digest").map_err(db)? != digest {
        return Err(Error::Conflict);
    }
    let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
    let response = app
        .protection
        .open_bytes(
            &sealed,
            &crate::protection::native_aad(
                tenant,
                "windows.unenrollment.response",
                &(
                    registration,
                    generation,
                    credential,
                    message.header.session_id,
                    &digest,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    audit.identify_device(registration);
    audit.registration(registration);
    audit.target(&device);
    audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
    Ok(Some(response.expose().to_vec()))
}
