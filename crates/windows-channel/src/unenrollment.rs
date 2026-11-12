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
                    principal.device(),
                    principal.epoch(),
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
                    principal.device(),
                    principal.epoch(),
                    principal.credential(),
                    message.header.session_id,
                    &digest,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    let budget = app.devices.retirement_budget();
    let mut facts = Vec::new();
    let outcome = app.audit_store.write(principal.tenant(),
            &budget.source_control(),
        (app, principal, audit, &mut facts, &digest, &sealed, message.header.session_id),
        |(app,p,audit,facts,digest,sealed,session),tx| Box::pin(async move {
            let replay = tx.with_connection_context(&mut (*app,*p,&mut **facts,*digest,*sealed,*session),
                |(app,p,facts,digest,sealed,session),c| Box::pin(async move {
                    let tenant = p.tenant().to_string();
                    crate::device::store::lock_channel(rss_mdm_install_support::StorageProfile::Mdm, c,&tenant,p.device(),p.require_channel()?).await?;
                    if let Some(row) = sqlx::query("SELECT digest, response FROM mdm_windows.unenrollment_receipts WHERE (tenant_id = CAST($1 AS uuid) AND device = $2 AND credential = $3 AND session = $4) AND unenrollment_receipts.protocol_epoch = $5")
                        .bind(&tenant).bind(p.device().into_uuid()).bind(p.credential()).bind(i64::from(*session)).bind(p.epoch()).fetch_optional(&mut *c).await.map_err(db)? {
                        if row.try_get::<Vec<u8>,_>("digest").map_err(db)? != **digest { return Err(Error::Conflict); }
                        return Ok::<_,Error>(Some(row.try_get::<Vec<u8>,_>("response").map_err(db)?));
                    }
                    crate::device::store::revalidate_management(rss_mdm_install_support::StorageProfile::Mdm, c,p).await?;
                    if p.purpose()==crate::device::Purpose::WindowsDeclared {
                        crate::device::linked::revoke_in(rss_mdm_install_support::StorageProfile::Mdm,c,p).await?;
                        sqlx::query("UPDATE mdm_access.management_sessions SET state='superseded' WHERE tenant_id=$1::uuid AND device=$2 AND protocol_epoch=$3 AND state IN('challenge','collecting')")
                            .bind(&tenant).bind(p.device().into_uuid()).bind(p.epoch()).execute(&mut *c).await.map_err(db)?;
                    } else {
                        app.departure.departed(c,&tenant,*p.device()).await.map_err(|_|Error::Conflict)?;
                        rss_mdm_registration_service::retire(rss_mdm_install_support::StorageProfile::Mdm,c,facts,&tenant,p.device(),"revoked",app.devices.retirement()).await?;
                    }
                    sqlx::query("INSERT INTO mdm_windows.unenrollment_receipts (tenant_id, device, credential, session, digest, response, protocol_epoch) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7)")
                        .bind(&tenant).bind(p.device().into_uuid()).bind(p.credential()).bind(i64::from(*session))
                        .bind(digest.as_slice()).bind(sealed.as_slice()).bind(p.epoch()).execute(c).await.map_err(db)?;
                    Ok::<_,Error>(None)
                })).await?;
            if replay.is_none() {
            let fact = rss_mdm_audit_integration::Fact::observation(audit, &format!("windows-unenrollment:{}:{}",p.device(),p.epoch()), 200, "success", None)
                .and_then(|f|f.with_details(serde_json::json!({"nativeType":"com.microsoft:mdm.unenrollment.userrequest","registrationState":"revoked","deviceCleanup":"unverified"}))).map_err(Error::from)?;
            facts.push(fact);
            } else { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            for fact in facts.iter() { app.audit_store.append(tx, fact).await.map_err(Error::from)?; }
            if replay.is_none() { audit.require_final_request(); }
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
                        principal.device(),
                        principal.epoch(),
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
    leaf: &rss_mdm_device_trust::windows::CheckedLeaf,
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
    let row=sqlx::query("SELECT u.device,u.protocol_epoch,u.credential,u.session,u.digest,u.response,c.protocol_request FROM mdm_windows.unenrollment_receipts u JOIN mdm_access.credentials c ON(c.tenant_id,c.device,c.id)=(u.tenant_id,u.device,u.credential) JOIN mdm_access.devices d ON(d.tenant_id,d.id)=(u.tenant_id,u.device) LEFT JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(c.tenant_id,c.protocol_request) WHERE u.tenant_id=$1::uuid AND c.channel='mdm' AND c.locator=$2 AND c.state='revoked' AND (d.state='revoked' OR (c.purpose='windows_declared' AND q.state='cancelled'))")
        .bind(tenant.to_string()).bind(locator).fetch_optional(&mut *tx).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let device: rss_mdm_agent_wire::DeviceId = row
        .try_get::<uuid::Uuid, _>("device")
        .and_then(|id| {
            rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
        })
        .map_err(db)?;
    let protocol_epoch: Uuid = row.try_get("protocol_epoch").map_err(db)?;
    let credential: Uuid = row.try_get("credential").map_err(db)?;
    let session: i64 = row.try_get("session").map_err(db)?;
    let request = crate::enrollment_store::native_request(
        &mut tx,
        &tenant.to_string(),
        &device,
        row.try_get("protocol_request").map_err(db)?,
    )
    .await
    .map_err(db)?;
    let protocol_device =
        crate::protocol_device::on(&mut tx, &tenant.to_string(), request, &device).await?;
    tx.rollback().await.map_err(db)?;
    if protocol_device != message.header.source
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
                    &device,
                    protocol_epoch,
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
                    &device,
                    protocol_epoch,
                    credential,
                    message.header.session_id,
                    &digest,
                ),
            )?,
        )
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
    audit.identify_device(&device);
    audit.target_device(&device);
    audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
    Ok(Some(response.expose().to_vec()))
}
