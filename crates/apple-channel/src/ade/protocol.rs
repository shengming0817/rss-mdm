use super::*;
use axum::{
    Extension,
    body::Bytes,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use rss_mdm_apple_mdm::profile;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::enrollment::native;
use serde_json::json;

pub async fn enroll(
    State(app): State<Arc<HttpState>>,
    Path((organization, profile)): Path<(Uuid, Uuid)>,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Result<Response, Error> {
    let now = super::now(&app)?;
    let verifier = rss_mdm_certificate::apple::ade::MachineVerifier::apple()?;
    #[cfg(feature = "integration")]
    let verifier = if let Some(f) = &app.apple()?.ade_fixture {
        rss_mdm_certificate::apple::ade::MachineVerifier::fixture(&f.manufacturer_root)?
    } else {
        verifier
    };
    let machine = tokio::task::spawn_blocking(move || verifier.verify(&bytes, now))
        .await
        .map_err(|_| Error::Conflict)??;
    let tenant = app.identity.tenant().to_string();
    audit.identify_service("service:apple-ade");
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let result=app.audit_store.write(app.identity.tenant(),&budget.control(),(&app,&tenant,organization,profile,&machine,&audit),|ctx,tx|Box::pin(async move{
        let(app,tenant,organization,profile,machine,audit)=*ctx;
        let (bytes,id,replayed)=tx.with_connection_context(&mut(app,tenant,organization,profile,machine),|ctx,c|Box::pin(async move{
            let(app,tenant,organization,profile,machine)=*ctx;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2673))").bind(format!("ade-identity:{tenant}:{organization}:{}",machine.udid())).execute(&mut *c).await.map_err(db)?;
            let digest=machine.digest().iter().map(|b|format!("{b:02x}")).collect::<String>();
            let old=sqlx::query("SELECT e.* FROM mdm_apple.ade_enrollments e WHERE tenant_id=$1::uuid AND organization=$2 AND udid=$3 AND NOT revoked FOR UPDATE").bind(tenant).bind(organization).bind(machine.udid()).fetch_optional(&mut *c).await.map_err(db)?;
            if let Some(old)=old{
                let id:Uuid=old.try_get("enrollment").map_err(db)?;
                let(state,live):(String,bool)=sqlx::query_as("SELECT state,expires_at>clock_timestamp() FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
                if state=="pending" && !live {
                    // The old request and challenge have expired; retain them as history.
                    sqlx::query("UPDATE mdm_apple.ade_enrollments SET revoked=true WHERE tenant_id=$1::uuid AND enrollment=$2").bind(tenant).bind(id).execute(&mut *c).await.map_err(db)?;
                }else{
                    if old.try_get::<String,_>("machine_digest").map_err(db)?!=digest || old.try_get::<Uuid,_>("profile_id").map_err(db)?!=profile{return Err(Error::Unauthorized);}
                    authority::require_in(c,tenant,id).await?;
                    if state!="pending" || !live{return Err(Error::Conflict);}
                    let sealed:Vec<u8>=old.try_get("profile").map_err(db)?;
                    let bytes=app.protection.open_bytes(&sealed,&aad(tenant,organization,&id.to_string(),"apple.ade.profile")?).map_err(|_|Error::Conflict)?;
                    return Ok((bytes.expose().to_vec(),id,true));
                }
            }
            let config=authority::issue_row(c,tenant,organization,profile,machine.serial()).await?;
            let id=Uuid::new_v4();let challenge=zeroize::Zeroizing::new(rss_mdm_registration_service::enrollment::random());
            let proof=native::issue_organization_in(c,tenant,organization,profile,machine,id,&challenge,authority::authority()).await?;
            let deadline:String=sqlx::query_scalar("SELECT expires_at::text FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
            let apple=app.apple()?;
            let(attempt,_,scep_url,scep_provisioner)=crate::enrollment::prepared(c,apple,proof.coordinates(),tenant,&deadline).await?;
            let setup:management::Setup=serde_json::from_value(config.try_get("configuration").map_err(db)?).map_err(|_|Error::Malformed)?;
            let bytes=apple.signer.sign(&profile::enrollment(&profile::EnrollmentProfile{
                mode:profile::EnrollmentMode::Ade{removable:setup.removable},access_rights:apple.access_rights() as u16,scep_url:&scep_url,scep_provisioner:&scep_provisioner,apns_topic:&apple.config.apns_topic,management_origin:&apple.config.management.origin,subject:&rss_mdm_certificate::apple::subject(id,attempt)
            },id,attempt,&challenge)?,super::now(app)?)?;
            let sealed=app.protection.seal_bytes(&bytes,&aad(tenant,organization,&id.to_string(),"apple.ade.profile")?).map_err(|_|Error::Conflict)?;
            sqlx::query("INSERT INTO mdm_apple.ade_enrollments(tenant_id,enrollment,organization,serial,udid,server_revision,assignment_revision,profile_id,profile_revision,machine_digest,machine,profile) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(tenant).bind(id).bind(organization).bind(machine.serial()).bind(machine.udid()).bind(config.try_get::<i64,_>("server_revision").map_err(db)?).bind(config.try_get::<i64,_>("assignment_revision").map_err(db)?).bind(profile).bind(config.try_get::<i64,_>("profile_revision").map_err(db)?).bind(&digest).bind(json!({"product":machine.product(),"osVersion":machine.os_version(),"build":machine.build(),"removable":setup.removable})).bind(sealed).execute(c).await.map_err(db)?;
            Ok::<_,Error>((bytes,id,false))
        })).await?;
        audit.operation(id,"apple_ade_enrollment");
        let fact=Fact::business(audit,&format!("ade-enroll:{id}"),machine.digest(),200,"success",Some(id))?;
        app.audit_store.append(tx,&fact,replayed).await.map_err(Error::from)?;audit.mark_commit_started();Ok(bytes)
    })).await;
    let bytes = crate::operations::settle(result, &audit)?;
    Ok((
        [
            ("content-type", "application/x-apple-aspen-config"),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response())
}
