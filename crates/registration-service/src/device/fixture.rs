//! Current native registration prerequisites; no enrollment operations or receipts are replayed.
use super::*;
use crate::database::db;

pub struct NativeSeed<'a> {
    pub device: &'a str,
    pub request: uuid::Uuid,
    pub ids: [uuid::Uuid; 3],
    pub windows_profile: Option<crate::enrollment::WindowsProfile>,
}

pub async fn native_in(
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    credential: &VerifiedChannelCredential,
    seed: NativeSeed<'_>,
) -> Result<crate::enrollment::Receipt, Error> {
    let tenant = credential.tenant.to_string();
    let current: Option<String> =
        sqlx::query_scalar("SELECT nullif(current_setting('rss.tenant_id',true),'')")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if current.as_deref() != Some(&tenant)
        || proof.tenant_id() != tenant
        || credential.purpose != Purpose::Primary
        || !matches!(
            credential.source,
            rss_mdm_inventory::ReportSource::MdmApple | rss_mdm_inventory::ReportSource::MdmWindows
        )
        || (credential.source == rss_mdm_inventory::ReportSource::MdmWindows)
            != seed.windows_profile.is_some()
    {
        return Err(Error::Forbidden);
    }
    proof.enrollment(seed.device)?;
    let password = crate::enrollment::Password::new(crate::enrollment::random())
        .map_err(|_| Error::Malformed)?;
    let digest = password
        .digest(&tenant, seed.device)
        .map_err(|_| Error::Malformed)?;
    let grant = uuid::Uuid::new_v4();
    let operation = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
        .bind(&tenant).bind(grant).bind(proof.principal_id()).bind(proof.instance_id()).bind(seed.device).execute(&mut *c).await.map_err(db)?;
    let expires = sqlx::query_scalar("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,source,expected_generation,password_digest,password_version,credential_ref,expires_at,issuance_operation,windows_profile) VALUES($1::uuid,$2,$3,'bound',$4,0,$5,1,$6,clock_timestamp()+interval '300 seconds',$7,$8) RETURNING floor(extract(epoch FROM expires_at))::bigint")
        .bind(&tenant).bind(seed.request).bind(grant).bind(credential.source.as_str()).bind(digest).bind(uuid::Uuid::new_v4()).bind(operation).bind(seed.windows_profile.map(crate::enrollment::WindowsProfile::as_str)).fetch_one(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(&tenant)
        .bind(seed.device)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,$4,1,$5,'active','primary',$6)")
        .bind(&tenant).bind(seed.ids[0]).bind(seed.device).bind(credential.channel.as_str()).bind(seed.request).bind(seed.ids[2]).execute(&mut *c).await.map_err(db)?;
    let locator: String = credential
        .locator
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,$4,$5,'active')")
        .bind(&tenant).bind(seed.ids[1]).bind(seed.ids[0]).bind(credential.channel.as_str()).bind(locator).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,$3,$4,true)")
        .bind(&tenant).bind(seed.ids[0]).bind(credential.source.as_str()).bind(seed.ids[2]).execute(c).await.map_err(db)?;
    Ok(crate::enrollment::Receipt {
        operation_id: operation,
        enrollment_id: seed.request,
        status: "bound".into(),
        expires_at: expires,
        registration: Some(seed.ids[0]),
        source: credential.source,
    })
}
