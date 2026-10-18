use super::*;
use crate::enrollment::managed::Authority;
/// Persist one native grant after execution has verified its frozen installation authority.
/// It creates neither an Enrollment request nor a Registration.
pub async fn create_in(
    c: &mut PgConnection,
    authority: Authority,
    input: &wire::NativeGrantRequest,
    native: &serde_json::Value,
) -> Result<(wire::GrantReceipt, bool), Error> {
    input.validate().map_err(|_| Error::Malformed)?;
    let p = authority.principal();
    let tenant = p.tenant().to_string();
    crate::admission::lock_in(c, &tenant).await?;
    crate::lifecycle::require_work_in(c, &tenant, p.device()).await?;
    if authority.installation() != input.installation_operation {
        return Err(Error::Forbidden);
    }
    let bound = hex(csr(&input.csr)?.spki());
    let digest = digest(input)?;
    sqlx::query(
        r#"
SELECT pg_advisory_xact_lock(hashtextextended($1,2630))
"#,
    )
    .bind(format!("{tenant}:native:{}", input.installation_operation))
    .execute(&mut *c)
    .await
    .map_err(db)?;
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='native' AND
native_authority->>'installation'= $2
"#,
    )
    .bind(&tenant)
    .bind(input.installation_operation.to_string())
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    {
        let row = native_grant_row(c, &tenant, id).await?;
        if row.try_get::<String, _>("request_digest").map_err(db)? != digest
            || row.try_get::<String, _>("spki").map_err(db)? != bound
        {
            return Err(Error::Conflict);
        }
        check_secret(&tenant, &row, &input.secret)?;
        return Ok((receipt(&row)?, true));
    }
    crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent).await?;
    let policy = settings::admit_on(c, &tenant, input.runtime.platform).await?;
    let id = Uuid::new_v4();
    let device = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,
id,
operation_id,
source,
actor,
instance,
device,
platform,
secret_digest,
request_digest,
spki,
state,
expires_at,
native_authority)
VALUES($1::uuid,
$2,
$3,
'native',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
least(to_timestamp($11),
clock_timestamp()+make_interval(secs=>$13)),
$12)
"#,
    )
    .bind(&tenant)
    .bind(id)
    .bind(input.operation_id)
    .bind(&authority.user().principal_id)
    .bind(&authority.user().instance_id)
    .bind(device)
    .bind(platform(input.runtime.platform))
    .bind(secret_digest(&tenant, id, &input.secret))
    .bind(digest)
    .bind(bound)
    .bind(authority.deadline() as f64)
    .bind(native)
    .bind(f64::from(policy.grant_seconds))
    .execute(&mut *c)
    .await
    .map_err(db)?;
    Ok((receipt(&native_grant_row(c, &tenant, id).await?)?, false))
}
/// Native proof reconstructed only from a stored grant and its still-current registration.
pub struct Source {
    principal: crate::device::DevicePrincipal,
    report_source: rss_mdm_inventory::ReportSource,
    installation: Uuid,
    runtime: Option<wire::RuntimeProfile>,
    bootstrap: Uuid,
}
impl Source {
    pub fn bootstrap(&self) -> Uuid {
        self.bootstrap
    }
    pub fn principal(&self) -> &crate::device::DevicePrincipal {
        &self.principal
    }
    pub fn report_source(&self) -> rss_mdm_inventory::ReportSource {
        self.report_source
    }
    pub fn installation(&self) -> Uuid {
        self.installation
    }
    pub fn runtime(&self) -> Option<&wire::RuntimeProfile> {
        self.runtime.as_ref()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    installation: Uuid,
    registration: Uuid,
    credential: Uuid,
    generation: i64,
    source: rss_mdm_inventory::ReportSource,
    runtime: Option<wire::RuntimeProfile>,
    bootstrap: Uuid,
}
pub(crate) async fn source(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    value: serde_json::Value,
) -> Result<Source, Error> {
    let s: Stored = serde_json::from_value(value).map_err(|_| Error::Corrupt)?;
    if s.source.channel() != rss_mdm_inventory::Channel::Mdm || s.installation.is_nil() {
        return Err(Error::Corrupt);
    }
    let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 AND installation=$3 AND active AND state<>'revoked' AND (state='consumed' OR deadline>extract(epoch FROM clock_timestamp())) AND source->>'registration'=$4 AND source->>'credential'=$5 AND source->>'generation'=$6)")
        .bind(tenant.to_string()).bind(s.bootstrap).bind(s.installation).bind(s.registration.to_string()).bind(s.credential.to_string()).bind(s.generation.to_string())
        .fetch_one(&mut *c).await.map_err(db)?;
    if !current {
        return Err(Error::Forbidden);
    }
    let locator: String = sqlx::query_scalar(
        r#"
SELECT locator FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND id=$2 AND
registration=$3 AND channel='mdm' AND state='active'
"#,
    )
    .bind(tenant.to_string())
    .bind(s.credential)
    .bind(s.registration)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .ok_or(Error::Forbidden)?;
    if locator.len() != 64 || !locator.is_ascii() {
        return Err(Error::Corrupt);
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&locator[i * 2..i * 2 + 2], 16).map_err(|_| Error::Corrupt)?
    }
    let usage = match s.source {
        rss_mdm_inventory::ReportSource::MdmWindows => rss_mdm_agent_wire::pki::Purpose::Windows,
        rss_mdm_inventory::ReportSource::MdmApple => rss_mdm_agent_wire::pki::Purpose::Apple,
        _ => return Err(Error::Forbidden),
    };
    rss_mdm_pki_service::registry::current_certificate_in(c, tenant, usage, &bytes)
        .await
        .map_err(|e| match e {
            rss_mdm_pki_service::Error::Storage => Error::Storage,
            _ => Error::Forbidden,
        })?;
    let mount = crate::device::ChannelMount::new(tenant, s.source, crate::device::Purpose::Primary);
    let principal = crate::device::store::management_in(c, &mount.credential(bytes)?).await?;
    if principal.registration() != s.registration
        || principal.generation() != s.generation
        || principal.credential() != s.credential
    {
        return Err(Error::Forbidden);
    }
    Ok(Source {
        principal,
        report_source: s.source,
        installation: s.installation,
        runtime: s.runtime,
        bootstrap: s.bootstrap,
    })
}

// Native creation is serialized by its installation advisory lock. A read here
// avoids granting the execution role lifecycle mutation rights or taking a
// grant lock after the native-channel lock held by its caller.
async fn native_grant_row(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<PgRow, Error> {
    sqlx::query("SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2 AND source='native'")
        .bind(tenant).bind(id).fetch_one(c).await.map_err(db)
}
