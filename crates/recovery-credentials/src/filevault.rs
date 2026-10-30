//! FileVault custody has its own identity; MDM and Agent are authenticated ingress sources.
//! ref: Apple DeviceManagement/FDERecoveryKeyEscrow; rust-openssl openssl/src/cms.rs.
use crate::{Binding, Coordinates, Error, Protection, Subject, storage};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::filevault as w;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

/// A server-authenticated transport coordinate, never an upload-selected target.
#[derive(Clone)]
pub struct Source {
    pub tenant: Uuid,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
impl Source {
    pub fn agent(p: &rss_mdm_registration_service::DevicePrincipal) -> Result<Self, Error> {
        if p.channel() != rss_mdm_inventory::Channel::Agent
            || p.purpose() != rss_mdm_registration_service::Purpose::Primary
        {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            tenant: Uuid::parse_str(&p.tenant().to_string()).map_err(|_| Error::Malformed)?,
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
        })
    }
    async fn require_current(&self, c: &mut PgConnection) -> Result<(), Error> {
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.registrations WHERE tenant_id=$1 AND id=$2 AND generation=$3 AND device=$4 AND state='active' AND channel IN('agent','mdm') AND purpose='primary')")
            .bind(self.tenant).bind(self.registration).bind(self.generation).bind(&self.device).fetch_one(c).await?;
        if !active {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
/// Only explicitly authorized configuration/native operations may create custody.
pub async fn source_binding(
    c: &mut PgConnection,
    source: &Source,
    create: bool,
) -> Result<Option<Binding>, Error> {
    source.require_current(c).await?;
    let mut id: Option<Uuid> = sqlx::query_scalar("SELECT s.custody FROM mdm_recovery.filevault_sources s JOIN mdm_recovery.filevault_custodies f ON(f.tenant_id,f.id,f.epoch)=(s.tenant_id,s.custody,s.epoch) WHERE s.tenant_id=$1 AND s.registration=$2 AND s.generation=$3 AND s.active AND f.active AND (s.association IS NULL OR mdm_devices.association_grant_current(s.association,s.association_version,s.registration,s.generation))")
        .bind(source.tenant).bind(source.registration).bind(source.generation).fetch_optional(&mut *c).await?;
    if id.is_none() && create {
        // An explicit administrative configuration may start a new independent custody;
        // it never revives the old grant or copies its material.
        let custody = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_recovery.filevault_custodies(tenant_id,id,origin_device,origin_registration,origin_generation) VALUES($1,$2,$3,$4,$5)")
            .bind(source.tenant).bind(custody).bind(&source.device).bind(source.registration).bind(source.generation).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_recovery.filevault_sources(tenant_id,registration,generation,custody,epoch) VALUES($1,$2,$3,$4,1) ON CONFLICT(tenant_id,registration,generation) DO UPDATE SET custody=excluded.custody,epoch=excluded.epoch,active=true,association=NULL,association_version=NULL")
            .bind(source.tenant).bind(source.registration).bind(source.generation).bind(custody).execute(&mut *c).await?;
        id = Some(custody);
    }
    let Some(id) = id else {
        return Ok(None);
    };
    let row=sqlx::query("SELECT epoch,origin_device,origin_registration,origin_generation FROM mdm_recovery.filevault_custodies WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE")
        .bind(source.tenant).bind(id).fetch_optional(c).await?.ok_or(Error::Conflict)?;
    Ok(Some(Binding {
        device: row.try_get("origin_device")?,
        registration: row.try_get("origin_registration")?,
        generation: row.try_get("origin_generation")?,
        subject: Subject::Filevault {
            custody: id,
            epoch: row.try_get("epoch")?,
        },
    }))
}
/// The original upload coordinate is provenance; the custody and its live sources own lifetime.
pub async fn active(c: &mut PgConnection, tenant: Uuid, binding: &Binding) -> Result<(), Error> {
    let Subject::Filevault { custody, epoch } = binding.subject else {
        return Err(Error::Malformed);
    };
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_recovery.filevault_custodies f WHERE f.tenant_id=$1 AND f.id=$2 AND f.epoch=$3 AND f.active AND f.origin_device=$4 AND f.origin_registration=$5 AND f.origin_generation=$6 AND EXISTS(SELECT FROM mdm_recovery.filevault_sources s JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(s.tenant_id,s.registration,s.generation) WHERE s.tenant_id=f.tenant_id AND s.custody=f.id AND s.epoch=f.epoch AND s.active AND r.state='active' AND (s.association IS NULL OR mdm_devices.association_grant_current(s.association,s.association_version,s.registration,s.generation))))")
        .bind(tenant).bind(custody).bind(epoch).bind(&binding.device).bind(binding.registration).bind(binding.generation).fetch_one(c).await?;
    if valid { Ok(()) } else { Err(Error::Conflict) }
}
fn coordinates(binding: &Binding) -> Result<(Uuid, i64), Error> {
    match binding.subject {
        Subject::Filevault { custody, epoch } => Ok((custody, epoch)),
        _ => Err(Error::Malformed),
    }
}
pub async fn configuration(
    c: &mut PgConnection,
    source: &Source,
    protection: &Protection,
) -> Result<w::Configuration, Error> {
    let Some(binding) = source_binding(c, source, false).await? else {
        return Ok(w::Configuration {
            enabled: false,
            revision: 0,
            custody_id: None,
            custody_epoch: 0,
            recipient_id: None,
            recipient_certificate: None,
            material_revision: 0,
        });
    };
    let (custody, epoch) = coordinates(&binding)?;
    let row=sqlx::query("SELECT enabled,revision,recipient FROM mdm_recovery.filevault_custodies WHERE tenant_id=$1 AND id=$2")
        .bind(source.tenant).bind(custody).fetch_one(&mut *c).await?;
    let recipient: Option<String> = row.try_get("recipient")?;
    let certificate = recipient
        .as_deref()
        .map(|id| {
            protection
                .recipient(id)?
                .certificate_der()
                .map(|v| STANDARD.encode(v))
        })
        .transpose()?;
    let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND subject=$2 AND NOT retired")
        .bind(source.tenant).bind(serde_json::to_value(&binding.subject).map_err(|_|Error::Malformed)?).fetch_optional(c).await?;
    Ok(w::Configuration {
        enabled: row.try_get("enabled")?,
        revision: row.try_get("revision")?,
        custody_id: Some(custody),
        custody_epoch: epoch,
        recipient_id: recipient,
        recipient_certificate: certificate,
        material_revision: revision.unwrap_or(0),
    })
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configure {
    pub operation_id: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub expected_revision: i64,
    pub enabled: bool,
    pub recipient_id: String,
}
pub async fn configure(
    c: &mut PgConnection,
    source: &Source,
    input: &Configure,
    protection: &Protection,
) -> Result<w::Configuration, Error> {
    if input.operation_id.is_nil()
        || input.expected_revision < 0
        || input.registration != source.registration
        || input.generation != source.generation
    {
        return Err(Error::Malformed);
    }
    source.require_current(c).await?;
    let digest = Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?).to_vec();
    if let Some(row)=sqlx::query("SELECT digest,receipt,purpose FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND operation=$4")
        .bind(source.tenant).bind(source.registration).bind(source.generation).bind(input.operation_id).fetch_optional(&mut *c).await? {
        if row.try_get::<String,_>("purpose")? != "configure" || row.try_get::<Vec<u8>,_>("digest")? != digest {return Err(Error::Conflict);}
        return serde_json::from_value(row.try_get("receipt")?).map_err(|_|Error::Integrity);
    }
    // Revoking collection must not depend on the recipient still being usable.
    let recipient = if input.enabled {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await?;
        protection
            .recipient(&input.recipient_id)?
            .require_current(now)?;
        Some(input.recipient_id.as_str())
    } else {
        None
    };
    let binding = source_binding(c, source, true)
        .await?
        .ok_or(Error::NotFound)?;
    let (id, _) = coordinates(&binding)?;
    let changed=sqlx::query("UPDATE mdm_recovery.filevault_custodies SET enabled=$3,recipient=$4,revision=revision+1 WHERE tenant_id=$1 AND id=$2 AND revision=$5")
        .bind(source.tenant).bind(id).bind(input.enabled).bind(recipient).bind(input.expected_revision).execute(&mut *c).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    let result = configuration(c, source, protection).await?;
    sqlx::query("INSERT INTO mdm_recovery.filevault_receipts(tenant_id,registration,generation,operation,purpose,digest,receipt) VALUES($1,$2,$3,$4,'configure',$5,$6)")
        .bind(source.tenant).bind(source.registration).bind(source.generation).bind(input.operation_id).bind(digest)
        .bind(serde_json::to_value(&result).map_err(|_|Error::Malformed)?).execute(c).await?;
    Ok(result)
}
pub async fn receipt(
    c: &mut PgConnection,
    source: &Source,
    operation: Uuid,
) -> Result<Option<w::Receipt>, Error> {
    source.require_current(c).await?;
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT receipt FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND operation=$4 AND purpose='upload'")
        .bind(source.tenant).bind(source.registration).bind(source.generation).bind(operation).fetch_optional(c).await?;
    value
        .map(|v| serde_json::from_value(v).map_err(|_| Error::Integrity))
        .transpose()
}
/// Both native ingress paths share material deduplication. Custody never proves an actual unlock.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit custody, operation and recipient coordinates shared by both authenticated ingress paths"
)]
async fn receive_cms(
    c: &mut PgConnection,
    protection: &Protection,
    tenant: Uuid,
    binding: &Binding,
    operation: Uuid,
    revision: i64,
    recipient: &str,
    cms: &[u8],
) -> Result<Coordinates, Error> {
    let secret = protection.recipient(recipient)?.decrypt(recipient, cms)?;
    // Receiving a carrier cannot resurrect a material version explicitly invalidated by its owner.
    let invalidated=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired AND v.invalidated_at IS NOT NULL AND v.sealed IS NOT NULL"))
        .bind(tenant).bind(serde_json::to_value(&binding.subject).map_err(|_|Error::Malformed)?).fetch_all(&mut *c).await?;
    for row in invalidated {
        use subtle::ConstantTimeEq;
        let material = storage::decode(&row)?;
        let old = Coordinates {
            tenant,
            material: material.id,
            binding: material.binding,
            version: material.version,
        };
        let clear = protection.keys.open(
            &row.try_get::<String, _>("key_id")?,
            &old,
            &row.try_get::<Vec<u8>, _>("sealed")?,
        )?;
        if bool::from(clear.expose().ct_eq(&secret)) {
            return Err(Error::Conflict);
        }
    }

    let value = storage::recovery_secret_in(
        c,
        &protection.keys,
        tenant,
        binding,
        revision,
        operation,
        &secret,
    )
    .await?;
    // Only settle the newly reserved operation; unrelated pending mutations retain their barrier.
    if storage::source_operation_in(c, &value).await? == operation {
        storage::settled_in(c, &value, operation).await?;
    }
    Ok(value)
}
pub async fn receive(
    c: &mut PgConnection,
    source: &Source,
    input: &w::Upload,
    protection: &Protection,
) -> Result<w::Receipt, Error> {
    let cms = input.decode().map_err(|_| Error::Malformed)?;
    source.require_current(c).await?;
    let digest = Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Malformed)?).to_vec();
    if let Some(row)=sqlx::query("SELECT digest,receipt FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3 AND operation=$4 AND purpose='upload'")
        .bind(source.tenant).bind(source.registration).bind(source.generation).bind(input.operation_id).fetch_optional(&mut *c).await? {
        if row.try_get::<Vec<u8>,_>("digest")?!=digest {return Err(Error::Conflict);}
        return serde_json::from_value(row.try_get("receipt")?).map_err(|_|Error::Integrity);
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_recovery.filevault_receipts WHERE tenant_id=$1 AND registration=$2 AND generation=$3")
        .bind(source.tenant).bind(source.registration).bind(source.generation).fetch_one(&mut *c).await?;
    if count >= 4096 {
        return Err(Error::Conflict);
    }
    let config = configuration(c, source, protection).await?;
    if !config.enabled
        || config.custody_id != Some(input.custody_id)
        || config.custody_epoch != input.custody_epoch
        || config.revision != input.configuration_revision
        || config.recipient_id.as_deref() != Some(input.recipient_id.as_str())
    {
        return Err(Error::Forbidden);
    }
    let binding = source_binding(c, source, false)
        .await?
        .ok_or(Error::Forbidden)?;
    let value = receive_cms(
        c,
        protection,
        source.tenant,
        &binding,
        input.operation_id,
        input.expected_revision,
        &input.recipient_id,
        &cms,
    )
    .await?;
    let receipt = w::Receipt {
        operation_id: input.operation_id,
        custody_id: input.custody_id,
        custody_epoch: input.custody_epoch,
        configuration_revision: input.configuration_revision,
        recipient_id: input.recipient_id.clone(),
        cms_digest: input.cms_digest.clone(),
        material: value.material,
        version: value.version,
        escrowed: true,
    };
    sqlx::query("INSERT INTO mdm_recovery.filevault_receipts(tenant_id,registration,generation,operation,purpose,digest,receipt) VALUES($1,$2,$3,$4,'upload',$5,$6)")
        .bind(source.tenant).bind(source.registration).bind(source.generation).bind(input.operation_id).bind(digest)
        .bind(serde_json::to_value(&receipt).map_err(|_|Error::Malformed)?).execute(c).await?;
    Ok(receipt)
}
/// Revoke only this ingress. A surviving source keeps the same custody and encrypted history.
pub async fn retire_source(
    c: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.filevault_sources s SET association=NULL,association_version=NULL FROM mdm_recovery.filevault_custodies f WHERE s.tenant_id=$1::uuid AND (s.tenant_id,s.custody,s.epoch)=(f.tenant_id,f.id,f.epoch) AND f.origin_registration=$2 AND s.registration<>$2 AND s.active AND s.association IS NOT NULL AND mdm_devices.association_grant_current(s.association,s.association_version,s.registration,s.generation)")
        .bind(tenant).bind(registration).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.filevault_sources SET active=false WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(tenant).bind(registration).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.filevault_custodies f SET active=false,enabled=false,revision=revision+1 WHERE tenant_id=$1::uuid AND active AND NOT EXISTS(SELECT FROM mdm_recovery.filevault_sources s JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(s.tenant_id,s.registration,s.generation) WHERE s.tenant_id=f.tenant_id AND s.custody=f.id AND s.epoch=f.epoch AND s.active AND r.state='active' AND (s.association IS NULL OR mdm_devices.association_grant_current(s.association,s.association_version,s.registration,s.generation)))")
        .bind(tenant).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries e SET retired=true,current_version=NULL FROM mdm_recovery.filevault_custodies f WHERE e.tenant_id=$1::uuid AND e.subject->>'kind'='filevault' AND (f.tenant_id,f.id::text,f.epoch::text)=(e.tenant_id,e.subject->>'custody',e.subject->>'epoch') AND NOT f.active")
        .bind(tenant).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.versions v SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) FROM mdm_recovery.entries e WHERE (v.tenant_id,v.entry)=(e.tenant_id,e.id) AND e.tenant_id=$1::uuid AND e.subject->>'kind'='filevault' AND e.retired AND v.invalidated_at IS NULL")
        .bind(tenant).execute(c).await?;

    Ok(())
}

/// Only an explicitly authorized, device-owner-verified association may call this operation.
/// Pending mutations are a barrier: merging never guesses whether a rotation committed.
pub async fn merge(
    c: &mut PgConnection,
    protection: &Protection,
    left: &Source,
    right: &Source,
    association: Uuid,
    association_version: i64,
) -> Result<Binding, Error> {
    use subtle::ConstantTimeEq;
    if left.tenant != right.tenant || left.registration == right.registration {
        return Err(Error::Malformed);
    }
    let tenant = left.tenant;
    let qualified:bool=sqlx::query_scalar("SELECT mdm_devices.association_grant_current($1,$2,$3,$4) AND mdm_devices.association_grant_current($1,$2,$5,$6)")
        .bind(association).bind(association_version).bind(left.registration).bind(left.generation).bind(right.registration).bind(right.generation).fetch_one(&mut *c).await?;
    if !qualified {
        return Err(Error::Forbidden);
    }
    let a = source_binding(c, left, true)
        .await?
        .ok_or(Error::Conflict)?;
    let b = source_binding(c, right, true)
        .await?
        .ok_or(Error::Conflict)?;
    let (aid, _) = coordinates(&a)?;
    let (bid, _) = coordinates(&b)?;
    if aid == bid {
        return Ok(a);
    }
    // The explicitly selected target retains its identity; the asset fence serializes both orders.
    let (keep, remove) = (a, b);
    let (kid, kepoch) = coordinates(&keep)?;
    let (rid, repoch) = coordinates(&remove)?;
    let policies:Vec<(bool,Option<String>)>=sqlx::query_as("SELECT enabled,recipient FROM mdm_recovery.filevault_custodies WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE")
        .bind(tenant).bind(vec![kid,rid]).fetch_all(&mut *c).await?;
    let recipients: std::collections::BTreeSet<_> =
        policies.iter().filter_map(|(_, r)| r.clone()).collect();
    if recipients.len() > 1 {
        return Err(Error::Conflict);
    }
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_recovery.entries e JOIN mdm_recovery.versions v ON(v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject=ANY($2) AND NOT e.retired AND v.pending)")
        .bind(tenant).bind(vec![serde_json::to_value(&keep.subject).map_err(|_|Error::Malformed)?,serde_json::to_value(&remove.subject).map_err(|_|Error::Malformed)?]).fetch_one(&mut *c).await?;
    if pending {
        return Err(Error::Conflict);
    }
    let rows=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired ORDER BY v.version FOR UPDATE OF e,v"))
        .bind(tenant).bind(serde_json::to_value(&remove.subject).map_err(|_|Error::Malformed)?).fetch_all(&mut *c).await?;
    for row in rows {
        let old = storage::decode(&row)?;
        let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("sealed")? else {
            continue;
        };
        let original = Coordinates {
            tenant,
            material: old.id,
            binding: old.binding.clone(),
            version: old.version,
        };
        let secret =
            protection
                .keys
                .open(&row.try_get::<String, _>("key_id")?, &original, &sealed)?;
        let target_rows=sqlx::query(storage::select_material!(" WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired ORDER BY v.version FOR UPDATE OF e,v"))
            .bind(tenant).bind(serde_json::to_value(&keep.subject).map_err(|_|Error::Malformed)?).fetch_all(&mut *c).await?;
        let mut duplicate = false;
        for target in target_rows {
            let m = storage::decode(&target)?;
            if let (Some(k), Some(bytes)) = (
                target.try_get::<Option<String>, _>("key_id")?,
                target.try_get::<Option<Vec<u8>>, _>("sealed")?,
            ) {
                let coord = Coordinates {
                    tenant,
                    material: m.id,
                    binding: m.binding,
                    version: m.version,
                };
                if bool::from(
                    protection
                        .keys
                        .open(&k, &coord, &bytes)?
                        .expose()
                        .ct_eq(secret.expose()),
                ) {
                    duplicate = true;
                    if matches!(
                        old.validity,
                        crate::Validity::Revoked | crate::Validity::Superseded
                    ) {
                        sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND version=$3")
                            .bind(tenant).bind(coord.material).bind(coord.version).execute(&mut *c).await?;
                    }
                    break;
                }
            }
        }
        if !duplicate {
            let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND subject=$2 AND NOT retired")
                .bind(tenant).bind(serde_json::to_value(&keep.subject).map_err(|_|Error::Malformed)?).fetch_optional(&mut *c).await?;
            let operation = Uuid::new_v4();
            let next =
                storage::reserve_in(c, tenant, &keep, operation, revision.unwrap_or(0)).await?;
            storage::ingest_in(c, &protection.keys, &next, operation, secret.expose()).await?;
            storage::settled_in(c, &next, operation).await?;
            if matches!(
                old.validity,
                crate::Validity::Revoked | crate::Validity::Superseded
            ) {
                sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND version=$3")
                    .bind(tenant).bind(next.material).bind(next.version).execute(&mut *c).await?;
            }
        }
    }
    // Preserve historical receipts but keep only one writable owner and one encrypted history.
    sqlx::query("UPDATE mdm_recovery.versions v SET key_id=NULL,sealed=NULL,pending=false,validity='superseded',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) FROM mdm_recovery.entries e WHERE (e.tenant_id,e.id)=(v.tenant_id,v.entry) AND e.tenant_id=$1 AND e.subject=$2")
        .bind(tenant).bind(serde_json::to_value(&remove.subject).map_err(|_|Error::Malformed)?).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries SET retired=true,current_version=NULL WHERE tenant_id=$1 AND subject=$2")
        .bind(tenant).bind(serde_json::to_value(&remove.subject).map_err(|_|Error::Malformed)?).execute(&mut *c).await?;
    sqlx::query(
        "UPDATE mdm_recovery.entries SET current_version=NULL WHERE tenant_id=$1 AND subject=$2",
    )
    .bind(tenant)
    .bind(serde_json::to_value(&keep.subject).map_err(|_| Error::Malformed)?)
    .execute(&mut *c)
    .await?;
    sqlx::query("UPDATE mdm_recovery.versions v SET validity='unverified' FROM mdm_recovery.entries e WHERE (e.tenant_id,e.id)=(v.tenant_id,v.entry) AND e.tenant_id=$1 AND e.subject=$2 AND v.invalidated_at IS NULL")
        .bind(tenant).bind(serde_json::to_value(&keep.subject).map_err(|_|Error::Malformed)?).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.filevault_sources SET custody=$3,epoch=$4,association=$6,association_version=$7 WHERE tenant_id=$1 AND custody=$2 AND epoch=$5 AND active")
        .bind(tenant).bind(rid).bind(kid).bind(kepoch).bind(repoch).bind(association).bind(association_version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.filevault_custodies SET active=false,enabled=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(rid).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.filevault_custodies SET enabled=$3,recipient=$4,revision=revision+1 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(kid).bind(policies.iter().any(|(e,_)|*e)).bind(recipients.into_iter().next()).execute(c).await?;
    Ok(keep)
}

/// Finish the original reserved native operation, without creating an unrelated candidate.
pub async fn receive_reserved_cms(
    c: &mut PgConnection,
    protection: &Protection,
    reserved: &Coordinates,
    operation: Uuid,
    recipient: &str,
    cms: &[u8],
) -> Result<Coordinates, Error> {
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(reserved.tenant)
    .bind(reserved.material)
    .fetch_one(&mut *c)
    .await?;
    let actual = receive_cms(
        c,
        protection,
        reserved.tenant,
        &reserved.binding,
        operation,
        revision,
        recipient,
        cms,
    )
    .await?;
    if actual.material != reserved.material || actual.version != reserved.version {
        sqlx::query("UPDATE mdm_recovery.versions SET validity='superseded',invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint,pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND operation=$4 AND sealed IS NULL")
            .bind(reserved.tenant).bind(reserved.material).bind(reserved.version).bind(operation).execute(c).await?;
    }
    Ok(actual)
}

/// Resolve only material owned by the custody of an already authenticated current source.
pub async fn material_coordinates(
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
    id: Uuid,
    version: i64,
) -> Result<Coordinates, Error> {
    active(c, tenant, binding).await?;
    let row = sqlx::query(storage::select_material!(
        " WHERE e.tenant_id=$1 AND e.subject=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired"
    ))
    .bind(tenant)
    .bind(serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?)
    .bind(id)
    .bind(version)
    .fetch_optional(c)
    .await?
    .ok_or(Error::NotFound)?;
    let material = storage::decode(&row)?;
    if !material.validity.readable() {
        return Err(Error::Conflict);
    }
    Ok(Coordinates {
        tenant,
        material: id,
        binding: material.binding,
        version,
    })
}
