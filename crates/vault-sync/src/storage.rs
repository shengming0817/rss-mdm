use super::*;
use sha2::{Digest, Sha256};
use sqlx::Row;
pub(crate) struct Scope {
    pub tenant: Uuid,
    pub instance: Uuid,
    pub principal: Uuid,
}
impl Scope {
    pub fn owner(&self) -> String {
        format!("{}:{}", self.instance, self.principal)
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn verify(key: &str, sig: &str, payload: &[u8]) -> Result<(), Error> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, bytes(key, 32, 32)?)
        .verify(payload, &bytes(sig, 64, 64)?)
        .map_err(|_| Error::Denied)
}
async fn epoch(c: &mut PgConnection, s: &Scope) -> Result<Uuid, Error> {
    sqlx::query("INSERT INTO rss_da.vault_epochs(tenant_id) VALUES($1) ON CONFLICT DO NOTHING")
        .bind(s.tenant)
        .execute(&mut *c)
        .await?;
    let restored: Uuid = sqlx::query_scalar(
        "SELECT incarnation FROM rss_da.vault_epochs WHERE tenant_id=$1 FOR SHARE",
    )
    .bind(s.tenant)
    .fetch_one(&mut *c)
    .await?;
    Ok(
        sqlx::query_scalar("SELECT incarnation FROM rss_da.vaults WHERE tenant_id=$1 AND owner=$2")
            .bind(s.tenant)
            .bind(s.owner())
            .fetch_optional(c)
            .await?
            .unwrap_or(restored),
    )
}

async fn vault(
    c: &mut PgConnection,
    s: &Scope,
) -> Result<Option<(Uuid, String, String, i64)>, Error> {
    Ok(sqlx::query_as("SELECT id,recovery_key,root_envelope,revision FROM rss_da.vaults WHERE tenant_id=$1 AND owner=$2").bind(s.tenant).bind(s.owner()).fetch_optional(c).await?)
}
async fn device(c: &mut PgConnection, s: &Scope, id: Uuid, inc: Uuid) -> Result<String, Error> {
    sqlx::query_scalar("SELECT public_key FROM rss_da.vault_devices WHERE tenant_id=$1 AND owner=$2 AND id=$3 AND incarnation=$4 AND active").bind(s.tenant).bind(s.owner()).bind(id).bind(inc).fetch_optional(c).await?.ok_or(Error::Denied)
}
pub(crate) async fn prepare(
    service: &Service,
    c: &mut PgConnection,
    s: &Scope,
    r: &Prepare,
) -> Result<(Challenge, bool), Error> {
    let inc = epoch(c, s).await?;
    let existing = vault(c, s).await?;
    let id = match (&r.action, existing.as_ref()) {
        (Action::Initialize { vault, .. }, None) => *vault,
        (Action::Initialize { vault, .. }, Some(v)) if *vault == v.0 => *vault,
        (Action::Initialize { .. }, _) => return Err(Error::Conflict),
        (_, Some(v)) => v.0,
        _ => return Err(Error::NotFound),
    };
    if !matches!(r.action, Action::Initialize { .. } | Action::Join { .. }) {
        device(c, s, r.device, inc).await?;
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    sqlx::query(
        "DELETE FROM rss_da.vault_challenges WHERE tenant_id=$1 AND owner=$2 AND expires_at<$3",
    )
    .bind(s.tenant)
    .bind(s.owner())
    .bind(now)
    .execute(&mut *c)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.vault_challenges WHERE tenant_id=$1 AND owner=$2",
    )
    .bind(s.tenant)
    .bind(s.owner())
    .fetch_one(&mut *c)
    .await?;
    if count >= 16 {
        return Err(Error::Capacity);
    }
    let challenge = Challenge {
        installation: service.installation,
        tenant: s.tenant,
        instance: s.instance,
        principal: s.principal,
        incarnation: inc,
        vault: id,
        nonce: Uuid::new_v4(),
        expires_at: now + 120,
        request: r.clone(),
    };
    sqlx::query("INSERT INTO rss_da.vault_challenges(tenant_id,owner,nonce,incarnation,document,expires_at) VALUES($1,$2,$3,$4,$5,$6)").bind(s.tenant).bind(s.owner()).bind(challenge.nonce).bind(inc).bind(serde_json::to_value(&challenge).map_err(|_|Error::Invalid)?).bind(challenge.expires_at).execute(c).await?;
    Ok((challenge, false))
}
pub(crate) async fn execute(
    service: &Service,
    c: &mut PgConnection,
    s: &Scope,
    r: &Execute,
) -> Result<(Response, bool), Error> {
    let h = &r.challenge;
    let request = &h.request;
    let mut incarnation = epoch(c, s).await?;
    if h.installation != service.installation
        || h.tenant != s.tenant
        || h.instance != s.instance
        || h.principal != s.principal
        || h.incarnation != incarnation
    {
        return Err(Error::Denied);
    }
    let existing = vault(c, s).await?;
    if existing.as_ref().is_some_and(|v| v.0 != h.vault) {
        return Err(Error::Denied);
    }
    let signing = h.signing_bytes()?;
    let key = match &request.action {
        Action::Initialize {
            vault,
            recovery_key,
            device,
            ..
        } => {
            if *vault != h.vault {
                return Err(Error::Denied);
            }
            if let Some(v) = &existing {
                if recovery_key != &v.1 {
                    return Err(Error::Denied);
                }
            }
            verify(
                recovery_key,
                r.recovery_signature.as_deref().ok_or(Error::Denied)?,
                &signing,
            )?;
            device.public_key.clone()
        }
        Action::Join { device, .. } => {
            verify(
                &existing.as_ref().ok_or(Error::NotFound)?.1,
                r.recovery_signature.as_deref().ok_or(Error::Denied)?,
                &signing,
            )?;
            device.public_key.clone()
        }
        _ => {
            if r.recovery_signature.is_some() {
                return Err(Error::Invalid);
            }
            device(c, s, request.device, incarnation).await?
        }
    };
    verify(&key, &r.signature, &signing)?;
    // Digest excludes the replaceable challenge, but includes the exact semantic request.
    let hash = digest(&serde_json::to_vec(request).map_err(|_| Error::Invalid)?);
    let receipt:Option<(String,serde_json::Value)>=sqlx::query_as("SELECT digest,document FROM rss_da.vault_receipts WHERE tenant_id=$1 AND owner=$2 AND incarnation=$3 AND operation=$4").bind(s.tenant).bind(s.owner()).bind(incarnation).bind(request.operation).fetch_optional(&mut *c).await?;
    if let Some((old, document)) = receipt {
        if old != hash {
            return Err(Error::Conflict);
        }
        // A replay cannot resurrect a removed endpoint, including an old Join receipt.
        device(c, s, request.device, incarnation).await?;
        return Ok((
            Response::Receipt {
                receipt: serde_json::from_value(document).map_err(|_| Error::Storage)?,
            },
            true,
        ));
    }
    let expected:Option<serde_json::Value>=sqlx::query_scalar("DELETE FROM rss_da.vault_challenges WHERE tenant_id=$1 AND owner=$2 AND nonce=$3 AND incarnation=$4 AND expires_at>=floor(extract(epoch FROM clock_timestamp()))::bigint RETURNING document").bind(s.tenant).bind(s.owner()).bind(h.nonce).bind(incarnation).fetch_optional(&mut *c).await?;
    if expected != Some(serde_json::to_value(h).map_err(|_| Error::Invalid)?) {
        return Err(Error::Denied);
    }
    let revision = existing.as_ref().map_or(0, |v| v.3);
    let revision = match &request.action {
        Action::Initialize {
            vault,
            recovery_key,
            root_envelope,
            device,
        } => {
            if existing.is_some() {
                return Err(Error::Conflict);
            }
            sqlx::query("INSERT INTO rss_da.vaults(tenant_id,owner,id,recovery_key,root_envelope,incarnation) VALUES($1,$2,$3,$4,$5,$6)").bind(s.tenant).bind(s.owner()).bind(vault).bind(recovery_key).bind(root_envelope).bind(incarnation).execute(&mut *c).await?;
            join(c, s, device, incarnation).await?;
            0
        }
        Action::Join {
            device,
            reset_devices,
        } => {
            if *reset_devices {
                incarnation = Uuid::new_v4();
                sqlx::query(
                    "UPDATE rss_da.vaults SET incarnation=$3 WHERE tenant_id=$1 AND owner=$2",
                )
                .bind(s.tenant)
                .bind(s.owner())
                .bind(incarnation)
                .execute(&mut *c)
                .await?;
                sqlx::query("DELETE FROM rss_da.vault_devices WHERE tenant_id=$1 AND owner=$2")
                    .bind(s.tenant)
                    .bind(s.owner())
                    .execute(&mut *c)
                    .await?;
                sqlx::query("DELETE FROM rss_da.vault_receipts WHERE tenant_id=$1 AND owner=$2")
                    .bind(s.tenant)
                    .bind(s.owner())
                    .execute(&mut *c)
                    .await?;
                sqlx::query("DELETE FROM rss_da.vault_challenges WHERE tenant_id=$1 AND owner=$2")
                    .bind(s.tenant)
                    .bind(s.owner())
                    .execute(&mut *c)
                    .await?;
            }
            join(c, s, device, incarnation).await?;
            revision
        }
        Action::Remove { device: target } => {
            let n=sqlx::query("UPDATE rss_da.vault_devices SET active=false WHERE tenant_id=$1 AND owner=$2 AND id=$3 AND incarnation=$4 AND active").bind(s.tenant).bind(s.owner()).bind(target).bind(incarnation).execute(&mut *c).await?.rows_affected();
            if n != 1 {
                return Err(Error::NotFound);
            }
            revision
        }
        Action::Write { items } => write(c, s, items, revision).await?,
        Action::Read { after, cursor } => {
            let v = existing.ok_or(Error::NotFound)?;
            if *after > revision {
                return Err(Error::Cursor);
            }
            let context = rss_mdm_query::cursor::fingerprint(&(
                service.installation,
                s.tenant,
                s.owner(),
                incarnation,
                request.device,
                revision,
                after,
            ))
            .map_err(|_| Error::Invalid)?;
            let position = cursor
                .as_ref()
                .map(|v| {
                    service
                        .cursor
                        .decode_bounded::<(i64, Uuid)>(v, &context, 4096)
                        .map_err(|_| Error::Cursor)
                })
                .transpose()?
                .unwrap_or((*after, Uuid::nil()));
            let rows=sqlx::query("SELECT id,revision,ciphertext FROM rss_da.vault_entries WHERE tenant_id=$1 AND owner=$2 AND revision>$3 AND (revision,id)>($4,$5) ORDER BY revision,id LIMIT 5").bind(s.tenant).bind(s.owner()).bind(after).bind(position.0).bind(position.1).fetch_all(c).await?;
            let mut entries = rows
                .iter()
                .map(|v| {
                    Ok(Entry {
                        id: v.try_get("id")?,
                        revision: v.try_get("revision")?,
                        ciphertext: v.try_get("ciphertext")?,
                    })
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?;
            let more = entries.len() > 4;
            entries.truncate(4);
            let next = if more {
                let e = entries.last().ok_or(Error::Storage)?;
                Some(
                    service
                        .cursor
                        .encode_bounded(&context, &(e.revision, e.id), 4096)
                        .map_err(|_| Error::Storage)?,
                )
            } else {
                None
            };
            return Ok((
                Response::Changes {
                    revision,
                    entries,
                    next_cursor: next,
                    root_envelope: v.2,
                },
                false,
            ));
        }
        Action::Devices => {
            let rows:Vec<(Uuid,String)>=sqlx::query_as("SELECT id,public_key FROM rss_da.vault_devices WHERE tenant_id=$1 AND owner=$2 AND incarnation=$3 AND active ORDER BY id LIMIT 33").bind(s.tenant).bind(s.owner()).bind(incarnation).fetch_all(c).await?;
            return Ok((
                Response::Devices {
                    devices: rows
                        .into_iter()
                        .map(|(id, public_key)| Device { id, public_key })
                        .collect(),
                },
                false,
            ));
        }
        Action::Operation { operation } => {
            let value:serde_json::Value=sqlx::query_scalar("SELECT document FROM rss_da.vault_receipts WHERE tenant_id=$1 AND owner=$2 AND incarnation=$3 AND operation=$4").bind(s.tenant).bind(s.owner()).bind(incarnation).bind(operation).fetch_optional(c).await?.ok_or(Error::NotFound)?;
            return Ok((
                Response::Receipt {
                    receipt: serde_json::from_value(value).map_err(|_| Error::Storage)?,
                },
                false,
            ));
        }
    };
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.vault_receipts WHERE tenant_id=$1 AND owner=$2 AND NOT control",
    )
    .bind(s.tenant)
    .bind(s.owner())
    .fetch_one(&mut *c)
    .await?;
    if count >= 100_000 && matches!(request.action, Action::Write { .. }) {
        return Err(Error::Capacity);
    }
    let receipt = Receipt {
        operation: request.operation,
        incarnation,
        revision,
    };
    sqlx::query("INSERT INTO rss_da.vault_receipts(tenant_id,owner,operation,incarnation,device,digest,document,control) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(s.tenant).bind(s.owner()).bind(request.operation).bind(incarnation).bind(request.device).bind(hash).bind(serde_json::to_value(&receipt).map_err(|_|Error::Storage)?).bind(!matches!(request.action,Action::Write{..})).execute(c).await?;
    Ok((Response::Receipt { receipt }, false))
}
async fn join(c: &mut PgConnection, s: &Scope, d: &Device, inc: Uuid) -> Result<(), Error> {
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.vault_devices WHERE tenant_id=$1 AND owner=$2 AND active AND incarnation=$3").bind(s.tenant).bind(s.owner()).bind(inc).fetch_one(&mut *c).await?;
    if count >= 32 {
        return Err(Error::Capacity);
    }
    // Identifiers are never reusable, even after removal or a cold restore.
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.vault_devices WHERE tenant_id=$1 AND owner=$2",
    )
    .bind(s.tenant)
    .bind(s.owner())
    .fetch_one(&mut *c)
    .await?;
    if total >= 10_000 {
        return Err(Error::Capacity);
    }
    let n=sqlx::query("INSERT INTO rss_da.vault_devices(tenant_id,owner,id,incarnation,public_key,active) VALUES($1,$2,$3,$4,$5,true) ON CONFLICT DO NOTHING").bind(s.tenant).bind(s.owner()).bind(d.id).bind(inc).bind(&d.public_key).execute(c).await?.rows_affected();
    if n != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn write(
    c: &mut PgConnection,
    s: &Scope,
    items: &[Mutation],
    revision: i64,
) -> Result<i64, Error> {
    let next = revision.checked_add(1).ok_or(Error::Capacity)?;
    for item in items {
        let current:Option<(i64,bool)>=sqlx::query_as("SELECT revision,ciphertext IS NULL FROM rss_da.vault_entries WHERE tenant_id=$1 AND owner=$2 AND id=$3").bind(s.tenant).bind(s.owner()).bind(item.id).fetch_optional(&mut *c).await?;
        if current.is_some_and(|(_, deleted)| deleted)
            || current.map_or(0, |v| v.0) != item.expected_revision
        {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO rss_da.vault_entries(tenant_id,owner,id,revision,ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,owner,id) DO UPDATE SET revision=excluded.revision,ciphertext=excluded.ciphertext").bind(s.tenant).bind(s.owner()).bind(item.id).bind(next).bind(&item.ciphertext).execute(&mut *c).await?;
    }
    let (total,live,size):(i64,i64,i64)=sqlx::query_as("SELECT count(*),count(ciphertext),coalesce(sum(octet_length(ciphertext)),0)::bigint FROM rss_da.vault_entries WHERE tenant_id=$1 AND owner=$2").bind(s.tenant).bind(s.owner()).fetch_one(&mut *c).await?;
    if total > 100_000 || live > 10_000 || size > 32 * 1024 * 1024 {
        return Err(Error::Capacity);
    }
    sqlx::query("UPDATE rss_da.vaults SET revision=$3 WHERE tenant_id=$1 AND owner=$2")
        .bind(s.tenant)
        .bind(s.owner())
        .bind(next)
        .execute(c)
        .await?;
    Ok(next)
}
