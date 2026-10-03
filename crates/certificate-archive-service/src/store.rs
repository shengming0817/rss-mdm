//! Product schema and SQL. Audit owns write transactions and settlement.
use crate::*;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use sqlx::{PgConnection, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

pub(crate) struct Vault {
    pub generation: i64,
    pub salt: Vec<u8>,
    pub wrapped: Vec<u8>,
}
pub(crate) async fn begin(
    pool: &PgPool,
    tenant: &str,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(&mut *tx).await?;
    Ok(tx)
}
pub(crate) async fn vault(c: &mut PgConnection, tenant: &str) -> Result<Option<Vault>, Error> {
    let row=sqlx::query("SELECT generation,salt,wrapped_key,kdf FROM mdm_certificate_archive.vaults WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(c).await?;
    row.map(|r| {
        if r.try_get::<String, _>("kdf")? != crate::protection::KDF {
            return Err(Error::Integrity);
        }
        Ok(Vault {
            generation: r.try_get("generation")?,
            salt: r.try_get("salt")?,
            wrapped: r.try_get("wrapped_key")?,
        })
    })
    .transpose()
}
pub(crate) async fn version(
    c: &mut PgConnection,
    tenant: &str,
    id: VersionRef,
) -> Result<(Version, Vec<u8>), Error> {
    let r=sqlx::query("SELECT entry_id::text,version,actor::text,instance::text,operation_id::text,created_at,metadata::text,facts::text,request_entry_id::text,request_version,source,sealed FROM mdm_certificate_archive.versions WHERE tenant_id=$1::uuid AND entry_id=$2::uuid AND version=$3").bind(tenant).bind(id.entry_id.to_string()).bind(id.version).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    Ok((decode_version(&r)?, r.try_get("sealed")?))
}
pub(crate) fn decode_version(r: &sqlx::postgres::PgRow) -> Result<Version, Error> {
    Ok(Version {
        entry_id: Uuid::parse_str(&r.try_get::<String, _>("entry_id")?)
            .map_err(|_| Error::Integrity)?,
        version: r.try_get("version")?,
        actor: r.try_get("actor")?,
        instance: r.try_get("instance")?,
        operation_id: Uuid::parse_str(&r.try_get::<String, _>("operation_id")?)
            .map_err(|_| Error::Integrity)?,
        created_at: r.try_get("created_at")?,
        metadata: serde_json::from_str(&r.try_get::<String, _>("metadata")?)
            .map_err(|_| Error::Integrity)?,
        facts: serde_json::from_str(&r.try_get::<String, _>("facts")?)
            .map_err(|_| Error::Integrity)?,
        request_version: match (
            r.try_get::<Option<String>, _>("request_entry_id")?,
            r.try_get::<Option<i64>, _>("request_version")?,
        ) {
            (None, None) => None,
            (Some(entry), Some(version)) if version > 0 => Some(VersionRef {
                entry_id: Uuid::parse_str(&entry).map_err(|_| Error::Integrity)?,
                version,
            }),
            _ => return Err(Error::Integrity),
        },
        source: r.try_get("source")?,
    })
}
pub(crate) async fn settings(c: &mut PgConnection, tenant: &str) -> Result<SettingsView, Error> {
    let row=sqlx::query("SELECT revision,document::text FROM mdm_certificate_archive.settings WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(c).await?;
    match row {
        None => Ok(SettingsView {
            revision: 0,
            value: Settings::default(),
        }),
        Some(r) => Ok(SettingsView {
            revision: r.try_get("revision")?,
            value: serde_json::from_str(&r.try_get::<String, _>("document")?)
                .map_err(|_| Error::Integrity)?,
        }),
    }
}
pub(crate) async fn operation(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<Option<(Vec<u8>, Receipt)>, Error> {
    let row=sqlx::query("SELECT digest,result::text FROM mdm_certificate_archive.operations WHERE tenant_id=$1::uuid AND actor=$2::uuid AND instance=$3::uuid AND id=$4::uuid").bind(p.tenant_id()).bind(p.principal_id()).bind(p.instance_id()).bind(id.to_string()).fetch_optional(c).await?;
    row.map(|r| {
        Ok((
            r.try_get("digest")?,
            serde_json::from_str(&r.try_get::<String, _>("result")?)
                .map_err(|_| Error::Integrity)?,
        ))
    })
    .transpose()
}
pub(crate) enum Mutation {
    Replay,
    Password {
        expected: i64,
        salt: Vec<u8>,
        wrapped: Vec<u8>,
    },
    Material {
        generation: i64,
        entry: Uuid,
        expected: i64,
        metadata: Box<Metadata>,
        facts: Vec<MaterialFacts>,
        sealed: Vec<u8>,
        request_version: Option<VersionRef>,
        source: &'static str,
    },
    Manage {
        entry: Uuid,
        input: ManageEntry,
    },
    Settings {
        expected: i64,
        value: Settings,
    },
    Export {
        generation: i64,
        id: VersionRef,
    },
}
impl Mutation {
    fn permissions(&self) -> &'static [Permission] {
        match self {
            Self::Replay | Self::Password { .. } => &[
                Permission::CertificateArchiveWrite,
                Permission::CertificateArchiveUnlock,
            ],
            Self::Material { .. } => &[
                Permission::CertificateArchiveWrite,
                Permission::CertificateArchiveUnlock,
            ],
            Self::Manage { .. } | Self::Settings { .. } => &[Permission::CertificateArchiveWrite],
            Self::Export { .. } => &[
                Permission::CertificateArchiveExport,
                Permission::CertificateArchiveUnlock,
            ],
        }
    }
}
pub(crate) async fn write(
    audit_store: &AuditStore,
    p: &AuthorizedPrincipal,
    id: Uuid,
    action: &'static str,
    digest: [u8; 32],
    mutation: Mutation,
    audit: &RequestAudit,
) -> Result<Receipt, Error> {
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    p.bind_audit(audit)?;
    audit.operation(id, action);
    let fact = Fact::business(
        audit,
        &format!(
            "certificate_archive:{}:{}:{}",
            p.instance_id(),
            p.principal_id(),
            id
        ),
        &digest,
        200,
        "success",
        None,
    )
    .map_err(|_| Error::Audit)?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(4));
    let control = budget.control();
    let attempt=audit_store.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_|Error::Integrity)?,&control,(p,id,action,digest,mutation,audit,audit_store,fact),|context,tx|Box::pin(async move{
        let (receipt,replayed)=tx.with_connection_context(context,|context,c|Box::pin(async move{
            let (p,id,action,digest,mutation,_,_,_)=context;
            p.check_live()?;
            rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
            let snapshot=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
            for permission in mutation.permissions(){snapshot.require(p,*permission,None).map_err(|_|Error::Forbidden)?;}
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2641))").bind(p.tenant_id()).execute(&mut *c).await?;
            // Export returns plaintext even on replay; a retired unlock cannot be reused.
            if let Mutation::Export { generation: expected, .. } = mutation {
                generation(c, p.tenant_id(), *expected).await?;
            }
            if let Some((old,result))=operation(c,p,*id).await?{if old.as_slice()!=digest||result.action!=*action{return Err(Error::Conflict)}return Ok((result,true))}
            let receipt=apply(c,p,*id,action,mutation).await?;
            sqlx::query("INSERT INTO mdm_certificate_archive.operations(tenant_id,actor,instance,id,action,digest,result,created_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::jsonb,floor(extract(epoch FROM clock_timestamp()))::bigint)").bind(p.tenant_id()).bind(p.principal_id()).bind(p.instance_id()).bind(id.to_string()).bind(*action).bind(digest.as_slice()).bind(serde_json::to_string(&receipt).map_err(|_|Error::Integrity)?).execute(c).await?;
            Ok((receipt,false))
        })).await?;
        context.6.append(tx,&context.7,replayed).await?;
        if replayed{context.5.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
        context.5.mark_commit_started();Ok(receipt)
    })).await;
    attempt.fold(
        |r| {
            audit.mark_committed();
            Ok(r.into_value())
        },
        |e| Err(tx_error(e)),
        |e| {
            audit.mark_rolled_back();
            Err(tx_error(e))
        },
        |_| {
            audit.mark_rollback_failed();
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |e| Err(tx_error(e)),
    )
}
fn tx_error(error: rss_audit_postgres::TransactionError<Error>) -> Error {
    match error {
        rss_audit_postgres::TransactionError::Operation(e) => e,
        rss_audit_postgres::TransactionError::Audit(_) => Error::Audit,
        rss_audit_postgres::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
async fn generation(c: &mut PgConnection, tenant: &str, expected: i64) -> Result<(), Error> {
    let actual = vault(c, tenant).await?.map(|v| v.generation).unwrap_or(0);
    if actual != expected {
        return Err(Error::Locked);
    }
    Ok(())
}
async fn apply(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
    action: &'static str,
    mutation: &Mutation,
) -> Result<Receipt, Error> {
    let tenant = p.tenant_id();
    let mut result = Receipt {
        operation_id: id,
        action: action.into(),
        entry_id: None,
        version: None,
        revision: 0,
    };
    match mutation {
        Mutation::Replay => return Err(Error::Conflict),
        Mutation::Password {
            expected,
            salt,
            wrapped,
        } => {
            generation(c, tenant, *expected).await?;
            let next = expected.checked_add(1).ok_or(Error::Conflict)?;
            if *expected == 0 {
                sqlx::query("INSERT INTO mdm_certificate_archive.vaults(tenant_id,generation,salt,wrapped_key,kdf,updated_at) VALUES($1::uuid,$2,$3,$4,$5,floor(extract(epoch FROM clock_timestamp()))::bigint)").bind(tenant).bind(next).bind(salt).bind(wrapped).bind(crate::protection::KDF).execute(c).await?;
            } else {
                sqlx::query("UPDATE mdm_certificate_archive.vaults SET generation=$2,salt=$3,wrapped_key=$4,updated_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid").bind(tenant).bind(next).bind(salt).bind(wrapped).execute(c).await?;
            }
            result.revision = next;
        }
        Mutation::Material {
            generation: expected_gen,
            entry,
            expected,
            metadata,
            facts,
            sealed,
            request_version,
            source,
        } => {
            generation(c, tenant, *expected_gen).await?;
            let actual:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_certificate_archive.entries WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(entry.to_string()).fetch_optional(&mut *c).await?;
            if actual.unwrap_or(0) != *expected {
                return Err(Error::Conflict);
            }
            let next = expected.checked_add(1).ok_or(Error::Conflict)?;
            if *expected == 0 {
                sqlx::query("INSERT INTO mdm_certificate_archive.entries(tenant_id,id,revision,recommended_version) VALUES($1::uuid,$2::uuid,$3,$3)").bind(tenant).bind(entry.to_string()).bind(next).execute(&mut *c).await?;
            } else {
                sqlx::query("UPDATE mdm_certificate_archive.entries SET revision=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(entry.to_string()).bind(next).execute(&mut *c).await?;
            }
            sqlx::query("INSERT INTO mdm_certificate_archive.versions(tenant_id,entry_id,version,actor,instance,operation_id,created_at,metadata,facts,sealed,source,request_entry_id,request_version) VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5::uuid,$6::uuid,floor(extract(epoch FROM clock_timestamp()))::bigint,$7::jsonb,$8::jsonb,$9,$10,$11::uuid,$12)").bind(tenant).bind(entry.to_string()).bind(next).bind(p.principal_id()).bind(p.instance_id()).bind(id.to_string()).bind(serde_json::to_string(metadata).map_err(|_|Error::Malformed)?).bind(serde_json::to_string(facts).map_err(|_|Error::Integrity)?).bind(sealed).bind(*source).bind(request_version.map(|r|r.entry_id.to_string())).bind(request_version.map(|r|r.version)).execute(c).await?;
            result.entry_id = Some(*entry);
            result.version = Some(next);
            result.revision = next;
        }
        Mutation::Manage { entry, input } => {
            if let Some(version) = input.recommended_version {
                self::version(
                    c,
                    tenant,
                    VersionRef {
                        entry_id: *entry,
                        version,
                    },
                )
                .await?;
            }
            let n=sqlx::query("UPDATE mdm_certificate_archive.entries SET revision=revision+1,retired=$3,recommended_version=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid AND revision=$5").bind(tenant).bind(entry.to_string()).bind(input.retired).bind(input.recommended_version).bind(input.expected_revision).execute(c).await?.rows_affected();
            if n != 1 {
                return Err(Error::Conflict);
            }
            result.entry_id = Some(*entry);
            result.revision = input.expected_revision + 1;
        }
        Mutation::Settings { expected, value } => {
            if settings(c, tenant).await?.revision != *expected {
                return Err(Error::Conflict);
            }
            let next = expected.checked_add(1).ok_or(Error::Conflict)?;
            sqlx::query("INSERT INTO mdm_certificate_archive.settings(tenant_id,revision,document) VALUES($1::uuid,$2,$3::jsonb) ON CONFLICT(tenant_id) DO UPDATE SET revision=EXCLUDED.revision,document=EXCLUDED.document").bind(tenant).bind(next).bind(serde_json::to_string(value).map_err(|_|Error::Malformed)?).execute(c).await?;
            result.revision = next;
        }
        Mutation::Export {
            generation: expected,
            id,
        } => {
            generation(c, tenant, *expected).await?;
            self::version(c, tenant, *id).await?;
            result.entry_id = Some(id.entry_id);
            result.version = Some(id.version);
            result.revision = id.version;
        }
    }
    Ok(result)
}
