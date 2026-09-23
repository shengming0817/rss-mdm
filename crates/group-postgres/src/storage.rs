use crate::{codec, model::*};
use rss_mdm_group::Rule;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sha2::{Digest, Sha256};
use sqlx::Row;

pub(crate) fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub(crate) fn fingerprint(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"rss-mdm-group-operation-v1");
    for p in parts {
        hash.update((p.len() as u64).to_be_bytes());
        hash.update(p);
    }
    hash.finalize().to_vec()
}
#[derive(Clone, Copy)]
pub(crate) enum StorageFault {
    Contract,
    DocumentDigest,
    StoredShape,
    RowCount,
    OutboxIdentity,
}
impl StorageFault {
    pub(crate) fn error(self) -> PgError {
        let reason = match self {
            Self::Contract => "group.storage_contract",
            Self::DocumentDigest => "group.document_digest",
            Self::StoredShape => "group.stored_shape",
            Self::RowCount => "group.row_count",
            Self::OutboxIdentity => "group.outbox_identity",
        };
        tracing::error!(target: "rss_mdm_group_postgres::storage", reason, "Group storage invariant");
        sqlx::Error::Protocol("Group storage invariant".into()).into()
    }
}
pub(crate) fn stored_shape() -> PgError {
    StorageFault::StoredShape.error()
}

pub(crate) fn data<T>(value: Result<T, impl std::fmt::Debug>) -> Result<T, PgError> {
    value.map_err(|_| stored_shape())
}
pub(crate) fn document(bytes: &[u8], expected: &[u8]) -> Result<(), PgError> {
    if digest(bytes) == expected {
        Ok(())
    } else {
        Err(StorageFault::DocumentDigest.error())
    }
}
pub(crate) async fn group(
    tx: &mut PgTransaction<'_>,
    id: GroupId,
    lock: bool,
) -> Result<Option<Group>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move |c|Box::pin(async move {
        if lock {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2387))")
                .bind(format!("group:{tenant}:{id}")).execute(&mut *c).await?;
        }
        let query=if lock {"SELECT * FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"}
        else {"SELECT * FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid"};
        sqlx::query(query).bind(tenant).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    row.map(|r| {
        let kind = match r.try_get::<&str, _>("kind")? {
            "static" => GroupKind::Static,
            "dynamic" => GroupKind::Dynamic,
            _ => return Err(stored_shape()),
        };
        Ok(Group {
            id,
            kind,
            name: r.try_get("name")?,
            description: r.try_get("description")?,
            revision: data(Revision::new(r.try_get("revision")?))?,
            member_version: r.try_get("member_version")?,
            member_count: data(usize::try_from(r.try_get::<i64, _>("member_count")?))?,
            rule_version: r.try_get("rule_version")?,
            deleted: r.try_get("deleted")?,
        })
    })
    .transpose()
}
pub(crate) async fn rule(
    tx: &mut PgTransaction<'_>,
    group: GroupId,
    version: String,
) -> Result<Rule, PgError> {
    find_rule(tx, group, version)
        .await?
        .ok_or_else(stored_shape)
}
pub(crate) async fn find_rule(
    tx: &mut PgTransaction<'_>,
    group: GroupId,
    version: String,
) -> Result<Option<Rule>, PgError> {
    let tenant = tx.tenant_id();
    let raw = tenant.to_string();
    let v = version.clone();
    let r=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT document,digest FROM mdm_group.rules WHERE tenant_id=$1::uuid AND group_id=$2::uuid AND version=$3")
        .bind(raw).bind(group.to_string()).bind(v).fetch_optional(c).await
    })).await?;
    let Some(r) = r else {
        return Ok(None);
    };
    let bytes: Vec<u8> = r.try_get("document")?;
    document(&bytes, r.try_get::<&[u8], _>("digest")?)?;
    let result = data(codec::decode_rule(&bytes))?;
    if result.view().tenant != tenant || result.view().version != version {
        return Err(stored_shape());
    }
    Ok(Some(result))
}
pub(crate) async fn write_rule(
    tx: &mut PgTransaction<'_>,
    group: GroupId,
    r: &Rule,
) -> Result<(), PgError> {
    let bytes = data(codec::encode_rule(r))?;
    let hash = digest(&bytes);
    let version = r.view().version.to_owned();
    let tenant = tx.tenant_id().to_string();
    let (expected,returned)=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_group.rules(tenant_id,group_id,version,document,digest) VALUES($1::uuid,$2::uuid,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(&tenant).bind(group.to_string()).bind(&version).bind(bytes).bind(&hash).execute(&mut *c).await?;
        let old:Vec<u8>=sqlx::query_scalar("SELECT digest FROM mdm_group.rules WHERE tenant_id=$1::uuid AND group_id=$2::uuid AND version=$3")
        .bind(tenant).bind(group.to_string()).bind(version).fetch_one(c).await?;
        Ok((hash,old))
    })).await?;
    if expected != returned {
        return Err(StorageFault::DocumentDigest.error());
    }
    Ok(())
}
pub(crate) async fn save_group(
    tx: &mut PgTransaction<'_>,
    g: &Group,
    create: bool,
) -> Result<(), PgError> {
    let g = g.clone();
    let tenant = tx.tenant_id().to_string();
    let n=tx.with_connection(move |c|Box::pin(async move {
        let query=if create {
            "INSERT INTO mdm_group.groups(tenant_id,id,kind,name,description,revision,member_version,member_count,rule_version,deleted) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10)"
        }else {
            "UPDATE mdm_group.groups SET name=$4,description=$5,revision=$6,member_version=$7,member_count=$8,rule_version=$9,deleted=$10 WHERE tenant_id=$1::uuid AND id=$2::uuid AND kind=$3"
        };
        sqlx::query(query).bind(tenant).bind(g.id.to_string()).bind(match g.kind {GroupKind::Static=>"static",GroupKind::Dynamic=>"dynamic"})
        .bind(g.name).bind(g.description).bind(g.revision.get()).bind(g.member_version).bind(g.member_count as i64).bind(g.rule_version).bind(g.deleted).execute(c).await.map(|r|r.rows_affected())
    })).await?;
    if n != 1 {
        return Err(StorageFault::RowCount.error());
    }
    Ok(())
}
pub(crate) struct StoredOperation {
    pub group: GroupId,
    pub digest: Vec<u8>,
    pub receipt: Receipt,
}
pub(crate) async fn operation(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    lock: bool,
) -> Result<Option<StoredOperation>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let raw = tenant.clone();
    let row=tx.with_connection(move |c|Box::pin(async move {
        if lock {sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2387))").bind(format!("operation:{raw}:{id}")).execute(&mut *c).await?;}
        sqlx::query("SELECT group_id::text,digest,request,receipt,receipt_digest,as_of FROM mdm_group.operations WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(raw).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    row.map(|row| {
        let group = data(GroupId::parse(row.try_get("group_id")?))?;
        let request: Vec<u8> = row.try_get("request")?;
        let as_of: i64 = row.try_get("as_of")?;
        let hash: Vec<u8> = row.try_get("digest")?;
        if fingerprint(&[tenant.as_bytes(), &as_of.to_be_bytes(), &request]) != hash {
            return Err(stored_shape());
        }
        let raw: Vec<u8> = row.try_get("receipt")?;
        document(&raw, row.try_get::<&[u8], _>("receipt_digest")?)?;
        let receipt: Receipt = data(codec::decode(&raw))?;
        if receipt.operation != id || receipt.group.id != group {
            return Err(stored_shape());
        }
        Ok(StoredOperation {
            group,
            digest: hash,
            receipt,
        })
    })
    .transpose()
}
pub(crate) struct NewOperation {
    pub id: OperationId,
    pub group: GroupId,
    pub digest: Vec<u8>,
    pub request: Vec<u8>,
    pub as_of: i64,
    pub receipt: Receipt,
}
pub(crate) async fn insert_operation(
    tx: &mut PgTransaction<'_>,
    op: NewOperation,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let receipt = data(codec::encode(&op.receipt))?;
    let hash = digest(&receipt);
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_group.operations(tenant_id,id,group_id,digest,request,receipt,receipt_digest,as_of) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8)")
            .bind(tenant).bind(op.id.to_string()).bind(op.group.to_string()).bind(op.digest).bind(op.request).bind(receipt).bind(hash).bind(op.as_of).execute(c).await?;Ok(())
    })).await
}
