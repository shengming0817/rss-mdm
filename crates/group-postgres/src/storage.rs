use crate::{codec, model::*};
use rss_mdm_group::{ObjectKey, Rule};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};

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
pub(crate) async fn members(
    tx: &mut PgTransaction<'_>,
    id: GroupId,
) -> Result<Vec<ObjectKey>, PgError> {
    let tenant = tx.tenant_id();
    let raw = tenant.to_string();
    let rows=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT object_id,object_digest FROM mdm_group.members WHERE tenant_id=$1::uuid AND group_id=$2::uuid ORDER BY object_id COLLATE \"C\" LIMIT 10001")
        .bind(raw).bind(id.to_string()).fetch_all(c).await
    })).await?;
    if rows.len() > rss_mdm_group::limits::OBJECTS {
        return Err(stored_shape());
    }
    rows.into_iter()
        .map(|r| {
            let id: String = r.try_get("object_id")?;
            document(id.as_bytes(), r.try_get::<&[u8], _>("object_digest")?)?;
            data(ObjectKey::new(tenant, id))
        })
        .collect()
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
    pub id: OperationId,
    pub group: GroupId,
    pub kind: String,
    pub digest: Vec<u8>,
    pub request: Vec<u8>,
    pub trigger: Option<Vec<u8>>,
    pub state: RunState,
    pub base: i64,
    pub rule_version: Option<String>,
    pub as_of: i64,
    pub result: Option<Vec<u8>>,
    pub duration: Option<i64>,
}
pub(crate) async fn operation(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    lock: bool,
) -> Result<Option<StoredOperation>, PgError> {
    let tenant_id = tx.tenant_id();
    let tenant = tenant_id.to_string();
    let row=tx.with_connection(move |c|Box::pin(async move {
        if lock {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2387))")
                .bind(format!("operation:{tenant}:{id}")).execute(&mut *c).await?;
        }
        let query=if lock {"SELECT *,group_id::text AS group_text, (extract(epoch FROM completed_at-created_at)*1000000)::bigint AS duration FROM mdm_group.operations WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"}
        else {"SELECT *,group_id::text AS group_text, (extract(epoch FROM completed_at-created_at)*1000000)::bigint AS duration FROM mdm_group.operations WHERE tenant_id=$1::uuid AND id=$2::uuid"};
        sqlx::query(query).bind(tenant).bind(id.to_string()).fetch_optional(c).await
    })).await?;
    let op = row.map(|r| stored_operation(id, r)).transpose()?;
    if let Some(op) = &op {
        let hash = match op.kind.as_str() {
            "command" => fingerprint(&[
                tenant_id.to_string().as_bytes(),
                &op.as_of.to_be_bytes(),
                &op.request,
            ]),
            "recalculation" => crate::runs::run_digest(
                tenant_id,
                op.group,
                op.base,
                op.rule_version.as_deref().ok_or_else(stored_shape)?,
                op.as_of,
                op.trigger.as_deref().ok_or_else(stored_shape)?,
                &op.request,
            ),
            _ => return Err(stored_shape()),
        };
        if op.digest != hash {
            return Err(StorageFault::DocumentDigest.error());
        }
        if let RunState::Completed(r) = &op.state
            && (r.operation != id
                || r.group.id != op.group
                || r.group.member_count > rss_mdm_group::limits::OBJECTS
                || r.group.member_version < 0
                || r.group.member_version > r.group.revision.get())
        {
            return Err(stored_shape());
        }
    }
    Ok(op)
}
fn stored_operation(id: OperationId, r: PgRow) -> Result<StoredOperation, PgError> {
    let state = match r.try_get::<&str, _>("state")? {
        "pending" => RunState::Pending,
        "completed" => RunState::Completed(data(codec::decode(r.try_get::<&[u8], _>("receipt")?))?),
        "rejected" => RunState::Rejected(data(serde_json::from_str(
            r.try_get::<&str, _>("failure")?,
        ))?),
        _ => return Err(stored_shape()),
    };
    let result: Option<Vec<u8>> = r.try_get("result")?;
    if let Some(bytes) = &result {
        document(bytes, r.try_get::<&[u8], _>("result_digest")?)?;
    }
    Ok(StoredOperation {
        id,
        group: data(GroupId::parse(r.try_get::<&str, _>("group_text")?))?,
        kind: r.try_get("kind")?,
        digest: r.try_get("digest")?,
        request: r.try_get("request")?,
        trigger: r.try_get("trigger")?,
        state,
        base: r.try_get("base_revision")?,
        rule_version: r.try_get("rule_version")?,
        as_of: r.try_get("as_of")?,
        result,
        duration: r.try_get("duration")?,
    })
}
pub(crate) struct NewOperation {
    pub id: OperationId,
    pub group: GroupId,
    pub digest: Vec<u8>,
    pub request: Vec<u8>,
    pub trigger: Option<Vec<u8>>,
    pub base: i64,
    pub rule_version: Option<String>,
    pub as_of: i64,
    pub receipt: Option<Receipt>,
}
pub(crate) async fn insert_operation(
    tx: &mut PgTransaction<'_>,
    op: NewOperation,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let receipt = op
        .receipt
        .as_ref()
        .map(codec::encode)
        .transpose()
        .map_err(|_| stored_shape())?;
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_group.operations(tenant_id,id,group_id,kind,digest,request,trigger,state,receipt,base_revision,rule_version,as_of,completed_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $8='completed' THEN clock_timestamp() ELSE NULL END)")
        .bind(tenant).bind(op.id.to_string()).bind(op.group.to_string()).bind(if op.trigger.is_some() {"recalculation"}else{"command"})
        .bind(op.digest).bind(op.request).bind(op.trigger).bind(if receipt.is_some() {"completed"}else{"pending"}).bind(receipt).bind(op.base).bind(op.rule_version).bind(op.as_of).execute(c).await?;
        Ok(())
    })).await
}
pub(crate) async fn complete(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    state: &RunState,
    result: Option<Vec<u8>>,
) -> Result<(), PgError> {
    let (status, receipt, failure) = match state {
        RunState::Completed(r) => ("completed", Some(data(codec::encode(r))?), None),
        RunState::Rejected(r) => ("rejected", None, Some(data(serde_json::to_string(r))?)),
        RunState::Pending => return Err(stored_shape()),
    };
    let tenant = tx.tenant_id().to_string();
    let hash = result.as_ref().map(|b| digest(b));
    let n=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("UPDATE mdm_group.operations SET state=$3,receipt=$4,failure=$5,result=$6,result_digest=$7,completed_at=clock_timestamp() WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending'")
        .bind(tenant).bind(id.to_string()).bind(status).bind(receipt).bind(failure).bind(result).bind(hash).execute(c).await.map(|r|r.rows_affected())
    })).await?;
    if n != 1 {
        return Err(StorageFault::RowCount.error());
    }
    Ok(())
}
pub(crate) async fn apply_delta(
    tx: &mut PgTransaction<'_>,
    group: GroupId,
    op: OperationId,
    added: &[ObjectKey],
    removed: &[ObjectKey],
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let changes: Vec<_> = added
        .iter()
        .map(|k| (k.id().to_string(), true))
        .chain(removed.iter().map(|k| (k.id().to_string(), false)))
        .collect();
    let valid=tx.with_connection(move |c|Box::pin(async move {
        for (id,added) in changes {
            let hash=digest(id.as_bytes());
            let q=if added {"INSERT INTO mdm_group.members(tenant_id,group_id,object_id,object_digest) VALUES($1::uuid,$2::uuid,$3,$4)"}
            else {"DELETE FROM mdm_group.members WHERE tenant_id=$1::uuid AND group_id=$2::uuid AND object_id=$3 AND object_digest=$4"};
            if sqlx::query(q).bind(&tenant).bind(group.to_string()).bind(&id).bind(&hash).execute(&mut *c).await?.rows_affected()!=1 {return Ok(false);}
            sqlx::query("INSERT INTO mdm_group.deltas(tenant_id,operation_id,object_id,object_digest,added) VALUES($1::uuid,$2::uuid,$3,$4,$5)")
            .bind(&tenant).bind(op.to_string()).bind(id).bind(hash).bind(added).execute(&mut *c).await?;
        } Ok(true)
    })).await?;
    if !valid {
        return Err(StorageFault::RowCount.error());
    }
    Ok(())
}
