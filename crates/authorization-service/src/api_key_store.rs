use crate::{
    api_key::*,
    context::AuthorizedPrincipal,
    credential::ApiKeySecret,
    database::db,
    operations::{Actor, Operation},
    *,
};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyMutation {
    Create { metadata: KeyMetadata },
    Update { metadata: KeyMetadata },
    Rotate,
    Revoke,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyChange {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    #[serde(flatten)]
    pub mutation: KeyMutation,
}
pub struct KeyChangeResult {
    pub receipt: Receipt,
    pub secret: Option<ApiKeySecret>,
}

pub async fn change_key(
    store: &AuditStore,
    proof: &AuthorizedPrincipal,
    id: Uuid,
    change: KeyChange,
    audit: &RequestAudit,
) -> Result<KeyChangeResult, Error> {
    let creator = proof.user()?;
    proof.require(Permission::AuthorizationWrite, None)?;
    if id.is_nil() || change.operation_id.is_nil() || change.expected_revision >= i64::MAX as u64 {
        return Err(Error::Malformed);
    }
    if let KeyMutation::Create { metadata } | KeyMutation::Update { metadata } = &change.mutation {
        metadata.validate()?;
    }
    let secret = if matches!(
        change.mutation,
        KeyMutation::Create { .. } | KeyMutation::Rotate
    ) {
        Some(ApiKeySecret::generate(id)?)
    } else {
        None
    };
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&("api_key", id, &change)).map_err(|_| Error::Malformed)?
        )
    );
    let operation = Operation {
        actor: Actor::from_authorized(proof),
        key: change.operation_id,
        digest: &digest,
    };
    audit.operation(
        change.operation_id,
        "api_key_change",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&id.to_string());
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        &format!("api_key:{}:{}", proof.principal_id(), change.operation_id),
        digest.as_bytes(),
        200,
        "success",
        None,
    )?;
    let context = KeyWrite {
        proof,
        id,
        change: &change,
        operation: &operation,
        creator: &creator,
        secret: secret.as_ref(),
        audit,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(3));
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &budget.source_control(),
            (store, context, fact),
            |(store, context, fact), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(context, |context, c| {
                            Box::pin(change_on(c, context))
                        })
                        .await?;
                    store
                        .append(tx, fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        context.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    context.audit.mark_commit_started();
                    Ok((receipt, replayed))
                })
            },
        )
        .await;
    let (receipt, replayed) = crate::operations::settle(attempt, audit)?;
    Ok(KeyChangeResult {
        receipt,
        secret: if replayed { None } else { secret },
    })
}
struct KeyWrite<'a> {
    proof: &'a AuthorizedPrincipal,
    id: Uuid,
    change: &'a KeyChange,
    operation: &'a Operation<'a>,
    creator: &'a User,
    secret: Option<&'a ApiKeySecret>,
    audit: &'a RequestAudit,
}
async fn change_on(
    c: &mut sqlx::PgConnection,
    context: &KeyWrite<'_>,
) -> Result<(Receipt, bool), Error> {
    let KeyWrite {
        proof,
        id,
        change,
        operation,
        creator,
        secret,
        audit,
    } = context;
    crate::store::lock(c, proof.tenant_id(), proof.instance_id()).await?;
    let snapshot = crate::snapshot_on(c, proof.tenant_id(), proof.instance_id()).await?;
    snapshot.require(proof, Permission::AuthorizationWrite, None)?;
    if snapshot
        .installation
        .as_ref()
        .ok_or(Error::Corrupt)?
        .is_management(proof.tenant_id())
    {
        return Err(Error::Forbidden);
    }
    if let Some(receipt) = crate::operations::replay(c, operation).await? {
        return Ok((
            serde_json::from_str(&receipt).map_err(|_| Error::Corrupt)?,
            true,
        ));
    }
    let old = snapshot.keys.iter().find(|key| key.id == *id);
    if old.map_or(0, |key| key.revision) != change.expected_revision
        || old.is_some_and(|key| key.revoked)
    {
        return Err(Error::Conflict);
    }
    let revision = change.expected_revision + 1;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    match &change.mutation {
        KeyMutation::Create { metadata } => {
            if old.is_some()
                || snapshot.keys.len() >= 1000
                || metadata.expires_at.is_some_and(|until| until <= now)
            {
                return Err(Error::Conflict);
            }
            sqlx::query("INSERT INTO mdm_access.api_keys(tenant_id,instance,id,revision,authority_revision,credential_revision,metadata,secret_digest,created_by,created_at) VALUES($1::uuid,$2::uuid,$3,1,1,1,$4,$5,$6,$7)")
                .bind(proof.tenant_id()).bind(proof.instance_id()).bind(id).bind(serde_json::to_value(metadata).map_err(|_| Error::Malformed)?)
                .bind(secret.ok_or(Error::Corrupt)?.digest(proof.instance_id(), proof.tenant_id())).bind(serde_json::to_value(creator).map_err(|_| Error::Malformed)?).bind(now)
                .execute(&mut *c).await.map_err(db)?;
        }
        mutation => {
            let old = old.ok_or(Error::Conflict)?;
            let (metadata, authority, credential, revoked) = match mutation {
                KeyMutation::Update { metadata } => {
                    if metadata.expires_at.is_some_and(|until| until <= now) {
                        return Err(Error::Malformed);
                    }
                    let changes_authority = old.metadata.enabled != metadata.enabled
                        || old.metadata.expires_at != metadata.expires_at
                        || old.metadata.grants != metadata.grants;
                    (
                        metadata,
                        old.authority_revision
                            .checked_add(u64::from(changes_authority)),
                        Some(old.credential_revision),
                        false,
                    )
                }
                KeyMutation::Rotate => (
                    &old.metadata,
                    Some(old.authority_revision),
                    old.credential_revision.checked_add(1),
                    false,
                ),
                KeyMutation::Revoke => (
                    &old.metadata,
                    old.authority_revision.checked_add(1),
                    Some(old.credential_revision),
                    true,
                ),
                KeyMutation::Create { .. } => return Err(Error::Conflict),
            };
            let authority =
                i64::try_from(authority.ok_or(Error::Conflict)?).map_err(|_| Error::Conflict)?;
            let credential =
                i64::try_from(credential.ok_or(Error::Conflict)?).map_err(|_| Error::Conflict)?;
            let hash = secret.map(|secret| secret.digest(proof.instance_id(), proof.tenant_id()));
            sqlx::query("UPDATE mdm_access.api_keys SET revision=$4,authority_revision=$5,credential_revision=$6,metadata=$7,secret_digest=coalesce($8,secret_digest),revoked=$9 WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3")
                .bind(proof.tenant_id()).bind(proof.instance_id()).bind(id).bind(revision as i64).bind(authority).bind(credential).bind(serde_json::to_value(metadata).map_err(|_| Error::Malformed)?).bind(hash).bind(revoked)
                .execute(&mut *c).await.map_err(db)?;
        }
    }
    let bounded: bool = sqlx::query_scalar("SELECT coalesce(sum(octet_length(metadata::text)+octet_length(created_by::text)),0)<=2097152 FROM mdm_access.api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid")
        .bind(proof.tenant_id()).bind(proof.instance_id()).fetch_one(&mut *c).await.map_err(db)?;
    if !bounded {
        return Err(Error::Conflict);
    }
    let receipt = Receipt {
        id: *id,
        revision,
        deleted: matches!(change.mutation, KeyMutation::Revoke),
    };
    crate::operations::save(
        c,
        operation,
        &serde_json::to_string(&receipt).map_err(|_| Error::Corrupt)?,
        audit,
    )
    .await?;
    Ok((receipt, false))
}

pub fn list_keys(
    proof: &AuthorizedPrincipal,
    after: Option<Uuid>,
) -> Result<(Vec<KeyRecord>, Option<Uuid>), Error> {
    proof.user()?;
    proof.require(Permission::AuthorizationRead, None)?;
    let mut selected: Vec<_> = proof
        .authorization()?
        .keys
        .iter()
        .filter(|key| after.is_none_or(|after| key.id > after))
        .take(101)
        .cloned()
        .collect();
    let next = (selected.len() > 100).then(|| selected[99].id);
    selected.truncate(100);
    Ok((selected, next))
}
