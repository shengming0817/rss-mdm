use super::support::{at, tenant};
use rss_mdm_policy_postgres::{
    PolicyStore, Publication,
    core::{Change, Definition, Policy},
};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgRuntime;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub fn definition() -> Definition {
    serde_json::from_value(json!({"resource":{"id":"resource","version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"targets":{"kind":"devices","devices":[]},"behavior":{"kind":"configuration","exit":"retain"}})).unwrap()
}
pub fn publication(id: Uuid, old: Option<&Policy>, change: Change) -> Publication {
    let changed = Policy::apply(
        id,
        old,
        old.map_or(0, |p| p.revision as u64),
        &change,
        Uuid::new_v4(),
    )
    .unwrap();
    Publication {
        policy: changed.policy,
        frozen: changed
            .semantic_changed
            .then(|| json!({"resourceDigest":[1,2,3],"configuration":true})),
        author: json!({"subject":"fixture"}),
        at: at(10).unix_seconds(),
    }
}
pub async fn execute(
    runtime: &PgRuntime,
    store: &PolicyStore,
    op: Uuid,
    input: &Publication,
    budget: OperationDeadline,
) -> Result<Value, rss_mdm_policy_postgres::Error> {
    let hash = Sha256::digest(
        serde_json::to_vec(&(&input.policy, &input.frozen, &input.author, input.at)).unwrap(),
    )
    .to_vec();
    runtime
        .local_tx_with_context(tenant(), budget, (store, input, hash), |ctx, tx| {
            Box::pin(async move {
                if let Some(value) = match ctx.0.replay_in(tx, op, &ctx.2).await? {
                    Ok(v) => v,
                    Err(e) => return Ok(Err(e)),
                } {
                    return Ok(Ok(value));
                }
                if let Err(e) = ctx.0.publish_in(tx, ctx.1).await? {
                    return Ok(Err(e));
                }
                let value = serde_json::to_value(&ctx.1.policy).unwrap();
                if let Err(e) = ctx.0.receipt_in(tx, op, &ctx.2, &value).await? {
                    return Ok(Err(e));
                }
                Ok(Ok(value))
            })
        })
        .await
        .fold(
            |v| v.map_err(rss_mdm_policy_postgres::Error::Rejected),
            |e| Err(rss_mdm_policy_postgres::Error::NotStarted(e)),
            |e| Err(rss_mdm_policy_postgres::Error::RolledBack(e)),
            |e| Err(rss_mdm_policy_postgres::Error::RollbackFailed(e)),
            |e| Err(rss_mdm_policy_postgres::Error::CommitUnknown(e)),
            |e| Err(rss_mdm_policy_postgres::Error::Fenced(e)),
        )
}
