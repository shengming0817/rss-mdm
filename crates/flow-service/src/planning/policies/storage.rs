use super::*;

pub async fn lock(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    crate::action_admission::lock(tx, &format!("policy:{id}")).await
}
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT mdm_planning.policy_lock($1)")
                .bind(id)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    checked(reader.read_in(tx, id).await?)
}
pub fn view(policy: &Policy) -> Result<Value> {
    checked_input(serde_json::to_value(rss_mdm_policy::View::from(policy)))
}
pub async fn write_in(
    store: &rss_mdm_policy_postgres::PolicyStore,
    tx: &mut PgTransaction<'_>,
    p: &Policy,
    frozen: Option<&Frozen>,
    proof: &AuthorizedPrincipal,
    now: i64,
) -> Result<()> {
    {
        let id = p.definition.scope;
        let tenant = tx.tenant_id().to_string();
        let exists=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT deleted)").bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        if !exists {
            return Err(Error::NotFound.into());
        }
    }
    if let Action::Software { rollout, .. } = &p.definition.action {
        let tenant = tx.tenant_id().to_string();
        let scopes: Vec<Uuid> = rollout.stages.iter().map(|s| s.scope).collect();
        let count: i64 = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT count(*) FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=ANY($2::uuid[]) AND NOT deleted")
                .bind(tenant).bind(scopes).fetch_one(c).await
        })).await?;
        if count != rollout.stages.len() as i64 {
            return Err(Error::NotFound.into());
        }
    }
    if let Some(config) = &p.definition.self_service {
        rss_mdm_execution_service::self_service::validate_access(
            config,
            proof.tenant_id(),
            proof.instance_id(),
        )?;
    }
    let publication = rss_mdm_policy_postgres::Publication {
        policy: p.clone(),
        frozen: frozen
            .map(|value| checked_input(serde_json::to_value(value)))
            .transpose()?,
        author: checked_input(serde_json::to_value(proof.user()))?,
        at: now,
    };
    checked(store.publish_in(tx, &publication).await?)?;
    Ok(())
}
pub async fn enqueue_change_in(
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    old: Option<&Policy>,
) -> Result<()> {
    crate::automation::jobs::enqueue_job_in(
        tx,
        Uuid::new_v4(),
        &crate::automation::JobInput::PolicyReconcile { policy: policy.id },
    )
    .await?;
    // Native templates reuse this Policy recovery owner for due reads and pending-run recovery.
    if old.is_some()
        || policy.definition.action.kind().assignment_behavior()
            == rss_mdm_policy::AssignmentBehavior::NativeCollectionRecovery
    {
        rss_mdm_execution_service::sources::storage::wake_execution_in(tx, policy.id).await?;
    }
    Ok(())
}
