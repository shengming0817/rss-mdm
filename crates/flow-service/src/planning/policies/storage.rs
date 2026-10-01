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
    Ok(
        json!({"id":policy.id,"revision":policy.revision,"version":policy.number,"versionId":policy.version,"enabled":policy.enabled,"definition":policy.definition}),
    )
}
pub async fn write_in(
    store: &rss_mdm_policy_postgres::PolicyStore,
    tx: &mut PgTransaction<'_>,
    p: &Policy,
    frozen: Option<(&Frozen, &Vec<u8>)>,
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
    let publication = rss_mdm_policy_postgres::Publication {
        policy: p.clone(),
        frozen: frozen
            .map(|(value, _)| checked_input(serde_json::to_value(value)))
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
    if matches!(
        policy.definition.action,
        Action::Configuration { .. } | Action::EnsureAgentInstalled { .. }
    ) || old.is_some_and(|p| {
        matches!(
            p.definition.action,
            Action::Configuration { .. } | Action::EnsureAgentInstalled { .. }
        )
    }) {
        crate::automation::jobs::enqueue_job_in(
            tx,
            Uuid::new_v4(),
            &crate::automation::JobInput::PolicyReconcile { policy: policy.id },
        )
        .await?;
    }
    // Native templates reuse this Policy recovery owner for due reads and pending-run recovery.
    if old.is_some() || matches!(policy.definition.action, Action::NativeCollection { .. }) {
        wake_execution_in(tx, policy.id).await?;
    }
    Ok(())
}
pub async fn wake_execution_in(tx: &mut PgTransaction<'_>, policy: Uuid) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::execution::recovery_scope(tx.tenant_id()),
        format!("policy.{policy}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
pub async fn version_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<(Policy, Frozen)> {
    let version = checked(reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let owner = read_in(reader, tx, version.policy)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((owner, stored(serde_json::from_value(version.frozen))?))
}
/// A fresh eligible source plus its stable membership-entry coordinate.
pub async fn eligible_in(
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &str,
) -> Result<Option<i64>> {
    if !policy.enabled {
        return Ok(None);
    }
    let scope = policy.definition.scope;
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT (mdm_planning.scope_admission($1,$2)->>'entry')::bigint")
                    .bind(scope)
                    .bind(device)
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}

pub async fn withdrawn_in(
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &str,
) -> Result<bool> {
    if !policy.enabled {
        return Ok(true);
    }
    let scope = policy.definition.scope;
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT mdm_planning.scope_admission($1,$2)->>'state'='excluded'",
                )
                .bind(scope)
                .bind(device)
                .fetch_one(c)
                .await
            })
        })
        .await?)
}
