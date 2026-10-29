use super::*;

pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    checked(reader.locked_in(tx, id).await?)
}
pub fn view(policy: &Policy) -> rss_mdm_policy::View {
    rss_mdm_policy::View::from(policy)
}
pub(super) async fn write_in(
    service: &Policies,
    tx: &mut PgTransaction<'_>,
    p: &Policy,
    change: &Change,
    frozen: Option<&Value>,
    proof: &AuthorizedPrincipal,
    now: i64,
) -> Result<()> {
    if !matches!(change, Change::Archive) {
        let mut targets = vec![p.definition.scope];
        if let Action::Software { rollout, .. } = &p.definition.action {
            targets.extend(rollout.stages.iter().map(|s| s.scope));
        }
        service
            .scopes
            .lock_references_in(tx, &targets)
            .await
            .map_err(|e| match e {
                rss_mdm_scope_postgres::BindingError::Storage(e) => Fault::Storage(e),
                rss_mdm_scope_postgres::BindingError::Missing => Error::NotFound.into(),
                rss_mdm_scope_postgres::BindingError::TenantMismatch => Error::Forbidden.into(),
                _ => Error::Conflict.into(),
            })?;
        if let Some(config) = &p.definition.self_service {
            rss_mdm_execution_service::self_service::validate_access(
                config,
                proof.tenant_id(),
                proof.instance_id(),
            )?;
        }
    }
    let publication = rss_mdm_policy_postgres::Publication {
        change: change.clone(),
        policy: p.clone(),
        frozen: frozen
            .map(|value| checked_input(serde_json::to_value(value)))
            .transpose()?,
        author: checked_input(serde_json::to_value(proof.actor()))?,
        at: now,
    };
    checked(service.policy_store.publish_in(tx, &publication).await?)?;
    Ok(())
}
pub async fn enqueue_change_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    old: Option<&Policy>,
) -> Result<()> {
    crate::worker::jobs::enqueue_job_in(
        tx,
        Uuid::new_v4(),
        &crate::worker::Work::PolicyReconcile { policy: policy.id },
    )
    .await?;
    // Software statistics also need this owner before any execution exists.
    if old.is_some()
        || policy.definition.action.kind() == rss_mdm_policy::ActionKind::Software
        || policy.definition.action.assignment_behavior()
            == rss_mdm_policy::AssignmentBehavior::NativeCollectionRecovery
    {
        rss_mdm_execution_service::sources::storage::wake_execution_in(reconcile, tx, policy.id)
            .await?;
    }
    Ok(())
}
