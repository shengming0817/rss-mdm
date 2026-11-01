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
            super::authorization::validate_access(config, proof.tenant_id(), proof.instance_id())?;
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
    profile: rss_mdm_install_support::StorageProfile,
    changes: &dyn crate::inputs::ExecutionChanges,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    old: Option<&Policy>,
) -> Result<()> {
    crate::worker::jobs::enqueue_job_in(
        profile,
        tx,
        Uuid::new_v4(),
        &crate::worker::Work::PolicyReconcile { policy: policy.id },
    )
    .await?;
    changes.policy_changed_in(tx, policy, old).await?;
    Ok(())
}
