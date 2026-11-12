use super::*;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::Policy;
impl Transactions {
    pub async fn accept_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &crate::events::participants::Target,
        cause: (Uuid, rss_mdm_audit_integration::activity::ActivityOrigin),
        deadline: i64,
        audit: &RequestAudit,
    ) -> Result<wire::PolicyEventDecision> {
        self.runtime.validate_transaction(tx)?;
        let now = storage::now(tx).await?;
        if now >= deadline {
            return Ok(wire::PolicyEventDecision::Expired);
        }
        storage::lock_device(tx, &target.device).await?;
        if policies::eligible_in(&self.source, tx, policy, &target.device)
            .await?
            .is_none()
        {
            return Ok(crate::events::rejected("scope_not_eligible"));
        }
        let tenant = tx.tenant_id().to_string();
        let device = target.device;
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(tenant).bind(device.into_uuid()).execute(c).await?;Ok(())})).await?;
        self.wake_devices_in(tx, std::slice::from_ref(&target.device))
            .await?;
        self.reconcile_configuration_target_in(
            tx,
            &target.device,
            audit,
            Some((policy.id, cause.1)),
        )
        .await?;
        self.configuration_event_result_in(tx, policy, target).await
    }
    pub(crate) async fn configuration_event_result_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        target: &crate::events::participants::Target,
    ) -> Result<wire::PolicyEventDecision> {
        let tenant = tx.tenant_id().to_string();
        let device = target.device;
        let id = policy.id;
        let version = policy.version;
        let rows:Vec<(Option<Uuid>,Option<String>)>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT DISTINCT c.operation,o.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects o USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.device=$2 AND c.policy=$3 AND c.version=$4 LIMIT 1000").bind(tenant).bind(device.into_uuid()).bind(id).bind(version).fetch_all(c).await})).await?;
        if let Some(reason) = rows.iter().find_map(|(_, reason)| reason.as_deref()) {
            return Ok(crate::events::rejected(reason));
        }
        let ids = rows
            .into_iter()
            .filter_map(|(id, _)| id)
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(crate::events::rejected("configuration_not_eligible"));
        }
        let mut applied = true;
        for id in &ids {
            let op = storage::load(tx, &self.protection, *id).await?;
            applied &= self.required_command(tx, &op).await?.status()
                == rss_device_command::Status::Applied;
        }
        Ok(if applied {
            wire::PolicyEventDecision::NoChange {
                reason: "configuration_applied".into(),
            }
        } else {
            wire::PolicyEventDecision::Accepted {
                operations: ids
                    .into_iter()
                    .map(|id| wire::PolicyEventOperation::Native { id })
                    .collect(),
            }
        })
    }
}

impl Transactions {
    pub async fn event_progress_in(
        &self,
        tx: &mut PgTransaction<'_>,
        reference: &wire::PolicyEventOperation,
    ) -> Result<crate::events::participants::EventOperationProgress> {
        let wire::PolicyEventOperation::Native { id } = reference else {
            return Err(Error::Malformed.into());
        };
        let operation = storage::load(tx, &self.protection, *id).await?;
        Ok(
            crate::events::participants::EventOperationProgress::Native {
                reference: reference.clone(),
                state: self.required_command(tx, &operation).await?.status(),
                agent_installation: None,
                allowed_actions: [],
            },
        )
    }
}
