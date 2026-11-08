//! Software owns removal Runs and installation-effect barriers during accepted Device cleanup.
use super::*;
use crate::deployment::actions::storage::agent_profile_in;
use crate::deployment::*;
use sqlx::Row;
impl Transactions {
    pub async fn prior_agent_installations_removed_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        channel: &Channel,
    ) -> Result<bool> {
        let context = context_in(self.lifecycle.clone(), tx, id).await?;
        if context
            .target
            .members
            .iter()
            .any(|m| m.channel == rss_mdm_inventory::Channel::Agent)
        {
            return Ok(true);
        }
        let tenant = tx.tenant_id();
        let t = tenant.to_string();
        let registration = channel.device.clone();
        let value = registration.clone();
        let installations:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT o.id FROM mdm_software_deployment.operations AS o INNER JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.authority ->> 'kind' = 'agent_install' AND d.status = 'applied' ORDER BY o.id LIMIT 129")
                .bind(t).bind(&value).fetch_all(c).await
        })).await?;
        if installations.len() > 128 {
            return self
                .block_retirement_cleanup(tx, id, registration, "agent_installation_history_limit")
                .await;
        }
        for execution in installations {
            let operation =
                crate::deployment::storage::load(tx, &self.protection, execution).await?;
            let observation = crate::deployment::native_installation::installation_observation(
                self.inventory.clone(),
                tx,
                self.windows_results.clone(),
                self.apple_results.clone(),
                self.agent_store.clone(),
                &operation,
            )
            .await?;
            // Only the installation owner's correlated post-dispatch observation
            // can prove absence. Bootstrap removal is not program removal.
            if observation["installation"] == "absent" {
                continue;
            }
            let lifecycle = self.lifecycle.clone();
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(lifecycle
                        .blocked_on(
                            c,
                            tenant,
                            id,
                            registration.clone(),
                            "agent_installation_removal_unavailable",
                            Some(execution),
                            false,
                        )
                        .await)
                })
            })
            .await??;
            return Ok(false);
        }
        Ok(true)
    }
    #[expect(
        clippy::cognitive_complexity,
        reason = "retirement preserves unknown effects and original delivery state while fencing new work"
    )]
    pub async fn cleanup_software_retirement_in(
        &self,
        tx: &mut PgTransaction<'_>,
        retirement: Uuid,
        channel: &Channel,
    ) -> Result<bool> {
        use crate::deployment::actions::{production, storage as runs};

        use rss_mdm_task_state::Execution;
        let rows = cleanup_candidates(tx, channel.device.clone()).await?;
        let tenant = tx.tenant_id();
        let registration = channel.device.clone();
        if rows.len() > 128 {
            return self
                .block_retirement_cleanup(tx, retirement, registration, "software_cleanup_limit")
                .await;
        }
        let target = Target {
            device: channel.device.clone(),
        };
        let lifecycle = self.lifecycle.clone();
        let origin = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(lifecycle
                        .context_on(c, tenant, retirement)
                        .await
                        .map(|r| r.origin))
                })
            })
            .await??;
        let mut complete = true;
        for row in rows {
            let effect: serde_json::Value = row.try_get("software_effect")?;
            let result: serde_json::Value = row.try_get("result")?;
            if result["effect"] != "verified" {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration.clone(),
                        "software_effect_unconfirmed",
                    )
                    .await;
            }
            if effect["intent"] == "uninstall" {
                continue;
            }
            let original: Uuid = row.try_get("id")?;
            let version: Uuid = row.try_get("policy_version")?;
            let id = cleanup_run_id(tenant, retirement, original)?;
            let t = tenant.to_string();
            let exists:bool=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(t).bind(id).fetch_one(c).await
            })).await?;
            if exists {
                let run = runs::load_run(tx, id).await?;
                if run.state.execution == Execution::Succeeded
                    && run
                        .result
                        .as_ref()
                        .is_some_and(|v| v.effect() == Some("verified"))
                {
                    continue;
                }
                let now = crate::deployment::storage::now(tx).await?;
                let reason = if delivery_ended(&run.state, now) {
                    Some("software_removal_not_started")
                } else if matches!(run.state.execution, Execution::Failed | Execution::Unknown) {
                    Some("software_removal_unconfirmed")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let unknown = run.state.execution == Execution::Unknown;
                    let lifecycle = self.lifecycle.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(lifecycle
                                .blocked_on(
                                    c,
                                    tenant,
                                    retirement,
                                    registration.clone(),
                                    reason,
                                    Some(id),
                                    unknown,
                                )
                                .await)
                        })
                    })
                    .await??;
                    return Ok(false);
                }
                complete = false;
                continue;
            }
            let software =
                crate::deployment::sources::software::retirement_in(self, tx, version, retirement)
                    .await?;
            let Some(binding) = crate::deployment::agent_facts::agent_binding_in(
                tx,
                self.agent_store.clone(),
                registration.clone(),
            )
            .await?
            else {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration.clone(),
                        "agent_binding_unavailable",
                    )
                    .await;
            };
            if !software
                .assignment
                .supported_in(&self.admission(), tx, &binding)
                .await?
            {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration.clone(),
                        "software_removal_unsupported",
                    )
                    .await;
            }
            let Some((platform, architecture)) =
                agent_profile_in(self, tx, registration.clone()).await?
            else {
                return Err(Error::Conflict.into());
            };
            let steps = software
                .assignment
                .prepared_in(
                    &self.admission(),
                    tx,
                    platform,
                    architecture,
                    &binding.execution_context,
                )
                .await?
                .ok_or(Error::Unsupported)?;
            if steps.iter().any(|s| !s.action.behavior.supports_removal()) {
                return self
                    .block_retirement_cleanup(
                        tx,
                        retirement,
                        registration.clone(),
                        "software_removal_unsupported",
                    )
                    .await;
            }
            let effect = crate::deployment::actions::software::effect_key(&software, &steps)?;
            let lifecycle = self.lifecycle.clone();
            let value = registration.clone();
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(lifecycle
                        .authorize_on(c, tenant, retirement, value, id)
                        .await)
                })
            })
            .await??;
            let now = crate::deployment::storage::now(tx).await?;
            production::queue_run_in(
                self,
                tx,
                production::RunInput {
                    request: None,
                    origin,
                    invocation: None,
                    source: runs::Source::RetirementSoftware {
                        version,
                        retirement,
                    },
                    target: &target,
                    id,
                    occurrence: format!("retirement:{retirement}:{original}"),
                    available: now,
                    deadline: now + i64::from(software.assignment.frozen.run_lifetime_seconds),
                    now,
                },
            )
            .await?;
            crate::deployment::actions::software::persist_effect_in(tx, id, &effect).await?;
            complete = false;
        }
        Ok(complete)
    }
    async fn block_retirement_cleanup(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        registration: String,
        reason: &'static str,
    ) -> Result<bool> {
        let tenant = tx.tenant_id();
        let lifecycle = self.lifecycle.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(lifecycle
                    .blocked_on(c, tenant, id, registration, reason, None, false)
                    .await)
            })
        })
        .await??;
        Ok(false)
    }
}
fn delivery_ended(state: &rss_mdm_task_state::RunState, now: i64) -> bool {
    use rss_mdm_task_state::{Cancellation, Execution};
    state.execution == Execution::NotStarted
        && (state.cancellation != Cancellation::None || now >= state.deadline)
}
async fn cleanup_candidates(
    tx: &mut PgTransaction<'_>,
    registration: String,
) -> Result<Vec<sqlx::postgres::PgRow>> {
    let t = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("SELECT DISTINCT ON (software_effect -> 'resource', software_effect -> 'target') id, policy_version, software_effect, result FROM mdm_software_deployment.action_runs WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND software_effect IS NOT NULL AND result ->> 'effect' IN ('verified', 'failed') ORDER BY software_effect -> 'resource', software_effect -> 'target', CAST(result ->> 'effectObservedAt' AS bigint) DESC NULLS LAST, CAST(result ->> 'effectReceivedAt' AS bigint) DESC NULLS LAST, created_at DESC, id DESC LIMIT 129")
                .bind(t).bind(&registration).fetch_all(c).await
        })).await?;
    Ok(rows)
}
fn cleanup_run_id(
    tenant: rss_request_context::TenantId,
    retirement: Uuid,
    original: Uuid,
) -> Result<Uuid> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(checked_input(serde_json::to_vec(&(
        tenant.to_string(),
        retirement,
        original,
    )))?);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    Ok(Uuid::from_bytes(bytes))
}
