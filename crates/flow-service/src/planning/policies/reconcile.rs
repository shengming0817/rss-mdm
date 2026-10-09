use super::*;
impl super::super::Planning {
    pub async fn advance_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        policy: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let Some(p) = storage::read_in(self.policy_store.reader(), tx, policy).await? else {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        };
        use rss_mdm_execution_service::source_authority::{Availability, SourceAuthority};
        let channel =
            rss_mdm_execution_service::source_authority::action_channel(p.definition.action.kind());
        let source = crate::planning::execution_source::ExecutionSource;
        let tenant = tx.tenant_id();
        let scope = p.definition.scope;
        let mut assignments = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(source
                        .assignment_objects_on(c, tenant, scope, channel, after.as_deref())
                        .await)
                })
            })
            .await?
            .map_err(rss_mdm_execution_service::Error::from)?;
        let reader = crate::planning::execution_source::ExecutionSource;
        let version = p.version;
        let readable = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(reader.policy_readable_on(c, tenant, version).await) })
            })
            .await?
            .map_err(rss_mdm_execution_service::Error::from)?;
        let more = assignments.len() > 64;
        assignments.truncate(64);
        let mut devices = Vec::new();
        let mut keys = Vec::new();
        for mut assignment in assignments {
            keys.push(assignment.object.key());
            if !readable {
                assignment.availability = Availability::Unavailable;
                assignment.reason = Some("source_forbidden".into());
            }
            if !p.enabled {
                assignment.availability = Availability::Unavailable;
                assignment.reason = Some("policy_disabled".into());
            }
            let input = checked_input(serde_json::to_value(&assignment))?;
            let tenant = tenant.to_string();
            let policy = p.id;
            let version = p.version;
            let key = assignment.object.key();
            let channel = channel.as_str();
            let reason = assignment.reason.clone();
            let available = assignment.availability == Availability::Ready;
            let target = assignment
                .target
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| Error::Malformed)?;
            let run = assignment.scope_result;
            let entry = match assignment.admission {
                rss_mdm_execution_service::source_authority::ScopeAdmission::Eligible { entry } => {
                    entry
                }
                _ => 0,
            };
            let excluded = assignment.admission
                == rss_mdm_execution_service::source_authority::ScopeAdmission::Excluded;
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_planning.policy_assignments(tenant_id,policy,version,object,channel,input,availability,reason,target,scope_result,entry_revision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id,policy,version,object,channel) DO UPDATE SET input=EXCLUDED.input,availability=EXCLUDED.availability,reason=EXCLUDED.reason,target=EXCLUDED.target,scope_result=EXCLUDED.scope_result,entry_revision=CASE WHEN $12 THEN 0 WHEN mdm_planning.policy_assignments.target IS DISTINCT FROM EXCLUDED.target THEN EXCLUDED.entry_revision ELSE greatest(mdm_planning.policy_assignments.entry_revision,CASE WHEN mdm_planning.policy_assignments.entry_revision=0 THEN EXCLUDED.entry_revision ELSE 0 END) END").bind(tenant).bind(policy).bind(version).bind(key).bind(channel).bind(input).bind(if available {"ready"}else{"unavailable"}).bind(reason).bind(target).bind(run).bind(entry).bind(excluded).execute(c).await?;Ok(())})).await?;
            if let Some(target) = assignment.target {
                devices.push(target.device);
            }
        }
        devices.sort();
        devices.dedup();
        for device in &devices {
            rss_mdm_execution_service::wake::wake_native_in(
                std::sync::Arc::new(crate::planning::execution_source::ExecutionSource),
                tx,
                device,
            )
            .await?;
        }
        // Removed source objects remain inspectable as unavailable; existing operation targets are immutable.
        let tenant = tenant.to_string();
        let policy = p.id;
        let version = p.version;
        let scope = p.definition.scope;
        let removed=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<String>>("UPDATE mdm_planning.policy_assignments a SET input=jsonb_set(jsonb_set(jsonb_set(a.input,'{availability}','\"unavailable\"'),'{reason}','\"source_removed\"'),'{admission}','{\"state\":\"excluded\"}'),availability='unavailable',reason='source_removed',entry_revision=0 WHERE a.tenant_id=$1::uuid AND a.policy=$2 AND a.version=$3 AND NOT EXISTS(SELECT 1 FROM mdm_planning.scopes s JOIN mdm_planning.scope_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=a.tenant_id AND s.id=$4 AND r.device=a.object) AND a.reason IS DISTINCT FROM 'source_removed' RETURNING target->>'device'").bind(tenant).bind(policy).bind(version).bind(scope).fetch_all(c).await})).await?;
        for device in removed.into_iter().flatten() {
            rss_mdm_execution_service::wake::wake_native_in(
                std::sync::Arc::new(crate::planning::execution_source::ExecutionSource),
                tx,
                &device,
            )
            .await?;
        }
        if more {
            {
                let tenant = tx.tenant_id().to_string();
                let next = keys.last().cloned();
                tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
                Ok(())
            }
        } else {
            crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await
        }
    }
}
