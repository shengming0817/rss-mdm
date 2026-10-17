//! Read-only bridge from a published Policy version to Agent execution.
use super::*;
use crate::action_contract::ScheduledInput;
pub struct ExecutionPolicy<T = FrozenAction> {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: T,
    pub frequency: Frequency,
    pub active: bool,
    policy: Policy,
}
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ExecutionPolicy> {
    let (policy, frozen) = storage::version_in(reader, tx, id).await?;
    let Frozen::Execution { action, frequency } = frozen else {
        return Err(Error::Unsupported.into());
    };
    Ok(ExecutionPolicy {
        id,
        owner: policy.id,
        active: policy.state.is_enabled() && policy.version == id,
        frozen: *action,
        frequency,
        policy,
    })
}
impl<T: ScheduledInput> ExecutionPolicy<T> {
    pub fn entry_source(&self) -> String {
        format!("scope:{}", self.policy.definition.scope)
    }

    pub async fn entry_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<Option<i64>> {
        if !self.active
            || now < self.frozen.execution_input().schedule.not_before
            || now >= self.frozen.execution_input().schedule.ends_at()
        {
            return Ok(None);
        }
        storage::eligible_in(source, tx, &self.policy, device).await
    }
    pub async fn withdrawn_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<bool> {
        if !self.active {
            return Ok(true);
        }
        storage::withdrawn_in(source, tx, &self.policy, device).await
    }
    pub async fn authorized_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<bool> {
        Ok(self.entry_in(source, tx, device, now).await?.is_some())
    }
}
/// Persisted round-robin cursor prevents a bounded policy page starving later assignments.
pub async fn agent_versions_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Vec<Uuid>> {
    versions_in(tx, registration, false).await
}
pub async fn native_versions_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Vec<Uuid>> {
    versions_in(tx, registration, true).await
}
async fn versions_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    native: bool,
) -> Result<Vec<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let kinds = if native {
        rss_mdm_policy::AssignmentBehavior::NativeCollectionRecovery
    } else {
        rss_mdm_policy::AssignmentBehavior::AgentCheckIn
    }
    .kinds();
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.action_polls(tenant_id,registration) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration.to_string()).execute(&mut *c).await?;
        let after=sqlx::query_scalar::<_,Option<Uuid>>("SELECT policy_after FROM mdm_commands.action_polls WHERE tenant_id=$1::uuid AND registration=$2::uuid FOR UPDATE").bind(&tenant).bind(registration.to_string()).fetch_one(&mut *c).await?;
        let rows=sqlx::query("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND definition->'action'->>'kind' =ANY($3) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64").bind(&tenant).bind(after).bind(kinds).fetch_all(&mut *c).await?;
        let next=if rows.len()==64 {rows.last().map(|r|r.try_get::<Uuid,_>("id")).transpose()?} else {None};
        sqlx::query("UPDATE mdm_commands.action_polls SET policy_after=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).bind(next).execute(c).await?;
        rows.into_iter().map(|r|r.try_get::<Uuid,_>("current_version")).collect::<std::result::Result<Vec<_>,sqlx::Error>>()
    })).await?;
    Ok(ids)
}

pub async fn native_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ExecutionPolicy<FrozenNativeCollection>> {
    let (policy, frozen) = storage::version_in(reader, tx, id).await?;
    let Frozen::NativeCollection { action, frequency } = frozen else {
        return Err(Error::Unsupported.into());
    };
    Ok(ExecutionPolicy {
        id,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled() && policy.version == id,
        policy,
    })
}
pub async fn agent_collection_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ExecutionPolicy<crate::action_contract::FrozenAgentCollection>> {
    let (policy, frozen) = storage::version_in(reader, tx, id).await?;
    let Frozen::AgentCollection { action, frequency } = frozen else {
        return Err(Error::Unsupported.into());
    };
    Ok(ExecutionPolicy {
        id,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled() && policy.version == id,
        policy,
    })
}

pub async fn credential_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<ExecutionPolicy<crate::credential_tasks::FrozenCredential>> {
    let (policy, frozen) = storage::version_in(reader, tx, id).await?;
    let Frozen::Credential { action, frequency } = frozen else {
        return Err(Error::Unsupported.into());
    };
    Ok(ExecutionPolicy {
        id,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled() && policy.version == id,
        policy,
    })
}
