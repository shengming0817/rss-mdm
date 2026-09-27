//! Read-only bridge from a published Policy version to Agent execution.
use super::*;
enum Authority {
    Policy(Policy),
    Remote(crate::planning::remote_operations::Remote),
}
pub(crate) struct ExecutionPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: FrozenAction,
    pub frequency: Frequency,
    pub active: bool,
    authority: Authority,
}
pub(crate) async fn read_in(
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
        active: policy.enabled && policy.version == id,
        frozen: *action,
        frequency,
        authority: Authority::Policy(policy),
    })
}
impl ExecutionPolicy {
    pub(crate) fn entry_source(&self) -> String {
        match &self.authority {
            Authority::Policy(p) => format!("scope:{}", p.definition.scope),
            Authority::Remote(_) => "remote".into(),
        }
    }

    pub(crate) async fn entry_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<Option<i64>> {
        if !self.active
            || now < self.frozen.input.schedule.not_before
            || now >= self.frozen.input.schedule.ends_at()
        {
            return Ok(None);
        }
        match &self.authority {
            Authority::Remote(remote) => Ok(
                crate::planning::remote_operations::storage::allowed_in(tx, remote.id, device, now)
                    .await?
                    .then_some(1),
            ),
            Authority::Policy(policy) => storage::eligible_in(tx, policy, device).await,
        }
    }
    pub(crate) async fn withdrawn_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
    ) -> Result<bool> {
        if !self.active {
            return Ok(true);
        }
        match &self.authority {
            Authority::Remote(remote) => Ok(remote.cancelled),
            Authority::Policy(policy) => storage::withdrawn_in(tx, policy, device).await,
        }
    }
    pub(crate) async fn authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        now: i64,
    ) -> Result<bool> {
        Ok(self.entry_in(tx, device, now).await?.is_some())
    }
}
/// Persisted round-robin cursor prevents a bounded policy page starving later assignments.
pub(crate) async fn agent_versions_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Vec<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.action_polls(tenant_id,registration) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration.to_string()).execute(&mut *c).await?;
        let after=sqlx::query_scalar::<_,Option<Uuid>>("SELECT policy_after FROM mdm_commands.action_polls WHERE tenant_id=$1::uuid AND registration=$2::uuid FOR UPDATE").bind(&tenant).bind(registration.to_string()).fetch_one(&mut *c).await?;
        let rows=sqlx::query("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND enabled AND definition->'behavior'->>'kind' IN ('execution','software') AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64").bind(&tenant).bind(after).fetch_all(&mut *c).await?;
        let next=if rows.len()==64 {rows.last().map(|r|r.try_get::<Uuid,_>("id")).transpose()?} else {None};
        sqlx::query("UPDATE mdm_commands.action_polls SET policy_after=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).bind(next).execute(c).await?;
        rows.into_iter().map(|r|r.try_get::<Uuid,_>("current_version")).collect::<std::result::Result<Vec<_>,sqlx::Error>>()
    })).await?;
    Ok(ids)
}

pub(crate) async fn remote_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<ExecutionPolicy> {
    let remote = crate::planning::remote_operations::storage::read_in(tx, id).await?;
    let Frozen::Execution { action, .. } = remote.frozen.clone() else {
        return Err(Error::Unsupported.into());
    };
    Ok(ExecutionPolicy {
        id,
        owner: id,
        frozen: *action,
        frequency: Frequency::OncePerVersion,
        active: !remote.cancelled,
        authority: Authority::Remote(remote),
    })
}
