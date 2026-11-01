//! One immutable credential policy plus current authority and Scope evidence.
use super::*;
use rss_mdm_policy::{Frequency, Policy};
use rss_mdm_registration_service::participants::scope::{Channel, ScopeAdmission, Sources};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecutionInput {
    pub platform: rss_mdm_policy::Platform,
    pub architecture: rss_mdm_policy::Architecture,
    pub schedule: rss_mdm_policy::schedule::Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    Credential {
        action: Box<super::credential_tasks::FrozenCredential>,
        frequency: Frequency,
    },
}
pub struct CredentialPolicy {
    pub id: Uuid,
    pub owner: Uuid,
    pub frozen: super::credential_tasks::FrozenCredential,
    pub frequency: Frequency,
    pub active: bool,
    pub policy: Policy,
}
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<CredentialPolicy> {
    let v = transaction::checked(reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let policy =
        transaction::checked(reader.locked_in(tx, v.policy).await?)?.ok_or(Error::NotFound)?;
    let Frozen::Credential { action, frequency } = stored(serde_json::from_value(v.frozen))?;
    Ok(CredentialPolicy {
        id,
        owner: policy.id,
        frozen: *action,
        frequency,
        active: policy.state.is_enabled(),
        policy,
    })
}
impl CredentialPolicy {
    pub fn entry_source(&self) -> String {
        format!("scope:{}", self.policy.definition.scope)
    }
    pub async fn entry_in(
        &self,
        source: &Arc<dyn Sources>,
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
        let source = source.clone();
        let tenant = tx.tenant_id();
        let device = device.to_owned();
        let scope = self.policy.definition.scope;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    if !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        c,
                        &tenant.to_string(),
                        &device,
                    )
                    .await?
                    {
                        return Ok(None);
                    }
                    Ok(
                        match source
                            .admission_on(c, tenant, scope, Channel::Agent, &device)
                            .await?
                        {
                            ScopeAdmission::Eligible { entry } => Some(entry),
                            _ => None,
                        },
                    )
                }
                .await)
            })
        })
        .await?
    }
    pub async fn authorized_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(self.run_admission_in(service, tx, target, now).await?
            && self
                .entry_in(&service.source, tx, &target.device, now)
                .await?
                .is_some())
    }
    pub async fn run_admission_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(self.active
            && self.frozen.authorized_in(service, tx, target, now).await?
            && super::credential_tasks::eligible(
                service,
                tx,
                target,
                self.frozen.input.architecture,
            )
            .await?)
    }
    pub async fn authorized_run_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        run: &storage::Run,
        now: i64,
    ) -> Result<bool> {
        if run.state.started_at.is_none() {
            let source = service.source.clone();
            let tenant = tx.tenant_id();
            let device = run.target.device.clone();
            let evidence = run.source_objects.clone();
            if !tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(source
                            .evidence_valid_on(c, tenant, Channel::Agent, &device, &evidence)
                            .await)
                    })
                })
                .await??
            {
                return Ok(false);
            }
        }
        self.run_admission_in(service, tx, &run.target, now).await
    }
    pub async fn completion_authorized_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(self.active && self.frozen.authorized_in(service, tx, target, now).await?)
    }
    pub async fn withdrawn_in(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        Ok(!self.active || !self.frozen.authorized_in(service, tx, target, now).await?)
    }
    pub async fn task(
        &self,
        service: &Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        issue: storage::TaskIssue,
    ) -> Result<rss_mdm_agent_wire::runtime::TaskPayload> {
        super::credential_tasks::task(self, service, tx, target, issue).await
    }
}
use sqlx::Row;
/// Persisted round-robin cursor prevents a bounded policy page starving later assignments.
pub async fn agent_versions_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Vec<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let kinds = vec!["credential"];
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_recovery_tasks.agent_admission(tenant_id,registration) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration.to_string()).execute(&mut *c).await?;
        let after=sqlx::query_scalar::<_,Option<Uuid>>("SELECT policy_after FROM mdm_recovery_tasks.agent_admission WHERE tenant_id=$1::uuid AND registration=$2::uuid FOR UPDATE").bind(&tenant).bind(registration.to_string()).fetch_one(&mut *c).await?;
        let rows=sqlx::query("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND definition->'action'->>'kind' =ANY($3) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64").bind(&tenant).bind(after).bind(kinds).fetch_all(&mut *c).await?;
        let next=if rows.len()==64 {rows.last().map(|r|r.try_get::<Uuid,_>("id")).transpose()?} else {None};
        sqlx::query("UPDATE mdm_recovery_tasks.agent_admission SET policy_after=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).bind(next).execute(c).await?;
        rows.into_iter().map(|r|r.try_get::<Uuid,_>("current_version")).collect::<std::result::Result<Vec<_>,sqlx::Error>>()
    })).await?;
    Ok(ids)
}
