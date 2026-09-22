use super::*;
use rss_mdm_policy as p;
use rss_mdm_policy_postgres as pg;
use sqlx::Row;

impl Management {
    pub(in crate::management) async fn start_policy_preview_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &str,
        task: Uuid,
        expected: u64,
        scope: Uuid,
        at: Timepoint,
    ) -> Result<Value> {
        let key = input(p::PolicyId::new(self.tenant, policy))?;
        let state = checked(self.policies.get_in(tx, &key).await?)?
            .ok_or(Error::ManagementNotFound(Missing::Policy))?;
        if state.storage_revision() != expected {
            return Err(Error::Conflict.into());
        }
        self.scope_definition(tx, scope).await?;
        let resolution = Uuid::new_v4();
        self.enqueue_job_in(tx, resolution, &JobInput::Scope { scope })
            .await?;
        self.enqueue_job_in(
            tx,
            task,
            &JobInput::Policy {
                policy: policy.into(),
                scope,
                resolution,
                assignment_revision: None,
                expected_revision: expected,
                as_of: at.unix_seconds(),
            },
        )
        .await
    }

    pub(super) async fn advance_policy_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &JobInput,
    ) -> Result<()> {
        let JobInput::Policy {
            policy,
            scope,
            resolution,
            assignment_revision,
            expected_revision,
            as_of,
        } = job
        else {
            return Err(Error::Malformed.into());
        };
        if let Some(expected) = assignment_revision {
            let tenant = self.tenant.to_string();
            let policy = policy.clone();
            let scope = *scope;
            let current:Option<i64>=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT revision FROM mdm_management.policy_assignments WHERE tenant_id=$1::uuid AND policy=$2 AND scope=$3::uuid")
                    .bind(tenant).bind(policy).bind(scope.to_string()).fetch_optional(c).await
            })).await?;
            if current != Some(*expected) {
                return Err(Error::Conflict.into());
            }
        }
        let tenant = self.tenant.to_string();
        let id = *resolution;
        let resolved=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.phase,r.definition_revision,r.input::text,s.resolution_revision,coalesce(r.result_fingerprint=current.result_fingerprint,false) AS current FROM mdm_management.scope_runs r JOIN mdm_management.scopes s ON (s.tenant_id,s.id)=(r.tenant_id,r.scope) LEFT JOIN mdm_management.scope_runs current ON (current.tenant_id,current.id)=(s.tenant_id,s.resolution) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?;
        let Some(resolved) = resolved else {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        };
        if resolved.try_get::<&str, _>("phase")? != "published" {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        }
        if !resolved.try_get::<bool, _>("current")? {
            return Err(Error::Conflict.into());
        }
        let candidate_id = input(p::RequestId::new(self.tenant, task.to_string()))?;
        let candidate = match self.policies.candidate_in(tx, &candidate_id).await? {
            Ok(c) => c,
            Err(pg::Rejection::NotFound) => {
                let frozen: ScopeInput = stored(serde_json::from_str(resolved.try_get("input")?))?;
                let definition = resolved.try_get::<i64, _>("definition_revision")? as u64;
                let version = resolved.try_get::<i64, _>("resolution_revision")? as u64;
                let mut references = scopes::references(*scope, definition, &frozen);
                references.push(pg::AssignmentReference {
                    id: format!("scope-resolution.{scope}"),
                    revision: version,
                });
                let request = pg::CandidateRequest {
                    id: candidate_id.clone(),
                    policy: input(p::PolicyId::new(self.tenant, policy))?,
                    expected_revision: *expected_revision,
                    targets: input(p::TargetSnapshotId::new(self.tenant, scope.to_string()))?,
                    target_revision: version,
                    references,
                    as_of: input(Timepoint::try_from(*as_of))?,
                };
                checked(self.policies.begin_candidate_in(tx, &request).await?)?
            }
            Err(_) => return Err(Error::Conflict.into()),
        };
        match candidate.phase {
            pg::CandidatePhase::Targets => {
                let tenant = self.tenant.to_string();
                let run = *resolution;
                let after = candidate.target_cursor.clone();
                let mut devices:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query_scalar("SELECT device FROM mdm_management.scope_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND matched AND device>coalesce($3::text,'') COLLATE \"C\" ORDER BY device LIMIT 1001")
                        .bind(tenant).bind(run.to_string()).bind(after).fetch_all(c).await
                })).await?;
                let more = devices.len() > 1000;
                devices.truncate(1000);
                let total = candidate.target_count + devices.len() as u64;
                if !devices.is_empty() {
                    let devices = devices
                        .into_iter()
                        .map(|d| input(p::DeviceId::new(self.tenant, d)))
                        .collect::<Result<Vec<_>>>()?;
                    let after = candidate
                        .target_cursor
                        .map(|d| input(p::DeviceId::new(self.tenant, d)))
                        .transpose()?;
                    checked(
                        self.policies
                            .append_candidate_targets_in(
                                tx,
                                &candidate_id,
                                after.as_ref(),
                                &devices,
                            )
                            .await?,
                    )?;
                }
                if !more {
                    checked(
                        self.policies
                            .seal_candidate_targets_in(tx, &candidate_id, total)
                            .await?,
                    )?;
                }
                Ok(())
            }
            pg::CandidatePhase::Facts => {
                checked(
                    self.policies
                        .advance_candidate_facts_in(tx, &candidate_id)
                        .await?,
                )?;
                Ok(())
            }
            pg::CandidatePhase::Ready | pg::CandidatePhase::Saved => {
                let tenant = self.tenant.to_string();
                let policy = policy.clone();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("UPDATE mdm_management.candidate_heads SET candidate=$3::uuid WHERE tenant_id=$1::uuid AND policy=$2 AND desired=$3::uuid")
                        .bind(tenant).bind(policy).bind(task.to_string()).execute(c).await?;Ok(())
                })).await?;
                self.finish_job_in(tx, task, None).await
            }
            pg::CandidatePhase::Superseded => {
                self.finish_job_in(tx, task, Some("superseded")).await
            }
        }
    }

    pub(in crate::management) async fn save_ready_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &str,
        request: &Operation<SavePlan>,
        at: Timepoint,
    ) -> Result<Value> {
        let (job, complete, failure, _, _) = self.job_in(tx, request.input.preview).await?;
        let JobInput::Policy {
            policy: owner,
            scope,
            resolution,
            ..
        } = job
        else {
            return Err(Error::Conflict.into());
        };
        if owner != policy || !complete || failure.is_some() {
            return Err(Error::Conflict.into());
        }
        if !self.scope_authority_current_in(tx, resolution).await? {
            return Err(Error::Conflict.into());
        }
        let candidate = input(p::RequestId::new(
            self.tenant,
            request.input.preview.to_string(),
        ))?;
        let operation = input(p::RequestId::new(
            self.tenant,
            request.operation_id.to_string(),
        ))?;
        let receipt = checked(
            self.policies
                .save_candidate_in(tx, &operation, &candidate, request.expected_revision, at)
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let policy = policy.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.policy_assignments VALUES($1::uuid,$2,$3::uuid,1) ON CONFLICT(tenant_id,policy) DO UPDATE SET scope=excluded.scope,revision=mdm_management.policy_assignments.revision+1")
                .bind(tenant).bind(policy).bind(scope.to_string()).execute(c).await?;Ok(())
        })).await?;
        Ok(
            serde_json::json!({"receipt":receipt,"preview":request.input.preview,"plan":receipt.plan_id,"dispatch":"not_requested"}),
        )
    }
}
