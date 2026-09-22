//! Immutable, paged candidates. Saving is an explicit pointer installation, never execution admission.
use crate::{PolicyStore, STORAGE, codec, core::*, error::*, model::*};
use rss_contract::Timepoint;
use rss_mdm_backend_postgres_support::digest;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::{Value, json};
use sqlx::Row;

/// Frozen planning preconditions; the product authorizes and resolves sources.
#[derive(Clone, Debug)]
pub struct CandidateRequest {
    /// Idempotency identity, also used to read the candidate.
    pub id: RequestId,
    /// Owning policy.
    pub policy: PolicyId,
    /// Aggregate revision covering lifecycle and execution facts.
    pub expected_revision: u64,
    /// Immutable target source identity.
    pub targets: TargetSnapshotId,
    /// Immutable target source revision.
    pub target_revision: u64,
    /// Exact source versions registered with the Policy adapter.
    pub references: Vec<AssignmentReference>,
    /// Provenance time; never an expiration time.
    pub as_of: Timepoint,
}
impl CandidateRequest {
    fn document(&self) -> Value {
        json!([
            2,
            self.id.value(),
            self.policy.value(),
            self.expected_revision,
            self.targets.value(),
            self.target_revision,
            self.references,
            self.as_of.unix_seconds()
        ])
    }
}
/// Durable candidate progress. Source completeness is distinct from a target page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePhase {
    /// Receiving ordered target pages.
    Targets,
    /// Complete targets; streaming the policy's execution facts.
    Facts,
    /// Complete candidate, not yet selected by an explicit save.
    Ready,
    /// Explicitly saved at least once; remains immutable historical evidence.
    Saved,
    /// Preconditions changed before completion.
    Superseded,
}
/// A bounded view of a candidate; targets and intents are separately paginated.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// Original immutable request.
    pub request: CandidateRequest,
    /// Current durable phase.
    pub phase: CandidatePhase,
    /// Last durably stored target.
    pub target_cursor: Option<String>,
    /// Last durably classified execution key.
    pub fact_cursor: Option<String>,
    /// Complete target count so far.
    pub target_count: u64,
    /// Classified execution count so far.
    pub fact_count: u64,
    /// Semantic identity, present only once complete.
    pub plan: Option<PlanId>,
    pub(crate) policy: Policy,
    targets: TargetDigest,
    facts: ExecutionDigest,
}
fn bytes32(value: Vec<u8>) -> Result<[u8; 32], PgError> {
    value
        .try_into()
        .map_err(|_| STORAGE.fault("candidate::digest"))
}

impl PolicyStore {
    /// Read a source token registered by the owning product composition.
    pub async fn reference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
    ) -> InTransaction<Option<u64>> {
        input!(self.check(tx)?);
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let revision:Option<i64>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT revision FROM mdm_policy.reference_heads WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).fetch_optional(c).await
        })).await?;
        Ok(Ok(revision
            .map(|r| STORAGE.integer("reference::revision", u64::try_from(r)))
            .transpose()?))
    }
    /// Advance one opaque source token in the source owner's publication transaction.
    /// This invalidates all referencing plans without a per-policy fanout transaction.
    pub async fn advance_reference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        revision: u64,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        input!(RequestId::new(self.tenant, id).map_err(|_| Rejection::InvalidInput));
        let revision = input!(i64::try_from(revision).map_err(|_| Rejection::InvalidInput));
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let changed=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_policy.reference_heads(tenant_id,id,revision) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision WHERE mdm_policy.reference_heads.revision<=excluded.revision")
                .bind(tenant).bind(id).bind(revision).execute(c).await.map(|r|r.rows_affected())
        })).await?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Rejection::Conflict)
        })
    }

    /// Record a newer input awaiting evaluation. Freshness is derived from these
    /// two watermarks, so finishing an old worker cannot erase a newer pending input.
    pub async fn require_reference_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        watermark: u64,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        let watermark = input!(i64::try_from(watermark).map_err(|_| Rejection::InvalidInput));
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let changed=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_policy.reference_heads SET required_input=greatest(required_input,$3) WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).bind(watermark).execute(c).await.map(|r|r.rows_affected())
        })).await?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Rejection::NotFound)
        })
    }
    /// Confirm the precise input covered by a published result, preserving any
    /// later required watermark. Compose with source publication in the same tx.
    pub async fn observe_reference_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        watermark: u64,
    ) -> InTransaction<()> {
        input!(self.check(tx)?);
        let watermark = input!(i64::try_from(watermark).map_err(|_| Rejection::InvalidInput));
        let tenant = self.tenant.to_string();
        let id = id.to_owned();
        let changed=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_policy.reference_heads SET observed_input=greatest(observed_input,$3) WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).bind(watermark).execute(c).await.map(|r|r.rows_affected())
        })).await?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Rejection::NotFound)
        })
    }

    /// Admit metadata only. Retries compare the original request, even after the
    /// policy has changed. The first admission freezes the policy decision input.
    pub async fn begin_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &CandidateRequest,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        if request.id.tenant() != self.tenant
            || request.policy.tenant() != self.tenant
            || request.targets.tenant() != self.tenant
        {
            return Ok(Err(Rejection::TenantMismatch));
        }
        if request.target_revision == 0 || request.references.len() > 4096 {
            return Ok(Err(Rejection::InvalidInput));
        }
        STORAGE.lock(tx, "policy", request.policy.value()).await?;
        let tenant = self.tenant.to_string();
        let id = request.id.value().to_owned();
        let exists=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_policy.candidates WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        if exists {
            let old = input!(self.candidate_in(tx, &request.id).await?);
            return Ok(if old.request.document() == request.document() {
                Ok(old)
            } else {
                Err(Rejection::IdentityConflict)
            });
        }
        let aggregate =
            input!(input!(self.get_in(tx, &request.policy).await?).ok_or(Rejection::NotFound));
        if aggregate.storage_revision() != request.expected_revision {
            return Ok(Err(Rejection::Conflict));
        }
        let mut unique = std::collections::BTreeSet::new();
        for reference in &request.references {
            input!(RequestId::new(self.tenant, &reference.id).map_err(|_| Rejection::InvalidInput));
            if !unique.insert(&reference.id) || reference.revision > i64::MAX as u64 {
                return Ok(Err(Rejection::InvalidInput));
            }
        }
        let document = STORAGE.encode(&json!([
            request.document(),
            codec::policy(aggregate.policy())
        ]))?;
        let fingerprint = digest(&document);
        let tenant = self.tenant.to_string();
        let r = request.clone();
        let target_root = TargetDigest::empty(self.tenant).state().to_vec();
        let fact_root = ExecutionDigest::empty(request.policy.clone())
            .state()
            .to_vec();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_policy.candidates(tenant_id,id,policy,expected_revision,input,fingerprint,phase,target_root,fact_root) VALUES($1::uuid,$2,$3,$4,$5,$6,'targets',$7,$8)")
                .bind(&tenant).bind(r.id.value()).bind(r.policy.value()).bind(r.expected_revision as i64).bind(document).bind(fingerprint).bind(target_root).bind(fact_root).execute(&mut *c).await?;
            for reference in r.references {
                sqlx::query("INSERT INTO mdm_policy.candidate_references VALUES($1::uuid,$2,$3,$4)")
                    .bind(&tenant).bind(r.id.value()).bind(reference.id).bind(reference.revision as i64).execute(&mut *c).await?;
            }
            Ok(())
        })).await?;
        if !self.candidate_references_match(tx, &request.id).await? {
            return Ok(Err(Rejection::Conflict));
        }
        self.candidate_in(tx, &request.id).await
    }

    /// Read progress without materializing targets, execution history or intents.
    pub async fn candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(
                        "SELECT * FROM mdm_policy.candidates WHERE tenant_id=$1::uuid AND id=$2",
                    )
                    .bind(tenant)
                    .bind(key)
                    .fetch_optional(c)
                    .await
                })
            })
            .await?;
        let row = input!(row.ok_or(Rejection::NotFound));
        let raw = STORAGE.checked(row.try_get("input")?, row.try_get("fingerprint")?)?;
        let input: Value = STORAGE.decode(&raw)?;
        let a = codec::array(&input, 2)?;
        let r = codec::array(&a[0], 8)?;
        if codec::number(&r[0])? != 2 {
            return Err(STORAGE.fault("candidate::format"));
        }
        let policy = codec::read_policy(&a[1])?;
        let request = CandidateRequest {
            id: decode_domain(
                "candidate::id",
                RequestId::new(self.tenant, codec::text(&r[1])?),
            )?,
            policy: decode_domain(
                "candidate::policy",
                PolicyId::new(self.tenant, codec::text(&r[2])?),
            )?,
            expected_revision: codec::number(&r[3])?,
            targets: decode_domain(
                "candidate::target",
                TargetSnapshotId::new(self.tenant, codec::text(&r[4])?),
            )?,
            target_revision: codec::number(&r[5])?,
            references: STORAGE.json(
                "candidate::references",
                serde_json::from_value(r[6].clone()),
            )?,
            as_of: codec::time(&r[7])?,
        };
        if &request.id != id
            || policy.key() != &request.policy
            || row.try_get::<String, _>("policy")? != request.policy.value()
            || row.try_get::<i64, _>("expected_revision")? as u64 != request.expected_revision
        {
            return Err(STORAGE.fault("candidate::identity"));
        }
        let phase = match row.try_get::<&str, _>("phase")? {
            "targets" => CandidatePhase::Targets,
            "facts" => CandidatePhase::Facts,
            "ready" => CandidatePhase::Ready,
            "saved" => CandidatePhase::Saved,
            "superseded" => CandidatePhase::Superseded,
            _ => return Err(STORAGE.fault("candidate::phase")),
        };
        let target_count = STORAGE.integer(
            "candidate::count",
            u64::try_from(row.try_get::<i64, _>("target_count")?),
        )?;
        let fact_count = STORAGE.integer(
            "candidate::count",
            u64::try_from(row.try_get::<i64, _>("fact_count")?),
        )?;
        Ok(Ok(Candidate {
            targets: TargetDigest::restore(
                self.tenant,
                bytes32(row.try_get("target_root")?)?,
                target_count,
            ),
            facts: ExecutionDigest::restore(
                request.policy.clone(),
                bytes32(row.try_get("fact_root")?)?,
                fact_count,
            ),
            request,
            policy,
            phase,
            target_count,
            fact_count,
            target_cursor: row.try_get("target_cursor")?,
            fact_cursor: row.try_get("fact_cursor")?,
            plan: row
                .try_get::<Option<Vec<u8>>, _>("plan_id")?
                .map(bytes32)
                .transpose()?
                .map(PlanId::from_bytes),
        }))
    }

    pub(crate) async fn candidate_references_match(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> Result<bool, PgError> {
        let tenant = self.tenant.to_string();
        let id = id.value().to_owned();
        let (current,pending)=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(bool,bool)>("SELECT NOT EXISTS(SELECT 1 FROM mdm_policy.candidate_references r LEFT JOIN mdm_policy.reference_heads h ON (h.tenant_id,h.id)=(r.tenant_id,r.reference) WHERE r.tenant_id=$1::uuid AND r.candidate=$2 AND (h.revision IS NULL OR h.revision<>r.revision)), EXISTS(SELECT 1 FROM mdm_policy.candidate_references r JOIN mdm_policy.reference_heads h ON (h.tenant_id,h.id)=(r.tenant_id,r.reference) WHERE r.tenant_id=$1::uuid AND r.candidate=$2 AND h.observed_input<h.required_input)")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        if current && pending {
            return Err(source_pending());
        }
        Ok(current)
    }

    async fn lock_candidate(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> InTransaction<Candidate> {
        let discovered = input!(self.candidate_in(tx, id).await?);
        STORAGE
            .lock(tx, "policy", discovered.request.policy.value())
            .await?;
        let candidate = input!(self.candidate_in(tx, id).await?);
        let aggregate = input!(
            input!(self.get_in(tx, &candidate.request.policy).await?).ok_or(Rejection::NotFound)
        );
        if aggregate.storage_revision() != candidate.request.expected_revision
            || !self.candidate_references_match(tx, id).await?
        {
            return Ok(Err(Rejection::Conflict));
        }
        Ok(Ok(candidate))
    }

    /// Append one ordered target page and its desired intents atomically. Complete
    /// historical predecessor lists are referenced through the frozen candidate,
    /// never embedded in a Supersede document.
    pub async fn append_candidate_targets_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
        after: Option<&DeviceId>,
        devices: &[DeviceId],
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        if devices.is_empty()
            || devices.len() > 1000
            || devices.iter().any(|d| d.tenant() != self.tenant)
            || after.is_some_and(|d| d.tenant() != self.tenant)
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut previous = after;
        for device in devices {
            if previous.is_some_and(|p| p >= device) {
                return Ok(Err(Rejection::InvalidInput));
            }
            previous = Some(device);
        }
        let mut candidate = input!(self.lock_candidate(tx, id).await?);
        let keys: Vec<_> = devices.iter().map(|d| d.value().to_owned()).collect();
        let fingerprint = digest(&STORAGE.encode(&json!([after.map(DeviceId::value), keys]))?);
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let first = keys[0].clone();
        let old=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,Vec<u8>>("SELECT fingerprint FROM mdm_policy.candidate_pages WHERE tenant_id=$1::uuid AND candidate=$2 AND first_device=$3")
                .bind(tenant).bind(key).bind(first).fetch_optional(c).await
        })).await?;
        if let Some(old) = old {
            return Ok(if old == fingerprint {
                Ok(candidate)
            } else {
                Err(Rejection::IdentityConflict)
            });
        }
        if candidate.phase != CandidatePhase::Targets
            || candidate.target_cursor.as_deref() != after.map(DeviceId::value)
        {
            return Ok(Err(Rejection::Conflict));
        }
        if candidate.target_count.saturating_add(devices.len() as u64) > 1_000_000 {
            return Ok(Err(Rejection::BudgetExceeded));
        }
        let tenant = self.tenant.to_string();
        let owner = candidate.request.policy.value().to_owned();
        let selected = keys.clone();
        let version = candidate
            .policy
            .version()
            .map_or(0, Version::number)
            .to_string();
        let history=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT d,EXISTS(SELECT 1 FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 AND device=d AND version=$4::numeric) AS current,EXISTS(SELECT 1 FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 AND device=d AND version<$4::numeric) AS previous FROM unnest($3::text[]) d")
                .bind(tenant).bind(owner).bind(selected).bind(version).fetch_all(c).await
        })).await?;
        let mut intents = Vec::new();
        for row in history {
            let device = decode_domain(
                "candidate::device",
                DeviceId::new(self.tenant, row.try_get::<String, _>("d")?),
            )?;
            let history = if row.try_get("current")? {
                ExecutionPresence::Current
            } else if row.try_get("previous")? {
                ExecutionPresence::Previous
            } else {
                ExecutionPresence::Absent
            };
            if let Some(desired) = input!(
                desired_for_device(&candidate.policy, &device, true, history)
                    .map_err(|_| Rejection::InvalidInput)
            ) {
                let (kind, execution) = match desired {
                    DesiredIntent::Add(e) => ("add", e),
                    DesiredIntent::Supersede(e) => ("supersede", e),
                };
                let document = json!({"kind":kind,"device":device.value(),"version":execution.key().version(),"predecessors":if kind=="supersede" {Some(json!({"candidate":id.value(),"device":device.value(),"beforeVersion":execution.key().version()}))}else{None}});
                intents.push((
                    kind.to_owned(),
                    device.value().to_owned(),
                    String::new(),
                    STORAGE.encode(&document)?,
                ));
            }
        }
        for device in devices {
            input!(
                candidate
                    .targets
                    .push(device)
                    .map_err(|_| Rejection::InvalidInput)
            );
        }
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let first = keys[0].clone();
        let last = keys.last().expect("nonempty").clone();
        let count = candidate.targets.count() as i64;
        let root = candidate.targets.state().to_vec();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_policy.candidate_targets SELECT $1::uuid,$2,d FROM unnest($3::text[]) d")
                .bind(&tenant).bind(&key).bind(keys).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_policy.candidate_pages VALUES($1::uuid,$2,$3,$4)")
                .bind(&tenant).bind(&key).bind(first).bind(fingerprint).execute(&mut *c).await?;
            write_intents(c,&tenant,&key,intents).await?;
            sqlx::query("UPDATE mdm_policy.candidates SET target_cursor=$3,target_count=$4,target_root=$5 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(key).bind(last).bind(count).bind(root).execute(c).await?;Ok(())
        })).await?;
        self.candidate_in(tx, id).await
    }

    /// Seal the complete source enumeration; neither a short page nor an empty
    /// response alone proves that the source was completely resolved.
    pub async fn seal_candidate_targets_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
        expected_count: u64,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        let candidate = input!(self.lock_candidate(tx, id).await?);
        if candidate.target_count != expected_count {
            return Ok(Err(Rejection::InvalidInput));
        }
        if candidate.phase == CandidatePhase::Targets {
            let tenant = self.tenant.to_string();
            let key = id.value().to_owned();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("UPDATE mdm_policy.candidates SET phase='facts' WHERE tenant_id=$1::uuid AND id=$2 AND phase='targets'")
                    .bind(tenant).bind(key).execute(c).await?;Ok(())
            })).await?;
        }
        self.candidate_in(tx, id).await
    }

    /// Classify one bounded history page. Aggregate CAS rejects any intervening
    /// lifecycle or fact write; mixed-generation input can never become a ready plan.
    pub async fn advance_candidate_facts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
    ) -> InTransaction<Candidate> {
        input!(self.check(tx)?);
        let mut candidate = input!(self.lock_candidate(tx, id).await?);
        if candidate.phase == CandidatePhase::Ready {
            return Ok(Ok(candidate));
        }
        if candidate.phase != CandidatePhase::Facts {
            return Ok(Err(Rejection::Conflict));
        }
        let page = input!(
            self.execution_facts_in(
                tx,
                &candidate.request.policy,
                candidate.fact_cursor.clone(),
                1000
            )
            .await?
        );
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let devices: Vec<_> = page
            .records
            .iter()
            .map(|f| f.device().value().to_owned())
            .collect();
        let targeted:std::collections::BTreeSet<String>=tx.with_connection(move |c|Box::pin(async move {
            let rows:Vec<String>=sqlx::query_scalar("SELECT device FROM mdm_policy.candidate_targets WHERE tenant_id=$1::uuid AND candidate=$2 AND device=ANY($3)")
                .bind(tenant).bind(key).bind(devices).fetch_all(c).await?;Ok(rows.into_iter().collect())
        })).await?;
        let mut intents = Vec::new();
        for fact in &page.records {
            let intent = input!(
                classify_record(
                    &candidate.policy,
                    targeted.contains(fact.device().value()),
                    fact
                )
                .map_err(|_| Rejection::InvalidInput)
            );
            let (kind, reason) = match intent {
                Intent::Retain { reason, .. } => (
                    "retain",
                    match reason {
                        RetainReason::Current => "current",
                        RetainReason::Paused => "paused",
                        RetainReason::Historical => "historical",
                    },
                ),
                Intent::Cancel { reason, .. } => (
                    "cancel",
                    match reason {
                        CancelReason::ScopeExit => "scope_exit",
                        CancelReason::Archived => "archived",
                        CancelReason::Superseded => "superseded",
                    },
                ),
            };
            intents.push((
                kind.to_owned(),
                fact.device().value().to_owned(),
                codec::key(fact),
                STORAGE
                    .encode(&json!({"kind":kind,"reason":reason,"execution":codec::fact(fact)}))?,
            ));
            input!(
                candidate
                    .facts
                    .push(fact)
                    .map_err(|_| Rejection::InvalidInput)
            );
        }
        let complete = page.next.is_none();
        let cursor = page
            .records
            .last()
            .map(codec::key)
            .or(candidate.fact_cursor.clone());
        let plan = if complete {
            Some(
                input!(
                    stream_plan_id(
                        &candidate.policy,
                        &candidate.request.targets,
                        candidate.request.target_revision,
                        &candidate.targets,
                        &candidate.facts
                    )
                    .map_err(|_| Rejection::InvalidInput)
                )
                .bytes()
                .to_vec(),
            )
        } else {
            None
        };
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let root = candidate.facts.state().to_vec();
        let count =
            input!(i64::try_from(candidate.facts.count()).map_err(|_| Rejection::BudgetExceeded));
        tx.with_connection(move |c|Box::pin(async move {
            write_intents(c,&tenant,&key,intents).await?;
            sqlx::query("UPDATE mdm_policy.candidates SET phase=$3,fact_cursor=$4,fact_count=$5,fact_root=$6,plan_id=$7 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(key).bind(if complete {"ready"}else{"facts"}).bind(cursor).bind(count).bind(root).bind(plan).execute(c).await?;Ok(())
        })).await?;
        self.candidate_in(tx, id).await
    }

    /// Explicitly install a complete candidate under source and aggregate CAS.
    /// The caller composes authorization, current source admission and audit in
    /// this transaction and declares the policy Outbox partition before calling.
    /// No target copy, execution record, approval or device message is produced.
    pub async fn save_candidate_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &RequestId,
        candidate_id: &RequestId,
        expected_revision: u64,
        at: Timepoint,
    ) -> InTransaction<Receipt> {
        input!(self.check(tx)?);
        if operation.tenant() != self.tenant || candidate_id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let request = STORAGE.encode(&json!([
            "save-candidate-v2",
            candidate_id.value(),
            expected_revision,
            at.unix_seconds()
        ]))?;
        let fingerprint = digest(&request);
        STORAGE.lock(tx, "request", operation.value()).await?;
        if let Some(old) = STORAGE.receipt(tx, operation.value()).await? {
            if old.fingerprint != fingerprint {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(STORAGE.decode(&old.receipt)?));
        }
        let candidate = input!(self.candidate_in(tx, candidate_id).await?);
        STORAGE
            .lock(tx, "policy", candidate.request.policy.value())
            .await?;
        let candidate = input!(self.candidate_in(tx, candidate_id).await?);
        let mut aggregate = input!(
            input!(self.get_in(tx, &candidate.request.policy).await?).ok_or(Rejection::NotFound)
        );
        let plan = input!(candidate.plan.ok_or(Rejection::Conflict));
        if aggregate.revision != expected_revision
            || aggregate.at.is_some_and(|previous| previous > at)
        {
            return Ok(Err(Rejection::Conflict));
        }
        let tenant = self.tenant.to_string();
        let key = candidate_id.value().to_owned();
        let references=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT h.id,h.revision,h.required_input,h.observed_input,r.revision AS expected FROM mdm_policy.candidate_references r JOIN mdm_policy.reference_heads h ON (h.tenant_id,h.id)=(r.tenant_id,r.reference) WHERE r.tenant_id=$1::uuid AND r.candidate=$2 ORDER BY h.id FOR SHARE OF h")
                .bind(tenant).bind(key).fetch_all(c).await
        })).await?;
        if references.len() != candidate.request.references.len() {
            return Err(STORAGE.fault("candidate::reference-count"));
        }
        for reference in references {
            if reference.try_get::<i64, _>("revision")?
                != reference.try_get::<i64, _>("expected")?
            {
                return Ok(Err(Rejection::Conflict));
            }
            if reference.try_get::<i64, _>("observed_input")?
                < reference.try_get::<i64, _>("required_input")?
            {
                return Err(source_pending());
            }
        }
        let already = candidate.phase == CandidatePhase::Saved
            && aggregate.plan_is_fresh()
            && aggregate.current_plan_id() == Some(plan);
        if !already
            && (candidate.phase != CandidatePhase::Ready
                || candidate.request.expected_revision != aggregate.revision)
        {
            return Ok(Err(Rejection::Conflict));
        }
        if !already {
            let previous = aggregate.revision;
            input!(aggregate.advance());
            aggregate.plan = Some(plan);
            aggregate.installed = Some(aggregate.revision);
            aggregate.installed_request = Some(operation.clone());
            aggregate.at = Some(at);
            aggregate.references_current = true;
            STORAGE
                .write(
                    tx,
                    candidate.request.policy.value(),
                    Some(previous),
                    aggregate.revision,
                    aggregate.document()?,
                )
                .await?;
            let tenant = self.tenant.to_string();
            let policy = candidate.request.policy.value().to_owned();
            let key = candidate_id.value().to_owned();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_policy.current_plans VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,policy) DO UPDATE SET candidate=excluded.candidate")
                    .bind(&tenant).bind(&policy).bind(&key).execute(&mut *c).await?;
                sqlx::query("UPDATE mdm_policy.candidates SET phase='saved' WHERE tenant_id=$1::uuid AND id=$2 AND phase='ready'")
                    .bind(tenant).bind(key).execute(c).await?;Ok(())
            })).await?;
            crate::event::append(
                &self.writer,
                tx,
                self.tenant,
                at,
                candidate.request.policy.value(),
                operation.value(),
                aggregate.revision,
            )
            .await?;
        }
        let receipt = Receipt {
            policy: candidate.request.policy.value().into(),
            request: operation.value().into(),
            storage_revision: aggregate.revision,
            plan_id: Some(codec::hex(plan.bytes())),
            plan_is_fresh: true,
        };
        STORAGE
            .save_receipt(
                tx,
                operation.value(),
                candidate.request.policy.value(),
                request,
                STORAGE.encode(&receipt)?,
            )
            .await?;
        Ok(Ok(receipt))
    }

    pub(crate) async fn installed_references_current(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &PolicyId,
    ) -> Result<Option<bool>, PgError> {
        let tenant = self.tenant.to_string();
        let owner = policy.value().to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_policy.candidate_references r LEFT JOIN mdm_policy.reference_heads h ON (h.tenant_id,h.id)=(r.tenant_id,r.reference) WHERE r.tenant_id=p.tenant_id AND r.candidate=p.candidate AND (h.revision IS NULL OR h.revision<>r.revision OR h.observed_input<h.required_input)) FROM mdm_policy.current_plans p WHERE p.tenant_id=$1::uuid AND p.policy=$2")
                .bind(tenant).bind(owner).fetch_optional(c).await
        })).await
    }
}

type EncodedIntent = (String, String, String, Vec<u8>);
async fn write_intents(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    candidate: &str,
    rows: Vec<EncodedIntent>,
) -> Result<(), sqlx::Error> {
    let mut kinds = Vec::new();
    let mut devices = Vec::new();
    let mut keys = Vec::new();
    let mut docs = Vec::new();
    let mut hashes = Vec::new();
    for (kind, device, key, document) in rows {
        kinds.push(kind);
        devices.push(device);
        keys.push(key);
        hashes.push(digest(&document));
        docs.push(document);
    }
    sqlx::query("INSERT INTO mdm_policy.candidate_intents SELECT $1::uuid,$2,* FROM unnest($3::text[],$4::text[],$5::text[],$6::bytea[],$7::bytea[])")
        .bind(tenant).bind(candidate).bind(kinds).bind(devices).bind(keys).bind(docs).bind(hashes).execute(c).await?;
    Ok(())
}

fn source_pending() -> PgError {
    rss_transactional_messaging::error::MessagingError::new(
        rss_transactional_messaging::error::MessagingErrorKind::Transient,
        std::io::Error::other("source input pending"),
    )
    .into()
}
