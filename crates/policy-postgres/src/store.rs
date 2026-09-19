use crate::{MAX_FACTS, STORAGE, codec, core::*, error::*, event, model::*};
use rss_mdm_backend_postgres_support::MAX_DOCUMENT;
use rss_mdm_backend_postgres_support::digest;
use rss_mdm_backend_postgres_support::{AggregateRecord, RequestRecord};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc};
/// Tenant-bound Policy persistence using the host-owned RSS PostgreSQL runtime.
pub struct PolicyStore {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    writer: PgOutboxWriter,
}
impl PolicyStore {
    /// Identify this tenant's ordered event partition for a canonical aggregate ID.
    /// The outer transaction declares every partition once, before any business locks.
    pub fn partition(
        &self,
        id: &str,
    ) -> Result<rss_transactional_messaging::message::PartitionIdentity, PgError> {
        use rss_transactional_messaging::message::{PartitionIdentity, PartitionKey};
        Ok(PartitionIdentity::new(
            self.tenant,
            event::domain(),
            STORAGE.invalid("store::partition", PartitionKey::parse(id))?,
        ))
    }

    /// Admit the exact schema and effective runtime privileges, then borrow the host runtime.
    /// Returns a settlement error on admission failure; never migrates or closes the runtime.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, deadline, |tx| {
                    Box::pin(async move {
                        STORAGE.verify(tx, crate::ADMISSION).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
        )?;
        Ok(Self {
            writer: PgOutboxWriter::new(runtime.clone(), event::domain()),
            runtime,
            tenant,
        })
    }
    /// Return the tenant permanently bound to this store.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.writer.validate_transaction(tx)?;
        Ok(if tx.tenant_id() == self.tenant {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    /// Read and validate the current aggregate for this store tenant. Missing identities return `None`.
    pub async fn get(
        &self,
        id: &PolicyId,
        deadline: OperationDeadline,
    ) -> Result<Option<Aggregate>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, (self, id), |(s, id), tx| {
                    Box::pin(async move { s.get_in(tx, id).await })
                })
                .await,
        )
    }
    /// Read through a borrowed transaction after runtime-owner and tenant validation.
    /// Never commits; propagate outer errors to the transaction owner.
    pub async fn get_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &PolicyId,
    ) -> InTransaction<Option<Aggregate>> {
        input!(self.check(tx)?);
        if id.tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        let row = STORAGE.read(tx, id.value()).await?;
        let result = row
            .map(
                |AggregateRecord {
                     revision: rev,
                     document: b,
                 }| {
                    let a = Aggregate::restore(&b)?;
                    if a.policy.key() != id || a.revision != rev {
                        return Err(STORAGE.fault("store::get_in"));
                    }
                    Ok(a)
                },
            )
            .transpose()?;
        if let Some(aggregate) = &result {
            if let Some(v) = aggregate.policy.version() {
                for (owner, kind, key, expected) in version_documents(v)? {
                    if STORAGE.immutable(tx, &owner, kind, &key).await?.as_ref() != Some(&expected)
                    {
                        return Err(STORAGE.fault("store::get_in"));
                    }
                }
            }
            if let Some(t) = &aggregate.targets {
                let key = format!("{}@{}", t.key().value(), t.revision());
                if STORAGE.immutable(tx, "", "targets", &key).await?.as_ref()
                    != Some(&STORAGE.encode(&codec::targets(t))?)
                {
                    return Err(STORAGE.fault("store::get_in"));
                }
            }
        }
        Ok(Ok(result))
    }
    /// Execute one fixed request atomically with its receipt and necessary RSS Outbox event.
    /// An identical request replays before CAS; on `CommitUnknown`, retain the original request and query its receipt.
    pub async fn execute(
        &self,
        r: &Request,
        deadline: OperationDeadline,
    ) -> Result<Receipt, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, (self, r), |(s, r), tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[s.partition(r.policy().value())?])
                            .await?;
                        s.execute_in(tx, r).await
                    })
                })
                .await,
        )
    }
    /// Execute using the caller transaction, validating runtime ownership and tenant before any path.
    /// Propagate the outer PG error to roll back; inspect the inner business rejection. This method never commits.
    /// The caller must declare the complete Outbox partition set before business locks.
    pub async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        r: &Request,
    ) -> InTransaction<Receipt> {
        input!(self.check(tx)?);
        if r.id.tenant() != self.tenant || r.policy().tenant() != self.tenant {
            return Ok(Err(Rejection::TenantMismatch));
        }
        input!(validate_request(r));
        let request_document = r.document()?;
        let fingerprint = digest(&request_document);
        STORAGE.lock(tx, "request", r.id.value()).await?;
        if let Some(RequestRecord {
            owner,
            fingerprint: hash,
            receipt: bytes,
            ..
        }) = STORAGE.receipt(tx, r.id.value()).await?
        {
            if owner != r.policy().value() || hash != fingerprint {
                return Ok(Err(Rejection::IdentityConflict));
            }
            let receipt: Receipt = STORAGE.decode(&bytes)?;
            if receipt.policy != owner || receipt.request != r.id.value() {
                return Err(STORAGE.fault("store::execute_in"));
            }
            return Ok(Ok(receipt));
        }
        STORAGE.lock(tx, "policy", r.policy().value()).await?;
        let old = input!(self.get_in(tx, r.policy()).await?);
        let create = matches!(r.command, Command::Create { .. });
        if create && old.is_some() {
            return Ok(Err(Rejection::Conflict));
        }
        let mut aggregate = if create {
            Aggregate::draft(r.policy().clone())
        } else {
            input!(old.ok_or(Rejection::NotFound))
        };
        if aggregate.revision != r.expected_storage_revision
            || aggregate.at.is_some_and(|at| at > r.as_of)
        {
            return Ok(Err(Rejection::Conflict));
        }
        let previous = aggregate.revision;
        let mut facts = load_facts(tx, r.policy()).await?;
        let mut plan_document = None;
        let changed = match &r.command {
            Command::Create { .. } => true,
            Command::Transition { transition, .. } => {
                aggregate.policy = input!(
                    aggregate
                        .policy
                        .transition(aggregate.policy.revision(), transition.clone())
                        .map_err(|_| Rejection::Conflict)
                );
                true
            }
            Command::SelectTargets {
                snapshot,
                references,
                ..
            } => {
                let changed = aggregate.targets.as_ref() != Some(snapshot)
                    || &aggregate.references != references;
                aggregate.targets = Some(snapshot.clone());
                aggregate.references = references.clone();
                changed
            }
            Command::ReplaceFacts { facts: updates, .. } => {
                let mut changed = false;
                for f in updates {
                    let k = codec::key(f);
                    let existing = input!(facts.get(&k).ok_or(Rejection::NotFound));
                    if existing.version() != f.version() {
                        return Ok(Err(Rejection::IdentityConflict));
                    }
                    changed |= existing != f;
                    facts.insert(k, f.clone());
                }
                changed
            }
            Command::Replan { .. } => {
                let targets = input!(aggregate.targets.as_ref().ok_or(Rejection::InvalidInput));
                let records: Vec<_> = facts.values().cloned().collect();
                let plan = input!(
                    reconcile(PlanInput {
                        policy: &aggregate.policy,
                        targets,
                        executions: &records,
                        request: r.id.clone(),
                        as_of: r.as_of
                    })
                    .map_err(|_| Rejection::InvalidInput)
                );
                let changed = !aggregate.plan_is_fresh() || aggregate.plan != Some(plan.id());
                let document = STORAGE.encode(&json!([
                    1,
                    codec::policy(&aggregate.policy),
                    codec::targets(targets),
                    records.iter().map(codec::fact).collect::<Vec<_>>()
                ]))?;
                for intent in plan.intents() {
                    let desired = match intent {
                        Intent::Add(d) | Intent::Supersede { replacement: d, .. } => Some(d),
                        _ => None,
                    };
                    if let Some(d) = desired {
                        let v = aggregate
                            .policy
                            .version()
                            .ok_or_else(|| STORAGE.fault("store::execute_in"))?;
                        let f = crate::error::decode_domain(
                            "store::execute_in",
                            ExecutionRecord::new(
                                v.clone(),
                                d.key().device().clone(),
                                Progress::Planned,
                                Effect::Unverified,
                            ),
                        )?;
                        facts.entry(codec::key(&f)).or_insert(f);
                    }
                }
                if facts.len() > MAX_FACTS {
                    return Ok(Err(Rejection::BudgetExceeded));
                }
                aggregate.plan = Some(plan.id());
                plan_document = Some((codec::hex(plan.id().bytes()), document));
                changed
            }
        };
        if changed {
            input!(aggregate.advance());
            aggregate.at = Some(r.as_of);
        }
        if changed && matches!(r.command, Command::Replan { .. }) {
            aggregate.installed = Some(aggregate.revision);
            aggregate.installed_request = Some(r.id.clone());
        }
        // Immutable checks precede all business writes. Concurrent cross-policy payload conflicts
        // become an outer storage error in STORAGE.freeze(), rolling back the entire transaction.
        if let Some(v) = aggregate.policy.version() {
            input!(compatible_version(tx, v).await?);
        }
        if let Some(t) = &aggregate.targets {
            let key = format!("{}@{}", t.key().value(), t.revision());
            let document = STORAGE.encode(&codec::targets(t))?;
            if STORAGE
                .immutable(tx, "", "targets", &key)
                .await?
                .is_some_and(|b| b != document)
            {
                return Ok(Err(Rejection::IdentityConflict));
            }
        }
        let response = Receipt::new(&aggregate, r);
        if create || changed {
            STORAGE
                .write(
                    tx,
                    r.policy().value(),
                    if create { None } else { Some(previous) },
                    aggregate.revision,
                    aggregate.document()?,
                )
                .await?;
        }
        if let Some(v) = aggregate.policy.version() {
            freeze_version(tx, v).await?;
        }
        if let Some(t) = &aggregate.targets {
            STORAGE
                .freeze(
                    tx,
                    "",
                    "targets",
                    &format!("{}@{}", t.key().value(), t.revision()),
                    STORAGE.encode(&codec::targets(t))?,
                )
                .await?;
        }
        if let Some((key, document)) = plan_document {
            // PlanId excludes provenance; retain the first canonical input.
            if STORAGE
                .immutable(tx, r.policy().value(), "plan", &key)
                .await?
                .is_none()
            {
                STORAGE
                    .freeze(tx, r.policy().value(), "plan", &key, document)
                    .await?;
            }
        }
        if changed {
            save_facts(tx, r.policy(), &facts).await?;
            event::append(
                &self.writer,
                tx,
                self.tenant,
                r.as_of,
                r.policy().value(),
                r.id.value(),
                aggregate.revision,
            )
            .await?;
        }
        STORAGE
            .save_receipt(
                tx,
                r.id.value(),
                r.policy().value(),
                request_document,
                STORAGE.encode(&response)?,
            )
            .await?;
        Ok(Ok(response))
    }
    /// Read the original durable request receipt without changing current aggregate state.
    /// Use this after an unconfirmed commit; absence alone is not permission to invent another request identity.
    pub async fn operation(
        &self,
        id: &RequestId,
        deadline: OperationDeadline,
    ) -> Result<Option<Receipt>, Error> {
        if id.tenant() != self.tenant {
            return Err(Rejection::TenantMismatch.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, id, |id, tx| {
                    Box::pin(async move {
                        Ok(Ok(STORAGE
                            .receipt(tx, id.value())
                            .await?
                            .map(|record| STORAGE.decode(&record.receipt))
                            .transpose()?))
                    })
                })
                .await,
        )
    }
    /// Restore an explicit replan using its immutable decision and original request provenance.
    /// Use Aggregate::current_plan_request to select the current installation.
    pub async fn plan(
        &self,
        policy: &PolicyId,
        request: &RequestId,
        deadline: OperationDeadline,
    ) -> Result<Option<Plan>, Error> {
        if policy.tenant() != self.tenant || request.tenant() != self.tenant {
            return Err(Rejection::TenantMismatch.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant,
                    deadline,
                    (policy, request),
                    |(policy, request), tx| {
                        Box::pin(async move {
                            let Some(RequestRecord {
                                request: original_request,
                                receipt,
                                ..
                            }) = STORAGE.receipt(tx, request.value()).await?
                            else {
                                return Ok(Ok(None));
                            };
                            let receipt: Receipt = STORAGE.decode(&receipt)?;
                            let raw: Value = STORAGE.decode(&original_request)?;
                            let fields = codec::array(&raw, 7)?;
                            if receipt.policy != policy.value()
                                || receipt.request != request.value()
                                || codec::text(&fields[1])? != policy.tenant().to_string()
                                || codec::text(&fields[2])? != request.value()
                                || codec::text(&fields[3])? != policy.value()
                                || fields[6] != json!([7])
                            {
                                return Ok(Err(Rejection::InvalidInput));
                            }
                            let id = codec::plan_id(
                                receipt
                                    .plan_id
                                    .as_deref()
                                    .ok_or_else(|| STORAGE.fault("store::plan"))?,
                            )?;
                            let bytes = STORAGE
                                .immutable(tx, policy.value(), "plan", &codec::hex(id.bytes()))
                                .await?
                                .ok_or_else(|| STORAGE.fault("store::plan"))?;
                            Ok(Ok(Some(restore_plan(
                                &bytes,
                                policy,
                                id,
                                request.clone(),
                                codec::time(&fields[5])?,
                            )?)))
                        })
                    },
                )
                .await,
        )
    }
    /// Read one immutable policy version, including versions never installed as plans.
    pub async fn version(
        &self,
        policy: &PolicyId,
        number: u64,
        deadline: OperationDeadline,
    ) -> Result<Option<Version>, Error> {
        if policy.tenant() != self.tenant || number == 0 {
            return Err(Rejection::InvalidInput.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, policy, move |policy, tx| {
                    Box::pin(async move {
                        let bytes = STORAGE
                            .immutable(tx, policy.value(), "version", &number.to_string())
                            .await?;
                        let value = bytes
                            .map(|b| codec::read_version(&STORAGE.decode::<Value>(&b)?))
                            .transpose()?;
                        if value
                            .as_ref()
                            .is_some_and(|v| v.policy() != *policy || v.number() != number)
                        {
                            return Err(STORAGE.fault("store::version"));
                        }
                        Ok(Ok(value))
                    })
                })
                .await,
        )
    }
    /// Read a complete, caller-owned immutable target snapshot by its original identity.
    pub async fn target_snapshot(
        &self,
        id: &TargetSnapshotId,
        revision: u64,
        deadline: OperationDeadline,
    ) -> Result<Option<TargetSnapshot>, Error> {
        if id.tenant() != self.tenant || revision == 0 {
            return Err(Rejection::InvalidInput.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, id, move |id, tx| {
                    Box::pin(async move {
                        let bytes = STORAGE
                            .immutable(tx, "", "targets", &format!("{}@{revision}", id.value()))
                            .await?;
                        let value = bytes
                            .map(|b| codec::read_targets(&STORAGE.decode::<Value>(&b)?))
                            .transpose()?;
                        if value
                            .as_ref()
                            .is_some_and(|v| v.key() != *id || v.revision() != revision)
                        {
                            return Err(STORAGE.fault("store::target_snapshot"));
                        }
                        Ok(Ok(value))
                    })
                })
                .await,
        )
    }
    /// Read at most `limit` authoritative facts (1–1000) and an opaque continuation cursor.
    /// The adapter does not order device events; use caller-confirmed snapshots with complete execution keys.
    pub async fn execution_facts(
        &self,
        policy: &PolicyId,
        after: Option<String>,
        limit: usize,
        deadline: OperationDeadline,
    ) -> Result<FactPage, Error> {
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant,
                    deadline,
                    (self, policy),
                    move |(store, policy), tx| {
                        Box::pin(
                            async move { store.execution_facts_in(tx, policy, after, limit).await },
                        )
                    },
                )
                .await,
        )
    }
    /// Read one bounded fact page in the host transaction, preserving the same
    /// snapshot as the aggregate. Validates both runtime provenance and tenant.
    pub async fn execution_facts_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &PolicyId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<FactPage> {
        input!(self.check(tx)?);
        if policy.tenant() != self.tenant
            || limit == 0
            || limit > 1000
            || after.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let owner = policy.value();
        let rows = query_fact_page(tx, owner, after, limit).await?;
        let records = decode_fact_page(rows, tx.tenant_id(), owner)?;
        Ok(Ok(fact_page(records, limit)))
    }
}
fn validate_request(r: &Request) -> Result<(), Rejection> {
    match &r.command {
        Command::SelectTargets {
            snapshot,
            references,
            ..
        } => {
            if snapshot.key().tenant() != r.id.tenant() {
                return Err(Rejection::TenantMismatch);
            }
            if snapshot.members().len() > MAX_FACTS || references.len() > 256 {
                return Err(Rejection::BudgetExceeded);
            }
            let mut ids = std::collections::BTreeSet::new();
            for v in references {
                if RequestId::new(r.id.tenant(), &v.id).is_err()
                    || v.revision == 0
                    || !ids.insert(&v.id)
                {
                    return Err(Rejection::InvalidInput);
                }
            }
        }
        Command::ReplaceFacts { facts, .. } => {
            if facts.len() > MAX_FACTS {
                return Err(Rejection::BudgetExceeded);
            }
            let mut keys = std::collections::BTreeSet::new();
            for f in facts {
                if f.version().policy() != r.policy() || !keys.insert(f.key()) {
                    return Err(Rejection::InvalidInput);
                }
            }
        }
        _ => (),
    };
    Ok(())
}
async fn compatible_version(tx: &mut PgTransaction<'_>, v: &Version) -> InTransaction<()> {
    for (owner, kind, key, doc) in version_documents(v)? {
        if STORAGE
            .immutable(tx, &owner, kind, &key)
            .await?
            .is_some_and(|b| b != doc)
        {
            return Ok(Err(Rejection::IdentityConflict));
        }
    }
    Ok(Ok(()))
}
type VersionDocument = (String, &'static str, String, Vec<u8>);
fn version_documents(v: &Version) -> Result<Vec<VersionDocument>, PgError> {
    let p = v.payload();
    Ok(vec![
        (
            v.policy().value().into(),
            "version",
            v.number().to_string(),
            STORAGE.encode(&codec::version(v))?,
        ),
        (
            "".into(),
            "payload",
            format!("{}@{}", p.object().value(), p.revision()),
            STORAGE.encode(&json!([
                p.object().tenant().to_string(),
                p.object().value(),
                p.revision(),
                p.digest()
            ]))?,
        ),
    ])
}
async fn freeze_version(tx: &mut PgTransaction<'_>, v: &Version) -> Result<(), PgError> {
    for (o, k, i, d) in version_documents(v)? {
        STORAGE.freeze(tx, &o, k, &i, d).await?;
    }
    Ok(())
}
fn read_fact_row(row: sqlx::postgres::PgRow) -> Result<ExecutionRecord, PgError> {
    let b = STORAGE.checked(row.try_get("document")?, row.try_get("digest")?)?;
    let f = codec::read_fact(&STORAGE.decode::<Value>(&b)?)?;
    if row.try_get::<String, _>("key")? != codec::key(&f) {
        return Err(STORAGE.fault("store::read_fact_row"));
    }
    Ok(f)
}
async fn load_facts(
    tx: &mut PgTransaction<'_>,
    policy: &PolicyId,
) -> Result<BTreeMap<String, ExecutionRecord>, PgError> {
    let (t, p) = (tx.tenant_id().to_string(), policy.value().to_owned());
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(LOAD_FACTS_SQL)
                    .bind(t)
                    .bind(p)
                    .fetch_all(c)
                    .await
            })
        })
        .await?;

    if rows.len() > MAX_FACTS {
        return Err(STORAGE.fault("store::load_facts"));
    }
    let mut facts = BTreeMap::new();
    let mut size = 0;
    for row in rows {
        size += row.try_get::<Vec<u8>, _>("document")?.len();
        if size > MAX_DOCUMENT {
            return Err(STORAGE.fault("store::load_facts"));
        }
        let f = read_fact_row(row)?;
        if f.version().policy() != policy {
            return Err(STORAGE.fault("store::load_facts"));
        }
        facts.insert(codec::key(&f), f);
    }
    Ok(facts)
}
async fn save_facts(
    tx: &mut PgTransaction<'_>,
    policy: &PolicyId,
    facts: &BTreeMap<String, ExecutionRecord>,
) -> Result<(), PgError> {
    let t = tx.tenant_id().to_string();
    let owner = policy.value().to_owned();
    let docs = facts
        .iter()
        .map(|(k, f)| {
            let b = STORAGE.encode(&codec::fact(f))?;
            Ok((k.clone(), digest(&b), b))
        })
        .collect::<Result<Vec<_>, PgError>>()?;
    tx.with_connection(move |c| {
        Box::pin(async move {
            for (k, h, b) in docs {
                sqlx::query(SAVE_FACTS_SQL)
                    .bind(&t)
                    .bind(&owner)
                    .bind(k)
                    .bind(b)
                    .bind(h)
                    .execute(&mut *c)
                    .await?;
            }
            Ok(())
        })
    })
    .await
}
fn restore_plan(
    b: &[u8],
    policy: &PolicyId,
    id: PlanId,
    request: RequestId,
    as_of: rss_contract::Timepoint,
) -> Result<Plan, PgError> {
    let v: Value = STORAGE.decode(b)?;
    let a = codec::array(&v, 4)?;
    if codec::number(&a[0])? != 1 {
        return Err(STORAGE.fault("store::restore_plan"));
    }
    let p = codec::read_policy(&a[1])?;
    let t = codec::read_targets(&a[2])?;
    let facts = a[3]
        .as_array()
        .ok_or_else(|| STORAGE.fault("store::restore_plan"))?
        .iter()
        .map(codec::read_fact)
        .collect::<Result<Vec<_>, _>>()?;
    let plan = crate::error::decode_domain(
        "store::restore_plan",
        reconcile(PlanInput {
            policy: &p,
            targets: &t,
            executions: &facts,
            request,
            as_of,
        }),
    )?;
    if plan.policy() != policy || plan.id() != id {
        return Err(STORAGE.fault("store::restore_plan"));
    }
    Ok(plan)
}

const EXECUTION_FACTS_SQL: &str = "SELECT key,document,digest FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 AND ($3::text IS NULL OR key COLLATE \"C\">$3 COLLATE \"C\") ORDER BY key COLLATE \"C\" LIMIT $4";
const LOAD_FACTS_SQL: &str = "SELECT key,document,digest FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 ORDER BY key COLLATE \"C\" LIMIT 10001";
const SAVE_FACTS_SQL: &str = "INSERT INTO mdm_policy.facts(tenant_id,owner,key,document,digest) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,owner,key) DO UPDATE SET document=EXCLUDED.document,digest=EXCLUDED.digest WHERE mdm_policy.facts.document<>EXCLUDED.document";

async fn query_fact_page(
    tx: &mut PgTransaction<'_>,
    owner: &str,
    after: Option<String>,
    limit: usize,
) -> Result<Vec<sqlx::postgres::PgRow>, PgError> {
    let (tenant, owner) = (tx.tenant_id().to_string(), owner.to_owned());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(EXECUTION_FACTS_SQL)
                .bind(tenant)
                .bind(owner)
                .bind(after)
                .bind((limit + 1) as i64)
                .fetch_all(c)
                .await
        })
    })
    .await
}
fn decode_fact_page(
    rows: Vec<sqlx::postgres::PgRow>,
    tenant: TenantId,
    owner: &str,
) -> Result<Vec<ExecutionRecord>, PgError> {
    rows.into_iter()
        .map(|row| {
            let fact = read_fact_row(row)?;
            if fact.version().policy().tenant() != tenant
                || fact.version().policy().value() != owner
            {
                return Err(STORAGE.fault("store::execution_facts"));
            }
            Ok(fact)
        })
        .collect()
}
fn fact_page(mut records: Vec<ExecutionRecord>, limit: usize) -> FactPage {
    let more = records.len() > limit;
    records.truncate(limit);
    let next = if more {
        records.last().map(codec::key)
    } else {
        None
    };
    FactPage { records, next }
}
