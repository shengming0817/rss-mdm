use crate::{STORAGE, codec, core::*, error::*, event, model::*};
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
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) writer: PgOutboxWriter,
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
    pub(crate) fn check(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
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
        let mut result = row
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
        if let Some(aggregate) = &mut result {
            if aggregate.plan.is_some() {
                aggregate.references_current = self
                    .installed_references_current(tx, id)
                    .await?
                    .unwrap_or(false);
            }
            if let Some(v) = aggregate.policy.version() {
                for (owner, kind, key, expected) in version_documents(v)? {
                    if STORAGE.immutable(tx, &owner, kind, &key).await?.as_ref() != Some(&expected)
                    {
                        return Err(STORAGE.fault("store::get_in"));
                    }
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
        let mut facts = match &r.command {
            Command::RecordExecutions { facts: updates, .. } => {
                load_selected_facts(tx, r.policy(), updates).await?
            }
            _ => BTreeMap::new(),
        };
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
            Command::RecordExecutions { facts: updates, .. } => {
                let mut changed = false;
                let mut versions = BTreeMap::new();
                for f in updates {
                    let k = codec::key(f);
                    if let Some(previous) = versions.insert(f.version().number(), f.version()) {
                        if previous != f.version() {
                            return Ok(Err(Rejection::IdentityConflict));
                        }
                    } else {
                        input!(compatible_version(tx, f.version()).await?);
                        if STORAGE
                            .immutable(
                                tx,
                                r.policy().value(),
                                "version",
                                &f.version().number().to_string(),
                            )
                            .await?
                            .is_none()
                        {
                            return Ok(Err(Rejection::NotFound));
                        }
                    }
                    input!(
                        classify_record(aggregate.policy(), false, f)
                            .map_err(|_| Rejection::InvalidInput)
                    );
                    let existing = facts.get(&k);
                    if existing.is_some_and(|old| old.version() != f.version()) {
                        return Ok(Err(Rejection::IdentityConflict));
                    }
                    changed |= existing != Some(f);
                    facts.insert(k, f.clone());
                }
                changed
            }
        };
        if changed {
            input!(aggregate.advance());
            aggregate.at = Some(r.as_of);
        }
        // Immutable checks precede all business writes. Concurrent cross-policy payload conflicts
        // become an outer storage error in STORAGE.freeze(), rolling back the entire transaction.
        if let Some(v) = aggregate.policy.version() {
            input!(compatible_version(tx, v).await?);
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
            || after.as_ref().is_some_and(|s| {
                s.len() > 512
                    || s.split_once('/').is_none_or(|(version, device)| {
                        version
                            .parse::<u64>()
                            .ok()
                            .is_none_or(|n| n == 0 || n.to_string() != version)
                            || DeviceId::new(self.tenant, device).is_err()
                    })
            })
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
    if let Command::RecordExecutions { facts, .. } = &r.command {
        if facts.len() > 1000 {
            return Err(Rejection::BudgetExceeded);
        }
        let mut keys = std::collections::BTreeSet::new();
        for f in facts {
            if f.version().policy() != r.policy() || !keys.insert(f.key()) {
                return Err(Rejection::InvalidInput);
            }
        }
    }
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
async fn load_selected_facts(
    tx: &mut PgTransaction<'_>,
    policy: &PolicyId,
    updates: &[ExecutionRecord],
) -> Result<BTreeMap<String, ExecutionRecord>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let owner = policy.value().to_owned();
    let keys: Vec<_> = updates.iter().map(codec::key).collect();
    let rows=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT key,document,digest FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 AND key=ANY($3)")
            .bind(tenant).bind(owner).bind(keys).fetch_all(c).await
    })).await?;
    let records = decode_fact_page(rows, tx.tenant_id(), policy.value())?;
    Ok(records.into_iter().map(|f| (codec::key(&f), f)).collect())
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
            let mut keys = Vec::with_capacity(docs.len());
            let mut documents = Vec::with_capacity(docs.len());
            let mut digests = Vec::with_capacity(docs.len());
            for (key, digest, document) in docs {
                keys.push(key);
                documents.push(document);
                digests.push(digest);
            }
            sqlx::query(SAVE_FACTS_SQL)
                .bind(t)
                .bind(owner)
                .bind(keys)
                .bind(documents)
                .bind(digests)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
const EXECUTION_FACTS_SQL: &str = "SELECT key,document,digest FROM mdm_policy.facts WHERE tenant_id=$1::uuid AND owner=$2 AND (version,device COLLATE \"C\")>(coalesce(split_part($3,'/',1)::numeric,0),coalesce(substring($3 FROM strpos($3,'/')+1),'') COLLATE \"C\") ORDER BY version,device COLLATE \"C\" LIMIT $4";
const SAVE_FACTS_SQL: &str = "INSERT INTO mdm_policy.facts(tenant_id,owner,key,document,digest) SELECT $1::uuid,$2,k,d,h FROM unnest($3::text[],$4::bytea[],$5::bytea[]) AS batch(k,d,h) ON CONFLICT(tenant_id,owner,key) DO UPDATE SET document=EXCLUDED.document,digest=EXCLUDED.digest WHERE mdm_policy.facts.document<>EXCLUDED.document";

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
