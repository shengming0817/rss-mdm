use crate::error::Error;
use crate::{
    codec,
    core::*,
    db::{self, *},
    error::*,
    event,
};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc};
/// Closed set of persistent aggregate mutations.
#[derive(Clone, Debug)]
pub enum Command {
    /// Create an initially empty aggregate.
    Create(Kind),
    /// Insert a new immutable resource version.
    Insert(Version),
    /// Make a frozen version active according to the core lifecycle.
    Activate(Id),
    /// Deprecate the specified version without deleting its content or history.
    Deprecate(Id),
    /// Archive only after the companion has counted references under the same resource lock.
    Archive {
        /// Exact immutable version to archive.
        version: Id,
        /// Reference count attested by the companion while holding the resource lock; must be zero.
        references: u64,
    },
}
/// Complete, immutable caller request. Preserve identity, time, expected revision and command during recovery.
#[derive(Clone, Debug)]
pub struct Request {
    /// Stable identity; changing a request body under an existing request identity is rejected.
    pub id: Id,
    /// Resource identity or restored resource value in this store tenant.
    pub resource: Id,
    /// The sole expected aggregate CAS token; zero is required for creation.
    pub expected_storage_revision: u64,
    /// Caller-fixed observation time; preserve it on request replay.
    pub as_of: Timepoint,
    /// The complete requested mutation, included in the request fingerprint.
    pub command: Command,
}
/// Validated core Resource and its adapter concurrency token.
#[derive(Clone, Debug)]
pub struct StoredResource {
    /// Resource identity or restored resource value in this store tenant.
    pub resource: Resource,
    /// Aggregate storage revision observed after the operation.
    pub storage_revision: u64,
}
/// Immutable response to the original request; replay does not rewrite this snapshot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Resource identity or restored resource value in this store tenant.
    pub resource: String,
    /// Original request identity associated with this receipt.
    pub request: String,
    /// Aggregate storage revision observed after the operation.
    pub storage_revision: u64,
}
/// Tenant-bound immutable Resource versions and lifecycle persistence.
pub struct ResourceStore {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    writer: PgOutboxWriter,
}
impl ResourceStore {
    /// Admit the exact schema and effective runtime privileges, then borrow the host runtime.
    /// Returns a settlement error on admission failure; never migrates or closes the runtime.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        d: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, d, |tx| {
                    Box::pin(async move {
                        verify(tx).await?;
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
        id: &Id,
        d: OperationDeadline,
    ) -> Result<Option<StoredResource>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, id), |(s, id), tx| {
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
        id: &Id,
    ) -> InTransaction<Option<StoredResource>> {
        input!(self.check(tx)?);
        let Some((revision, document)) = db::read(tx, id.as_str()).await? else {
            return Ok(Ok(None));
        };
        let t = self.tenant.to_string();
        let owner = id.as_str().to_owned();
        let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT key,document,digest FROM mdm_resource.immutable WHERE tenant_id=$1::uuid AND owner=$2 AND kind='version' ORDER BY key COLLATE \"C\" LIMIT 10001").bind(t).bind(owner).fetch_all(c).await})).await?;
        if rows.len() > 10_000 {
            return Err(fault());
        }
        let mut versions = BTreeMap::new();
        let mut size = 0;
        for row in rows {
            let bytes = checked(row.try_get("document")?, row.try_get("digest")?)?;
            size += bytes.len();
            if size > MAX_DOCUMENT {
                return Err(fault());
            }
            let v = codec::read_version(&bytes)?;
            if v.tenant() != self.tenant
                || v.resource() != id
                || v.label().as_str() != row.try_get::<String, _>("key")?
            {
                return Err(fault());
            }
            versions.insert(v.label().as_str().into(), v);
        }
        let resource = codec::restore(&document, versions)?;
        let s = resource.snapshot();
        if s.tenant != self.tenant || &s.key != id {
            return Err(fault());
        }
        Ok(Ok(Some(StoredResource {
            resource,
            storage_revision: revision,
        })))
    }
    /// Lock the resource aggregate and return its immutable version, state and storage revision.
    /// Hold this borrowed transaction while adding references or checking archive eligibility.
    pub async fn lock_version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &Id,
        version: &Id,
    ) -> InTransaction<(Version, State, u64)> {
        input!(self.check(tx)?);
        lock(tx, "resource", id.as_str()).await?;
        let s = input!(input!(self.get_in(tx, id).await?).ok_or(Rejection::NotFound));
        let v = input!(s.resource.version(version).map_err(|_| Rejection::NotFound));
        let state = data(s.resource.state(version))?;
        Ok(Ok((v.clone(), state, s.storage_revision)))
    }
    /// Execute one fixed request atomically with its receipt and necessary RSS Outbox event.
    /// An identical request replays before CAS; on `CommitUnknown`, retain the original request and query its receipt.
    pub async fn execute(&self, r: &Request, d: OperationDeadline) -> Result<Receipt, Error> {
        if matches!(r.command, Command::Archive { .. }) {
            return Err(Rejection::CompanionRequired.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (self, r), |(s, r), tx| {
                    Box::pin(async move { s.execute_in(tx, r).await })
                })
                .await,
        )
    }
    /// Archive requires the host to lock/check all external references in this same transaction.
    pub async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        r: &Request,
    ) -> InTransaction<Receipt> {
        input!(self.check(tx)?);
        let request_document = request_document(self.tenant, r)?;
        let hash = digest(&request_document);
        lock(tx, "resource", r.resource.as_str()).await?;
        lock(tx, "request", r.id.as_str()).await?;
        if let Some((owner, old, b)) = db::receipt(tx, r.id.as_str()).await? {
            if owner != r.resource.as_str() || old != hash {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return Ok(Ok(decode(&b)?));
        }
        let old = input!(self.get_in(tx, &r.resource).await?);
        let create = matches!(r.command, Command::Create(_));
        if create && old.is_some() {
            return Ok(Err(Rejection::Conflict));
        }
        let (mut resource, revision) = if let Command::Create(kind) = r.command {
            (Resource::new(self.tenant, r.resource.clone(), kind), 0)
        } else {
            let old = input!(old.ok_or(Rejection::NotFound));
            (old.resource, old.storage_revision)
        };
        if revision != r.expected_storage_revision {
            return Ok(Err(Rejection::Conflict));
        }
        let before = codec::header(&resource)?;
        let result = match &r.command {
            Command::Create(_) => Ok(()),
            Command::Insert(v) => resource.insert(v.clone(), r.as_of).map(|_| ()),
            Command::Activate(v) => resource.activate(v, r.as_of),
            Command::Deprecate(v) => resource.deprecate(v, r.as_of),
            Command::Archive {
                version,
                references,
            } => resource.archive(
                version,
                &References::new(
                    self.tenant,
                    r.resource.clone(),
                    version.clone(),
                    true,
                    *references,
                ),
                r.as_of,
            ),
        };
        input!(result.map_err(|e| match e {
            crate::core::Error::Referenced => Rejection::Referenced,
            crate::core::Error::TenantMismatch => Rejection::TenantMismatch,
            crate::core::Error::IdentityConflict => Rejection::IdentityConflict,
            _ => Rejection::InvalidInput,
        }));
        let snapshot = resource.snapshot();
        if snapshot.versions.len() > 10_000 {
            return Ok(Err(Rejection::BudgetExceeded));
        }
        let mut total = 0usize;
        for entry in &snapshot.versions {
            total += codec::version(&entry.version)?.len();
            if total > MAX_DOCUMENT {
                return Ok(Err(Rejection::BudgetExceeded));
            }
        }
        let document = codec::header(&resource)?;
        let changed = create || before != document;
        let next = if changed {
            input!(
                revision
                    .checked_add(1)
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or(Rejection::Conflict)
            )
        } else {
            revision
        };
        if let Command::Insert(v) = &r.command
            && let Some(old) =
                db::immutable(tx, r.resource.as_str(), "version", v.label().as_str()).await?
            && old != codec::version(v)?
        {
            return Ok(Err(Rejection::IdentityConflict));
        }
        if changed {
            db::write(
                tx,
                r.resource.as_str(),
                if create { None } else { Some(revision) },
                next,
                document,
            )
            .await?;
            if let Command::Insert(v) = &r.command {
                freeze(
                    tx,
                    r.resource.as_str(),
                    "version",
                    v.label().as_str(),
                    codec::version(v)?,
                )
                .await?;
            }
            event::append(
                &self.writer,
                tx,
                self.tenant,
                r.as_of,
                r.resource.as_str(),
                r.id.as_str(),
                next,
            )
            .await?;
        }
        let receipt = Receipt {
            resource: r.resource.as_str().into(),
            request: r.id.as_str().into(),
            storage_revision: next,
        };
        db::save_receipt(
            tx,
            r.id.as_str(),
            r.resource.as_str(),
            hash,
            request_document,
            encode(&receipt)?,
        )
        .await?;
        Ok(Ok(receipt))
    }
    /// Read the original durable request receipt without changing current aggregate state.
    /// Use this after an unconfirmed commit; absence alone is not permission to invent another request identity.
    pub async fn operation(&self, id: &Id, d: OperationDeadline) -> Result<Option<Receipt>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, id, |id, tx| {
                    Box::pin(async move {
                        Ok(Ok(db::receipt(tx, id.as_str())
                            .await?
                            .map(|(_, _, b)| decode(&b))
                            .transpose()?))
                    })
                })
                .await,
        )
    }
    /// Read one validated immutable version, including historical versions.
    pub async fn version(
        &self,
        id: &Id,
        label: &Id,
        d: OperationDeadline,
    ) -> Result<Option<Version>, Error> {
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, d, (id, label), |(id, label), tx| {
                    Box::pin(async move {
                        let value = db::immutable(tx, id.as_str(), "version", label.as_str())
                            .await?
                            .map(|b| codec::read_version(&b))
                            .transpose()?;
                        if value.as_ref().is_some_and(|v| {
                            v.tenant() != tx.tenant_id()
                                || v.resource() != *id
                                || v.label() != *label
                        }) {
                            return Err(fault());
                        }
                        Ok(Ok(value))
                    })
                })
                .await,
        )
    }
}
fn request_document(t: TenantId, r: &Request) -> Result<Vec<u8>, PgError> {
    let command = match &r.command {
        Command::Create(k) => json!([0, codec::kind(*k)]),
        Command::Insert(v) => json!([1, decode::<Value>(&codec::version(v)?)?]),
        Command::Activate(v) => json!([2, v.as_str()]),
        Command::Deprecate(v) => json!([3, v.as_str()]),
        Command::Archive {
            version,
            references,
        } => json!([4, version.as_str(), references]),
    };
    encode(&json!([
        1,
        t.to_string(),
        r.id.as_str(),
        r.resource.as_str(),
        r.expected_storage_revision,
        r.as_of.unix_seconds(),
        command
    ]))
}
