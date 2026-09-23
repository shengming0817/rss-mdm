use crate::{
    admission, codec,
    event::{self, ChangeKind},
    model::*,
    storage::{self as db, *},
};
use rss_contract::Timepoint;
use rss_mdm_group::Rule;
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    outbox::{AppendOutcome, OutboxWriter},
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgRuntime, PgTransaction};
use serde_json::json;
use std::sync::Arc;

macro_rules! input {
    ($value:expr) => {
        match $value {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        }
    };
}
pub(crate) use input;

/// One tenant's Group adapter. The host owns and closes the shared RSS runtime.
/// Borrowed methods validate the runtime owner and tenant before all reads/writes.
/// Companion callers must propagate SQL errors to the outer
/// local_tx owner, never issue transaction-control SQL or change tenant settings.
pub struct GroupStore {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    writer: PgOutboxWriter,
}
impl GroupStore {
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
            data(PartitionKey::parse(id))?,
        ))
    }

    /// Verify the installed Group catalog/security contract using the host-owned runtime.
    /// The host must keep this same runtime for every borrowed transaction passed to the store.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        settle(
            runtime
                .local_tx(tenant, deadline, |tx| {
                    Box::pin(async move {
                        admission::verify(tx).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
            None,
        )?;
        Ok(Self {
            writer: PgOutboxWriter::new(runtime.clone(), event::domain()),
            runtime,
            tenant,
        })
    }
    /// Return the tenant used for all reads, writes, rules and operation identities.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub(crate) fn check_transaction(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.writer.validate_transaction(tx)?;
        Ok(if self.tenant == tx.tenant_id() {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    /// Read the current group including a tombstone; missing/foreign groups return None.
    pub async fn get(
        &self,
        id: GroupId,
        deadline: OperationDeadline,
    ) -> Result<Option<Group>, Error> {
        settle(
            self.runtime
                .local_tx(self.tenant, deadline, move |tx| {
                    Box::pin(async move { Ok(Ok(db::group(tx, id, false).await?)) })
                })
                .await,
            None,
        )
    }
    /// Read an immutable rule version, including history after logical deletion.
    /// Use `get().rule_version` for the rule belonging to an observed group revision.
    /// Missing or foreign-tenant versions return None; the host authorizes disclosure.
    pub async fn rule(
        &self,
        id: GroupId,
        version: &str,
        deadline: OperationDeadline,
    ) -> Result<Option<Rule>, Error> {
        text(version, false)?;
        if version.len() > 256 {
            return Err(Rejection::InvalidInput.into());
        }
        let version = version.to_owned();
        settle(
            self.runtime
                .local_tx(self.tenant, deadline, move |tx| {
                    Box::pin(async move { Ok(Ok(db::find_rule(tx, id, version).await?)) })
                })
                .await,
            None,
        )
    }
    /// N12 takes this lock before creating/checking references; deletion uses the same lock.
    pub async fn lock_reference_target_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: GroupId,
    ) -> InTransaction<Group> {
        input!(self.check_transaction(tx)?);
        let g = input!(db::group(tx, id, true).await?.ok_or(Rejection::NotFound));
        input!(active(&g));
        Ok(Ok(g))
    }
    /// Read members while holding the reference lock in the host transaction.
    /// N12 must use execute_in to compose deletion, reference checks and audit atomically.
    pub async fn execute(
        &self,
        operation: OperationId,
        as_of: Timepoint,
        command: &Command,
        deadline: OperationDeadline,
    ) -> Result<Receipt, Error> {
        if matches!(command, Command::Delete { .. }) {
            return Err(Rejection::CompanionTransactionRequired.into());
        }
        settle(
            self.runtime
                .local_tx_with_context(self.tenant, deadline, (self, command), move |ctx, tx| {
                    Box::pin(async move {
                        tx.prepare_outbox_partitions(&[ctx
                            .0
                            .partition(&ctx.1.group().to_string())?])
                            .await?;
                        ctx.0.execute_in(tx, operation, as_of, ctx.1).await
                    })
                })
                .await,
            Some(operation),
        )
    }
    /// Stage a complete command and its genuine change event; never commit.
    /// For deletion, N12 must first lock_reference_target_in and check references in this
    /// same transaction. Its success audit must also be staged before the outer commit.
    /// The caller must declare the complete Outbox partition set before business locks.
    pub async fn execute_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: OperationId,
        as_of: Timepoint,
        command: &Command,
    ) -> InTransaction<Receipt> {
        input!(self.check_transaction(tx)?);
        let request = input!(command_document(self.tenant, command));
        let hash = fingerprint(&[
            self.tenant.to_string().as_bytes(),
            &as_of.unix_seconds().to_be_bytes(),
            &request,
        ]);
        let existing = db::group(tx, command.group(), true).await?;
        if let Some(old) = db::operation(tx, operation, true).await? {
            return replay_command(old, command.group(), &hash);
        }
        let (mut group, create) = input!(command_group(command, existing));
        if let Command::SetRule { rule, .. } = command {
            input!(self.check_rule_identity(tx, group.id, rule).await?);
        }
        let previous_count = group.member_count;
        let (kind, rule_to_write) = input!(apply_command(command, &mut group));
        if kind.is_some() && !create {
            group.revision = input!(group.revision.next());
        }
        let removed = if matches!(command, Command::Delete { .. }) {
            group.member_count = 0;
            group.member_version = group.revision.get();
            previous_count
        } else {
            0
        };
        let receipt = Receipt {
            operation,
            group,
            added: 0,
            removed,
        };
        if let Some(kind) = kind {
            self.append(tx, as_of, kind, &receipt).await?;
        }
        if create || kind.is_some() {
            db::save_group(tx, &receipt.group, create).await?;
        }
        if let Some(rule) = rule_to_write {
            db::write_rule(tx, receipt.group.id, rule).await?;
        }
        db::insert_operation(
            tx,
            NewOperation {
                id: operation,
                group: receipt.group.id,
                digest: hash,
                request,
                as_of: as_of.unix_seconds(),
                receipt: receipt.clone(),
            },
        )
        .await?;
        Ok(Ok(receipt))
    }
    async fn check_rule_identity(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        r: &Rule,
    ) -> InTransaction<()> {
        let tenant = self.tenant.to_string();
        let version = r.view().version.to_owned();
        let hash = digest(&data(codec::encode_rule(r))?);
        let old=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,Vec<u8>>("SELECT digest FROM mdm_group.rules WHERE tenant_id=$1::uuid AND group_id=$2::uuid AND version=$3")
            .bind(tenant).bind(group.to_string()).bind(version).fetch_optional(c).await
        })).await?;
        Ok(if old.is_some_and(|h| h != hash) {
            Err(Rejection::IdentityConflict)
        } else {
            Ok(())
        })
    }
    pub(crate) async fn append(
        &self,
        tx: &mut PgTransaction<'_>,
        at: Timepoint,
        kind: ChangeKind,
        receipt: &Receipt,
    ) -> Result<(), PgError> {
        // Check writer provenance before Group DML. A prior message without its atomic receipt
        // indicates corruption, not an invitation to adopt or repair unknown business effects.
        match self
            .writer
            .append(tx, event::message(self.tenant, at, kind, receipt)?)
            .await?
        {
            AppendOutcome::Inserted => Ok(()),
            AppendOutcome::AlreadyPresent => Err(StorageFault::OutboxIdentity.error()),
        }
    }
}

pub(crate) fn active(g: &Group) -> CommandOutcome<()> {
    if g.deleted {
        Err(Rejection::Deleted)
    } else {
        Ok(())
    }
}
pub(crate) fn dynamic(group: &Group, expected: Revision) -> CommandOutcome<()> {
    active(group)?;
    if group.kind != GroupKind::Dynamic {
        return Err(Rejection::KindMismatch);
    }
    if group.revision != expected {
        return Err(Rejection::VersionConflict);
    }
    Ok(())
}
pub(crate) fn core_rejection(e: rss_mdm_group::Error) -> Rejection {
    match e {
        rss_mdm_group::Error::TenantMismatch => Rejection::TenantMismatch,
        rss_mdm_group::Error::IncompleteSnapshot => Rejection::IncompleteSnapshot,
        rss_mdm_group::Error::LimitExceeded(_) => Rejection::PageBudgetExceeded,
        _ => Rejection::InvalidInput,
    }
}
fn text(s: &str, empty: bool) -> CommandOutcome<()> {
    if s.len() > rss_mdm_group::limits::STRING_BYTES
        || s.contains('\0')
        || (!empty && (s.trim().is_empty() || s.chars().any(char::is_control)))
    {
        Err(Rejection::InvalidInput)
    } else {
        Ok(())
    }
}
fn rule_doc(t: TenantId, r: &Rule) -> CommandOutcome<serde_json::Value> {
    if r.view().tenant != t {
        return Err(Rejection::TenantMismatch);
    }
    if r.view().version.len() > 256 {
        return Err(Rejection::InvalidInput);
    }
    serde_json::from_slice(&codec::encode_rule(r).map_err(|_| Rejection::InvalidInput)?)
        .map_err(|_| Rejection::InvalidInput)
}
fn command_document(t: TenantId, c: &Command) -> CommandOutcome<Vec<u8>> {
    let body = match c {
        Command::Create {
            name,
            description,
            definition,
            ..
        } => {
            text(name, false)?;
            text(description, true)?;
            json!({"kind":"create","name":name,"description":description,"rule":match definition {Definition::Static=>None,Definition::Dynamic(r)=>Some(rule_doc(t,r)?)}})
        }
        Command::Edit {
            name, description, ..
        } => {
            text(name, false)?;
            text(description, true)?;
            json!({"kind":"edit","name":name,"description":description})
        }
        Command::SetRule { rule, .. } => json!({"kind":"rule","rule":rule_doc(t,rule)?}),
        Command::Delete { .. } => json!({"kind":"delete"}),
    };
    codec::encode(&json!({"v":1,"group":c.group(),"expected":c.expected(),"command":body}))
        .map_err(|_| Rejection::InvalidInput)
}
fn replay_command(old: StoredOperation, group: GroupId, hash: &[u8]) -> InTransaction<Receipt> {
    if old.group != group || old.digest != hash {
        return Ok(Err(Rejection::IdentityConflict));
    }
    Ok(Ok(old.receipt))
}

fn command_group(command: &Command, existing: Option<Group>) -> CommandOutcome<(Group, bool)> {
    Ok(match (command, existing) {
        (
            Command::Create {
                group,
                name,
                description,
                definition,
            },
            None,
        ) => {
            let (kind, version) = match definition {
                Definition::Static => (GroupKind::Static, None),
                Definition::Dynamic(r) => (GroupKind::Dynamic, Some(r.view().version.into())),
            };
            (
                Group {
                    id: *group,
                    kind,
                    name: name.clone(),
                    description: description.clone(),
                    revision: Revision::new(1)?,
                    member_version: 0,
                    member_count: 0,
                    rule_version: version,
                    deleted: false,
                },
                true,
            )
        }
        (Command::Create { .. }, Some(_)) => return Err(Rejection::IdentityConflict),
        (_, None) => return Err(Rejection::NotFound),
        (_, Some(g)) => {
            active(&g)?;
            if command.expected() != Some(g.revision) {
                return Err(Rejection::VersionConflict);
            }
            (g, false)
        }
    })
}

type AppliedCommand<'a> = (Option<ChangeKind>, Option<&'a Rule>);
fn apply_command<'a>(
    command: &'a Command,
    group: &mut Group,
) -> CommandOutcome<AppliedCommand<'a>> {
    let mut kind = None;
    let mut rule_to_write: Option<&Rule> = None;
    match command {
        Command::Create { definition, .. } => {
            kind = Some(ChangeKind::Created);
            if let Definition::Dynamic(r) = definition {
                rule_to_write = Some(r);
            }
        }
        Command::Edit {
            name, description, ..
        } => {
            if group.name != *name || group.description != *description {
                group.name = name.clone();
                group.description = description.clone();
                kind = Some(ChangeKind::Edited);
            }
        }
        Command::SetRule { rule, .. } => {
            if group.kind != GroupKind::Dynamic {
                return Err(Rejection::KindMismatch);
            }
            if group.rule_version.as_deref() != Some(rule.view().version) {
                group.rule_version = Some(rule.view().version.into());
                kind = Some(ChangeKind::RuleChanged);
                rule_to_write = Some(rule);
            }
        }
        Command::Delete { .. } => {
            group.deleted = true;
            kind = Some(ChangeKind::Deleted);
        }
    }
    Ok((kind, rule_to_write))
}
