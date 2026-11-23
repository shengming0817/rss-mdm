//! Policy-owned durable work records, borrowed from the initiating transaction.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// Original retirement coordinate, independent of the Scope publication that discovers it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetirementOccurrence {
    /// One management request and its original exclusive deadline.
    Explicit {
        /// Original accepted operation.
        trigger: Uuid,
        /// Database acceptance time used to calculate the schedule slot.
        created_at: i64,
        /// Exclusive request deadline in Unix seconds.
        deadline: i64,
    },
    /// Immutable coordinate of one calendar occurrence.
    Calendar {
        /// Scheduled Unix second before jitter.
        at: i64,
    },
}
impl RetirementOccurrence {
    /// Identity understood by the Device owner.
    pub fn identity(self) -> String {
        match self {
            Self::Explicit { trigger, .. } => format!("explicit:{trigger}"),
            Self::Calendar { at } => format!("calendar:{at}"),
        }
    }
}

/// Immutable continuation of one Scope publication's active-trigger scan.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerPage {
    /// Initiating Policy reconciliation job.
    pub publication: Uuid,
    /// Last inspected (deadline, admission ordinal), exclusive.
    pub after: (i64, i64),
    /// Maximum committed admission ordinal under the original Policy lock.
    pub through: i64,
    /// Last deadline present when this publication started.
    pub last_deadline: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Policy-local durable work; no cross-domain dispatcher consumes this type.
pub enum Work {
    /// One accepted lifecycle occurrence and immutable target evidence.
    Lifecycle {
        /// Authored Policy identity.
        policy: Uuid,
        /// Immutable accepted execution version.
        version: Uuid,
        /// Device-owned immutable object evidence.
        object: serde_json::Value,
        /// Original calendar or explicit-trigger occurrence.
        occurrence: String,
        /// Published Scope evidence under which this object qualified.
        scope_result: Uuid,
        /// Last admissible acceptance time, in Unix seconds.
        deadline: i64,
    },
    /// Fan out one fixed occurrence using the work row's device cursor.
    RetirementPage {
        /// Authored Policy identity.
        policy: Uuid,
        /// Frozen publication version.
        version: Uuid,
        /// Original retirement trigger.
        occurrence: RetirementOccurrence,
        /// The Scope refresh that requested a new scan, absent on the original request.
        publication: Option<Uuid>,
    },
    /// Resume one publication's bounded scan of active explicit triggers.
    RetirementRefresh {
        /// Authored Policy identity.
        policy: Uuid,
        /// Frozen publication version.
        version: Uuid,
        /// Trigger scan checkpoint.
        page: TriggerPage,
    },
    /// Advance one independently identified event batch.
    PolicyEvent {
        /// Original accepted event batch.
        batch: Uuid,
    },
    /// Recompute assignments for the current Policy.
    PolicyReconcile {
        /// Authored Policy identity.
        policy: Uuid,
    },
}
impl Work {
    /// Stable persisted work kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RetirementPage { .. } => "retirement_page",
            Self::RetirementRefresh { .. } => "retirement_refresh",
            Self::Lifecycle { .. } => "policy_lifecycle",
            Self::PolicyReconcile { .. } => "policy_reconcile",
            Self::PolicyEvent { .. } => "policy_event",
        }
    }
    /// Business target identifier.
    pub fn target(&self) -> String {
        match self {
            Self::Lifecycle { policy, .. }
            | Self::RetirementPage { policy, .. }
            | Self::RetirementRefresh { policy, .. } => policy.to_string(),
            Self::PolicyReconcile { policy } => policy.to_string(),
            Self::PolicyEvent { batch } => batch.to_string(),
        }
    }
}

use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;
/// Insert the original work and its commit-delivered notification atomically.
pub async fn enqueue_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    input: &Work,
) -> Result<bool, PgError> {
    let epoch = tx.expected_epoch().get();

    let tenant = tx.tenant_id().to_string();
    let document =
        serde_json::to_value(input).map_err(|_| crate::storage(profile).fault("work.input"))?;
    let kind = input.kind();
    let target = input.target();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let inserted = sqlx::query(crate::storage_profile::sql(profile).work_enqueue_in_1)
                .bind(&tenant)
                .bind(id)
                .bind(kind)
                .bind(target)
                .bind(&document)
                .bind(epoch)
                .execute(&mut *c)
                .await?;
            if inserted.rows_affected() == 0 {
                let prior: serde_json::Value =
                    sqlx::query(crate::storage_profile::sql(profile).work_read_in_1)
                        .bind(&tenant)
                        .bind(id)
                        .fetch_one(&mut *c)
                        .await?
                        .try_get("input")?;
                let same = match kind {
                    "retirement_page" | "retirement_refresh" => prior == document,
                    "policy_lifecycle" => {
                        // A later scan must keep the first device work's lifetime.
                        ["kind", "policy", "version", "occurrence", "object"]
                            .iter()
                            .all(|key| prior[*key] == document[*key])
                    }
                    _ => false,
                };
                if !same {
                    return Err(sqlx::Error::Protocol(
                        "policy work identity conflict".into(),
                    ));
                }
                return Ok(false);
            }
            sqlx::query("SELECT pg_notify('mdm_work','policy')")
                .execute(c)
                .await?;
            Ok(true)
        })
    })
    .await
}
/// Durable work observed by the worker; absence is distinct from completion.
pub struct Record {
    /// Original typed work.
    pub input: Work,
    /// Committed retirement outcome or cumulative device-page progress.
    pub retirement_result: Option<serde_json::Value>,
    /// Committed terminal state.
    pub completed: bool,
    /// Closed product failure code, when terminal.
    pub failure: Option<String>,
    /// Last committed page boundary.
    pub cursor: Option<rss_mdm_agent_wire::ObjectRef>,
    /// Whether its RSS wake was committed.
    pub started: bool,
}
/// Read one retained task in the initiating tenant.
pub async fn read_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Record>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).work_read_in_1)
                    .bind(tenant)
                    .bind(id)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?;
    row.map(|r| {
        Ok(Record {
            input: serde_json::from_value(r.try_get("input")?)
                .map_err(|_| crate::storage(profile).fault("work.decode"))?,
            retirement_result: r.try_get("retirement_result")?,
            completed: r.try_get("completed")?,
            failure: r.try_get("failure")?,
            cursor: match (
                r.try_get::<Option<i16>, _>("cursor_kind")?,
                r.try_get::<Option<Uuid>, _>("cursor_id")?,
            ) {
                (None, None) => None,
                (Some(kind), Some(id)) => Some(
                    rss_mdm_agent_wire::ObjectRef::from_parts(kind, id)
                        .map_err(|_| crate::storage(profile).fault("work.cursor"))?,
                ),
                _ => return Err(crate::storage(profile).fault("work.cursor")),
            },
            started: r.try_get("started")?,
        })
    })
    .transpose()
}
/// Device-specific evidence of one original trigger. An accepted intent remains authoritative
/// after subsequent Scope evaluations. Within the other outcomes return the latest dispatch.
pub async fn device_evidence_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    trigger: Uuid,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let occurrence = format!("explicit:{trigger}");
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).work_device_evidence)
                .bind(tenant)
                .bind(occurrence)
                .bind(device.to_string())
                .fetch_optional(c)
                .await
        })
    })
    .await
}
/// Advance a page only in the transaction that published its effects.
pub async fn cursor_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    cursor: Option<rss_mdm_agent_wire::ObjectRef>,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).work_cursor_in_1)
                .bind(tenant)
                .bind(id)
                .bind(cursor.map(|o| o.kind()))
                .bind(cursor.map(|o| o.uuid()))
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}

/// Count a committed device page; empty or unresolved scopes remain distinguishable from dispatch.
pub async fn record_retirement_page_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    eligible: i64,
    pending: i64,
    more: bool,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).work_retirement_counts)
                .bind(tenant)
                .bind(id)
                .bind(eligible)
                .bind(pending)
                .bind(more)
                .fetch_one(c)
                .await
        })
    })
    .await
}

/// Persist the business result in the same protected transaction as task settlement.
pub async fn retirement_result_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    result: serde_json::Value,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).work_retirement_result)
                .bind(tenant)
                .bind(id)
                .bind(result)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}

/// Record actual execution inside the claim-protected business transaction.
pub async fn started_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).work_started_in_1)
                .bind(tenant)
                .bind(id)
                .execute(c)
                .await
                .map(|r| r.rows_affected() > 0)
        })
    })
    .await
}
/// Transition a task to its terminal result, returning its business audit identity once.
pub async fn finish_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    failure: Option<String>,
) -> Result<Option<(String, String)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as(crate::storage_profile::sql(profile).work_finish_in_1)
                .bind(tenant)
                .bind(id)
                .bind(failure)
                .fetch_optional(c)
                .await
        })
    })
    .await
}
/// Check an exact task identity, optionally requiring terminal state.
pub async fn exists_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    completed: bool,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).work_exists_in_1)
                .bind(tenant)
                .bind(id)
                .bind(completed)
                .fetch_one(c)
                .await
        })
    })
    .await
}
/// Record a replacement without changing either accepted identity.
pub async fn replacement_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    old: Uuid,
    new: Uuid,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).work_replacement_in_1)
                .bind(tenant)
                .bind(old)
                .bind(new)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
/// Bounded queue counts for health reporting.
pub async fn counts_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
) -> Result<[u64; 5], PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let row: (i64, i64, i64, i64, i64) =
                sqlx::query_as(crate::storage_profile::sql(profile).work_counts_in_1)
                    .bind(tenant)
                    .fetch_one(c)
                    .await?;
            Ok([
                row.0 as u64,
                row.1 as u64,
                row.2 as u64,
                row.3 as u64,
                row.4 as u64,
            ])
        })
    })
    .await
}
