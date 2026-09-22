//! Bounded views of immutable candidates; host authorization is required per read.
use crate::{core::*, error::*, *};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;

/// Intent partition used as part of a host-signed query cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    /// New desired execution, not an execution fact.
    Add,
    /// New desired version with paginated historical predecessors.
    Supersede,
    /// Preserve existing execution history.
    Retain,
    /// Express cancellation intent without dispatching.
    Cancel,
}
impl IntentKind {
    fn name(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Supersede => "supersede",
            Self::Retain => "retain",
            Self::Cancel => "cancel",
        }
    }
}
/// Position within a fixed candidate and intent partition.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentPosition {
    /// Last device read in binary lexical order.
    pub device: String,
    /// Last execution key within this device (empty for desired intents).
    pub execution: String,
}
/// A bounded desired or existing-execution decision.
#[derive(Clone, Debug)]
pub enum CandidateIntent {
    /// Desired execution only; a superseding intent's history is separately read.
    Desired {
        /// Target device identity.
        device: DeviceId,
        /// Canonical policy version.
        version: u64,
        /// Whether older executions exist.
        supersedes: bool,
    },
    /// Existing execution retained with a core reason.
    Retain {
        /// Immutable execution fact at candidate admission.
        execution: ExecutionRecord,
        /// Core lifecycle decision.
        reason: RetainReason,
    },
    /// Existing execution for which cancellation is requested.
    Cancel {
        /// Immutable execution fact at candidate admission.
        execution: ExecutionRecord,
        /// Core lifecycle decision.
        reason: CancelReason,
    },
}
/// One immutable decision with its continuation position.
#[derive(Clone, Debug)]
pub struct CandidateIntentRow {
    /// Position to bind into a query cursor.
    pub position: IntentPosition,
    /// Typed semantic decision; never a storage JSON dump.
    pub intent: CandidateIntent,
}
impl PolicyStore {
    /// Read complete immutable targets, at most 1,000 devices per transaction.
    pub async fn candidate_targets_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<Vec<String>> {
        input!(self.check(tx)?);
        if !(1..=1000).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let candidate = input!(self.candidate_in(tx, id).await?);
        if !matches!(
            candidate.phase,
            CandidatePhase::Ready | CandidatePhase::Saved
        ) {
            return Ok(Err(Rejection::Conflict));
        }
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        Ok(Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_policy.candidate_targets WHERE tenant_id=$1::uuid AND candidate=$2 AND ($3::text IS NULL OR device>$3 COLLATE \"C\") ORDER BY device LIMIT $4")
                .bind(tenant).bind(key).bind(after).bind(limit as i64).fetch_all(c).await
        })).await?))
    }
    /// Read one intent partition with a 1,000-object / 16 MiB bound. A host may
    /// continue after the last returned row; an empty page proves exhaustion.
    pub async fn candidate_intents_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &RequestId,
        kind: IntentKind,
        after: Option<IntentPosition>,
        limit: usize,
    ) -> InTransaction<Vec<CandidateIntentRow>> {
        input!(self.check(tx)?);
        if !(1..=1000).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let candidate = input!(self.candidate_in(tx, id).await?);
        if !matches!(
            candidate.phase,
            CandidatePhase::Ready | CandidatePhase::Saved
        ) {
            return Ok(Err(Rejection::Conflict));
        }
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        // Only metadata is materialized before selecting the bounded payload.
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,execution_key,octet_length(document) AS bytes FROM mdm_policy.candidate_intents WHERE tenant_id=$1::uuid AND candidate=$2 AND kind=$3 AND ($4::text IS NULL OR (device,execution_key)>($4 COLLATE \"C\",$5 COLLATE \"C\")) ORDER BY device,execution_key LIMIT $6")
                .bind(tenant).bind(key).bind(kind.name()).bind(after.as_ref().map(|p|&p.device)).bind(after.as_ref().map(|p|&p.execution)).bind(limit as i64).fetch_all(c).await
        })).await?;
        let mut devices = Vec::new();
        let mut keys = Vec::new();
        let mut bytes = 0usize;
        for row in metadata {
            let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
            if bytes + size > 16 * 1024 * 1024 {
                break;
            }
            bytes += size;
            devices.push(row.try_get::<String, _>("device")?);
            keys.push(row.try_get::<String, _>("execution_key")?);
        }
        let tenant = self.tenant.to_string();
        let key = id.value().to_owned();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT i.device,i.execution_key,i.document,i.digest FROM unnest($4::text[],$5::text[]) AS p(device,key) JOIN mdm_policy.candidate_intents i ON i.device=p.device AND i.execution_key=p.key WHERE i.tenant_id=$1::uuid AND i.candidate=$2 AND i.kind=$3 ORDER BY i.device,i.execution_key")
                .bind(tenant).bind(key).bind(kind.name()).bind(devices).bind(keys).fetch_all(c).await
        })).await?;
        let mut result = Vec::new();
        for row in rows {
            let position = IntentPosition {
                device: row.try_get("device")?,
                execution: row.try_get("execution_key")?,
            };
            let document = STORAGE.checked(row.try_get("document")?, row.try_get("digest")?)?;
            let value: serde_json::Value = STORAGE.decode(&document)?;
            if value["kind"].as_str() != Some(kind.name()) {
                return Err(STORAGE.fault("intent::kind"));
            }
            let intent = match kind {
                IntentKind::Add | IntentKind::Supersede => {
                    let device = decode_domain(
                        "intent::device",
                        DeviceId::new(self.tenant, codec::text(&value["device"])?),
                    )?;
                    let version = codec::number(&value["version"])?;
                    if device.value() != position.device
                        || !position.execution.is_empty()
                        || candidate.policy.version().map(Version::number) != Some(version)
                    {
                        return Err(STORAGE.fault("intent::identity"));
                    }
                    CandidateIntent::Desired {
                        device,
                        version,
                        supersedes: kind == IntentKind::Supersede,
                    }
                }
                IntentKind::Retain | IntentKind::Cancel => {
                    let execution = codec::read_fact(&value["execution"])?;
                    if execution.device().value() != position.device
                        || codec::key(&execution) != position.execution
                        || execution.version().policy() != &candidate.request.policy
                    {
                        return Err(STORAGE.fault("intent::identity"));
                    }
                    let reason = codec::text(&value["reason"])?;
                    if kind == IntentKind::Retain {
                        CandidateIntent::Retain {
                            execution,
                            reason: match reason {
                                "current" => RetainReason::Current,
                                "paused" => RetainReason::Paused,
                                "historical" => RetainReason::Historical,
                                _ => return Err(STORAGE.fault("intent::reason")),
                            },
                        }
                    } else {
                        CandidateIntent::Cancel {
                            execution,
                            reason: match reason {
                                "scope_exit" => CancelReason::ScopeExit,
                                "archived" => CancelReason::Archived,
                                "superseded" => CancelReason::Superseded,
                                _ => return Err(STORAGE.fault("intent::reason")),
                            },
                        }
                    }
                }
            };
            result.push(CandidateIntentRow { position, intent });
        }
        Ok(Ok(result))
    }
}
