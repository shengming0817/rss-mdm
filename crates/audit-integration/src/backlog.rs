//! One bounded snapshot of source capacity; never scans or decodes pending payloads.
use crate::{AuditStore, BacklogLimits, Error};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use serde::Serialize;
use sqlx::Row;
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BacklogSnapshot {
    pub events: u64,
    /// Exact frozen source payload bytes, excluding PostgreSQL physical overhead.
    pub source_bytes: u64,
    pub reserved_events: u64,
    pub reserved_source_bytes: u64,
    pub max_events: u64,
    pub max_source_bytes: u64,
    pub oldest_seconds: Option<u64>,
    pub warning: bool,
    pub admission_closed: bool,
    pub reserve_exhausted: bool,
}
impl BacklogSnapshot {
    fn new(values: [u64; 4], oldest_seconds: Option<u64>, limits: BacklogLimits) -> Self {
        let [events, source_bytes, reserved_events, reserved_source_bytes] = values;
        let max_events = limits.events();
        let max_source_bytes = limits.bytes();
        Self {
            events,
            source_bytes,
            reserved_events,
            reserved_source_bytes,
            max_events,
            max_source_bytes,
            oldest_seconds,
            warning: (events as u128) * 5 >= (max_events as u128) * 4
                || (source_bytes as u128) * 5 >= (max_source_bytes as u128) * 4
                || oldest_seconds.is_some_and(|age| age > 300),
            admission_closed: events >= max_events || source_bytes >= max_source_bytes,
            reserve_exhausted: reserved_events >= max_events.div_ceil(10)
                || reserved_source_bytes >= max_source_bytes.div_ceil(10),
        }
    }
}
impl AuditStore {
    pub async fn backlog(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<BacklogSnapshot, Error> {
        let raw = self.runtime.local_tx(tenant, deadline, |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("SELECT coalesce(b.events,0) AS events,coalesce(b.bytes,0) AS bytes,coalesce(b.reserved_events,0) AS reserved_events,coalesce(b.reserved_bytes,0) AS reserved_bytes, (SELECT greatest(0,floor(extract(epoch FROM clock_timestamp()))::bigint-enqueued_at) FROM mdm_audit.receipts WHERE tenant_id=$1::uuid AND projected_at IS NULL ORDER BY enqueued_at LIMIT 1) AS oldest FROM (SELECT 1) seed LEFT JOIN mdm_audit.backlog b ON b.tenant_id=$1::uuid")
                    .bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok, |e| Err(Error::Audit(e.into())), |e| Err(Error::Audit(e.into())),
            |_| Err(Error::RollbackFailed), |_| Err(Error::CommitUnknown), |e| Err(Error::Audit(e.into())))?;
        let count = |name| -> Result<u64, Error> {
            u64::try_from(raw.try_get::<i64, _>(name)?).map_err(|_| Error::Receipt)
        };
        let values = [
            count("events")?,
            count("bytes")?,
            count("reserved_events")?,
            count("reserved_bytes")?,
        ];
        let oldest = raw
            .try_get::<Option<i64>, _>("oldest")?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| Error::Receipt)?;
        if (values[0] > 0 || values[2] > 0) != oldest.is_some() {
            return Err(Error::Receipt);
        }
        Ok(BacklogSnapshot::new(values, oldest, self.limits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_and_age_warn_before_admission_closes_and_reserve_is_independent() {
        let limits = BacklogLimits::new(100, 1000).unwrap();
        let normal = BacklogSnapshot::new([79, 799, 0, 0], Some(300), limits);
        assert!(!normal.warning && !normal.admission_closed && !normal.reserve_exhausted);
        for (counts, age) in [
            ([80, 0, 0, 0], None),
            ([0, 800, 0, 0], None),
            ([1, 1, 0, 0], Some(301)),
        ] {
            let state = BacklogSnapshot::new(counts, age, limits);
            assert!(state.warning && !state.admission_closed);
        }
        let full = BacklogSnapshot::new([100, 900, 0, 0], Some(1), limits);
        assert!(full.admission_closed && !full.reserve_exhausted);
        assert!(BacklogSnapshot::new([100, 900, 10, 10], Some(1), limits).reserve_exhausted);
        assert!(BacklogSnapshot::new([100, 900, 1, 100], Some(1), limits).reserve_exhausted);
        let huge = BacklogLimits::new(i64::MAX as u64 / 2, i64::MAX as u64 / 2).unwrap();
        assert!(
            !BacklogSnapshot::new([huge.events() / 2, huge.bytes() / 2, 0, 0], None, huge).warning
        );
    }
}
