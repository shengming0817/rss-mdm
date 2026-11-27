use super::*;
use rss_observation::{
    Body, Change, Coverage, Epoch, Id, LifecycleGrant, Policy, Registration, Scope, VerifiedBatch,
};
use sqlx::Row;

pub(super) fn scope(
    tenant: TenantId,
    installation: Uuid,
    device: Uuid,
    epoch: Uuid,
    kind: &str,
) -> Result<Scope, rss_observation::Error> {
    Ok(Scope::new(
        tenant,
        Id::new(format!("{device}:{kind}"))?,
        Registration::new(epoch.to_string())?,
        Id::new(installation.to_string())?,
        Id::new(kind)?,
        Epoch::new(epoch.to_string())?,
    ))
}
struct Accepted<'a>(&'a Scope, &'a Batch);
impl Authority for Accepted<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_observation::Error> {
        if match access {
            Access::Activate { scope } => scope == self.0,
            Access::Submit { scope, coverage } => scope == self.0 && coverage == self.1.coverage(),
            _ => false,
        } {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
fn report(
    kind: &str,
    sequence: i64,
    received: i64,
    document: serde_json::Value,
) -> Result<Batch, Error> {
    let id = |v: &str| Id::new(v).map_err(|_| Error::Corrupt);
    let coverage = Coverage::new(id(kind)?, id("1")?, id("rss.da.diagnostic")?, id("json")?);
    let bytes = serde_json::to_vec(&document).map_err(|_| Error::Corrupt)?;
    Batch::new(
        id(&sequence.to_string())?,
        u64::try_from(sequence).map_err(|_| Error::Corrupt)?,
        rss_contract::Timepoint::try_from(received).map_err(|_| Error::Corrupt)?,
        coverage,
        Body::Snapshot(vec![Change::upsert(id("report")?, bytes)]),
    )
    .map_err(|_| Error::Corrupt)
}
impl Worker {
    pub(super) async fn deliver(&self, deadline: Deadline) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await.map_err(crate::database::db)?;
        fence(&mut tx, self.binding)
            .await
            .map_err(crate::database::db)?;
        // The oldest pending member of each stream must commit before its successor.
        let row=sqlx::query("SELECT device,registration_epoch,kind,sequence,stream_revision,received_at,document,storage_epoch FROM rss_da.report_history h WHERE tenant_id=$1::uuid AND delivery_pending AND NOT EXISTS (SELECT FROM rss_da.report_history p WHERE (p.tenant_id,p.device,p.kind)=(h.tenant_id,h.device,h.kind) AND p.delivery_pending AND (p.stream_revision,p.sequence)<(h.stream_revision,h.sequence)) ORDER BY received_at,device,kind LIMIT 1 FOR UPDATE OF h")
           .bind(self.binding.tenant().to_string()).fetch_optional(&mut *tx).await.map_err(crate::database::db)?;
        let Some(row) = row else {
            tx.rollback().await.map_err(crate::database::db)?;
            return Ok(false);
        };
        let epoch: i64 = row.try_get("storage_epoch").map_err(crate::database::db)?;
        if epoch != self.binding.epoch().get() {
            return Err(Error::Conflict);
        }
        let device: Uuid = row.try_get("device").map_err(crate::database::db)?;
        let registration: Uuid = row
            .try_get("registration_epoch")
            .map_err(crate::database::db)?;
        let kind: String = row.try_get("kind").map_err(crate::database::db)?;
        let sequence: i64 = row.try_get("sequence").map_err(crate::database::db)?;
        let revision: i64 = row
            .try_get("stream_revision")
            .map_err(crate::database::db)?;
        let scope = scope(
            self.binding.tenant(),
            self.installation,
            device,
            registration,
            &kind,
        )
        .map_err(|_| Error::Corrupt)?;
        let batch = report(
            &kind,
            sequence,
            row.try_get("received_at").map_err(crate::database::db)?,
            row.try_get("document").map_err(crate::database::db)?,
        )?;
        let authorized = Accepted(&scope, &batch);
        let lifecycle =
            LifecycleGrant::verify(&authorized, scope.clone()).map_err(|_| Error::Forbidden)?;
        let verified = VerifiedBatch::verify(&authorized, scope.clone(), batch.clone())
            .map_err(|_| Error::Forbidden)?;
        let previous = u64::try_from(revision - 1).map_err(|_| Error::Corrupt)?;
        self.observation
            .activate(
                &lifecycle,
                (previous > 0).then_some(previous),
                &Policy::new(86400, 3600, 3600).map_err(|_| Error::Configuration)?,
                deadline,
            )
            .await
            .map_err(|_| Error::Storage)?;
        if let Err(e) = self.observation.receive(&verified, deadline).await
            && e.kind() != rss_observation::ErrorKind::HistoryExpired
        {
            return Err(Error::Storage);
        }
        sqlx::query("UPDATE rss_da.report_history SET delivery_pending=false WHERE tenant_id=$1::uuid AND device=$2 AND registration_epoch=$3 AND kind=$4 AND sequence=$5")
           .bind(self.binding.tenant().to_string()).bind(device).bind(registration).bind(&kind).bind(sequence).execute(&mut *tx).await.map_err(crate::database::db)?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(true)
    }
}
