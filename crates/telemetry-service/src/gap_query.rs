//! Device loss diagnostics. No field coverage, sampled values or source authority is inferred.
use crate::{Error, Service};
use rss_mdm_agent_wire::runtime::TelemetryGapReport;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

/// Ordering coordinate only; every page repeats current device authorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cursor {
    pub received_at: i64,
    pub report_id: uuid::Uuid,
}
/// Bounded receipt-time query for one device, including its previous registration diagnostics.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub device: String,
    pub received_from: i64,
    pub received_until: i64,
    pub limit: NonZeroU32,
    pub after: Option<Cursor>,
}
/// A stored self-report with the receiver's timestamp, not a sampled metric.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub report: TelemetryGapReport,
    pub received_at: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub reports: Vec<Report>,
    pub next: Option<Cursor>,
}
impl Service {
    pub async fn gaps(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: &Request,
        audit: &RequestAudit,
    ) -> Result<Page, Error> {
        proof.check_live().map_err(|_| Error::Denied)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Denied);
        }
        if input.device.is_empty()
            || input.device.len() > 512
            || input.device.chars().any(char::is_control)
            || input.received_from < 0
            || input.received_until <= input.received_from
            || input.limit.get() > 256
            || input.after.as_ref().is_some_and(|c| {
                c.received_at < input.received_from
                    || c.received_at >= input.received_until
                    || c.report_id.is_nil()
            })
        {
            return Err(Error::Invalid);
        }
        let service = self.clone();
        let proof = proof.clone();
        let input = input.clone();
        let _audit = audit.clone();
        let failure = Arc::new(Mutex::new(None));
        let rejected = failure.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    service
                        .planning
                        .audit_store
                        .bind_in(tx)
                        .await
                        .map_err(crate::storage_error)?;
                    let read_service = service.clone();
                    let page = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                read_on(&read_service, c, &proof, &input)
                                    .await
                                    .map_err(|e| {
                                        *rejected.lock().expect("gap query rejection") = Some(e);
                                        sqlx::Error::Protocol("gap query rejected".into())
                                    })
                            })
                        })
                        .await?;

                    Ok(page)
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| {
                    Err(failure
                        .lock()
                        .expect("gap query rejection")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn read_on(
    service: &Service,
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    input: &Request,
) -> Result<Page, Error> {
    rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
        .await
        .map_err(|_| Error::Denied)?;
    let authorization =
        rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(|_| Error::Denied)?;
    authorization
        .require(proof, Permission::InventoryRead, Some(&input.device))
        .map_err(|_| Error::Denied)?;
    let rows = sqlx::query("SELECT id,report,received_at FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid AND device=$2 AND received_at>=$3 AND received_at<$4 AND expires_at>floor(extract(epoch FROM clock_timestamp())*1000000)::bigint AND ($5::bigint IS NULL OR (received_at,id)>($5,$6)) ORDER BY received_at,id LIMIT $7")
        .bind(service.tenant.to_string()).bind(&input.device).bind(input.received_from).bind(input.received_until)
        .bind(input.after.as_ref().map(|v| v.received_at)).bind(input.after.as_ref().map(|v| v.report_id))
        .bind(i64::from(input.limit.get()) + 1).fetch_all(c).await?;
    let more = rows.len() > input.limit.get() as usize;
    let mut reports = Vec::new();
    let mut next = None;
    for row in rows.into_iter().take(input.limit.get() as usize) {
        let received_at = row.try_get("received_at")?;
        next = Some(Cursor {
            received_at,
            report_id: row.try_get("id")?,
        });
        let report = serde_json::from_value(row.try_get("report")?).map_err(|_| Error::Storage)?;
        reports.push(Report {
            report,
            received_at,
        });
    }
    proof.check_live().map_err(|_| Error::Denied)?;
    Ok(Page {
        reports,
        next: if more { next } else { None },
    })
}
