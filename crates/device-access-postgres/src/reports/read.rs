use super::*;
use crate::database::db;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::window;
use sqlx::Row;
pub static WINDOW: window::Schema = window::Schema {
    id: "da_report_history",
    default_limit: 64,
    max_limit: 100,
    order: "sequence desc",
    purpose: rss_mdm_query::window::Purpose::History,
    reason: "Immutable history coordinates define navigation; mutable business directories use model-derived RSQL",
    context: &["kind"],
};
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub kind: Kind,
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}
/// Closed wire snapshots; persistence is decoded according to the requested stream.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Report {
    Status(da::StatusReport),
    Application(da::ApplicationReport),
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub receipt: Receipt,
    pub stale: bool,
    pub report: Report,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub items: Vec<View>,
    pub next_cursor: Option<String>,
}
/// Device-reported values specific to the two authenticated DA report types.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged, rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum AssetFacts {
    Status {
        client_version: String,
        modules: da::ClientModules,
        health: da::Health,
        binding: da::Health,
        factor: da::Health,
        configuration_digest: Option<String>,
    },
    Application {
        artifact: Uuid,
        digest: String,
        state: da::ApplicationState,
        sources: Vec<da::ReportedSource>,
        operation_id: Uuid,
    },
}
/// Latest committed Inventory fact for one authenticated DA report stream.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub kind: Kind,
    pub registration_epoch: Uuid,
    pub sequence: i64,
    pub position: i64,
    pub received_at: i64,
    pub evidence: da::EvidenceLevel,
    pub facts: AssetFacts,
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Malformed,
    }
}
async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<String, Error> {
    rss_mdm_authorization_service::lock_shared_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    let scope = rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    scope.require(p, Permission::OperationRead, Some(device))?;
    scope.query_binding(p).map_err(Into::into)
}
impl Service {
    pub async fn inventory_assets(
        &self,
        p: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Vec<Asset>, Error> {
        if !self.project_reports {
            return Err(Error::Unsupported);
        }
        self.read_with_session(p,(self,p,device),|ctx,c|Box::pin(async move{
            let (service,p,device)=*ctx;
            authorize(c,p,device).await?;
            let epoch=endpoints::current_da_epoch_in(c,p.tenant_id(),device).await?;
            let rows=sqlx::query("SELECT kind,sequence,position,received_at,facts FROM rss_da.inventory_assets WHERE tenant_id=$1::uuid AND installation=$2 AND device=$3 AND registration_epoch=$4 AND generation=$5 ORDER BY kind")
                .bind(p.tenant_id()).bind(service.service_id()?).bind(device.into_uuid()).bind(epoch).bind(inventory::GENERATION).fetch_all(c).await.map_err(db)?;
            rows.into_iter().map(|r|Ok(Asset{kind:match r.try_get::<&str,_>("kind").map_err(db)?{"status"=>Kind::Status,"application"=>Kind::Application,_=>return Err(Error::Corrupt)},
               registration_epoch:epoch,sequence:r.try_get("sequence").map_err(db)?,position:r.try_get("position").map_err(db)?,received_at:r.try_get("received_at").map_err(db)?,evidence:da::EvidenceLevel::Reported,facts:r.try_get::<sqlx::types::Json<AssetFacts>,_>("facts").map_err(db)?.0})).collect()
        })).await
    }
    pub async fn latest_report(
        &self,
        p: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        kind: Kind,
    ) -> Result<Option<View>, Error> {
        self.read_with_session(p,(self,p,device,kind),|ctx,c|Box::pin(async move{
            let(service,p,device,kind)=*ctx;authorize(c,p,device).await?;
            endpoints::lock_da_in(c,p.tenant_id(),device).await?;
            let epoch=endpoints::current_da_epoch_in(c,p.tenant_id(),device).await?;
            let row=sqlx::query("SELECT document, receipt FROM rss_da.report_heads WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3 AND registration_epoch=$4")
                .bind(p.tenant_id()).bind(device.into_uuid()).bind(kind.name()).bind(epoch).fetch_optional(&mut *c).await.map_err(db)?;
            let now=crate::platform_sso::store::now(c).await?;
            row.map(|r|view(&r,kind,now,service.report_limits.stale_seconds)).transpose()
        })).await
    }
    pub async fn report_history(
        &self,
        p: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        input: &Query,
    ) -> Result<Page, Error> {
        let q = WINDOW
            .page(input.limit, input.cursor.clone(), 4096)
            .map_err(query_error)?;
        self.read_with_session(p,(self,p,device,input,&q),|ctx,c|Box::pin(async move{
            let(service,p,device,input,q)=*ctx;let grants=authorize(c,p,device).await?;
            endpoints::lock_da_in(c,p.tenant_id(),device).await?;
            let epoch=endpoints::current_da_epoch_in(c,p.tenant_id(),device).await?;
            let binding=rss_mdm_query::cursor::fingerprint(&("da.reports.v1",p.tenant_id(),p.instance_id(),p.principal_id(),grants,device,epoch,input.kind,q.limit())).map_err(query_error)?;
            let after:Option<i64>=input.cursor.as_ref().map(|v|service.cursor.decode_bounded(v,&binding,4096)).transpose().map_err(query_error)?;
            let now=crate::platform_sso::store::now(c).await?;
            let mut rows=sqlx::query("SELECT sequence, document, receipt FROM rss_da.report_history WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3 AND registration_epoch=$7 AND received_at > $4 AND (CAST($5 AS bigint) IS NULL OR sequence < $5) ORDER BY sequence DESC LIMIT $6")
                .bind(p.tenant_id()).bind(device.into_uuid()).bind(input.kind.name()).bind(now-i64::from(service.report_limits.history_seconds)).bind(after).bind(q.limit() as i64+1).bind(epoch).fetch_all(c).await.map_err(db)?;
            let more=rows.len()>q.limit();rows.truncate(q.limit());
            let next_cursor=if more {Some(service.cursor.encode_bounded(&binding,&rows.last().ok_or(Error::Corrupt)?.try_get::<i64,_>("sequence").map_err(db)?,4096).map_err(query_error)?)}else{None};
            Ok(Page{items:rows.iter().map(|r|view(r,input.kind,now,service.report_limits.stale_seconds)).collect::<Result<_,_>>()?,next_cursor})
        })).await
    }
}
fn view(r: &sqlx::postgres::PgRow, kind: Kind, now: i64, stale: u32) -> Result<View, Error> {
    let receipt: Receipt =
        serde_json::from_value(r.try_get("receipt").map_err(db)?).map_err(|_| Error::Corrupt)?;
    Ok(View {
        stale: now >= receipt.received_at + i64::from(stale),
        receipt,
        report: match kind {
            Kind::Status => Report::Status(
                serde_json::from_value(r.try_get("document").map_err(db)?)
                    .map_err(|_| Error::Corrupt)?,
            ),
            Kind::Application => Report::Application(
                serde_json::from_value(r.try_get("document").map_err(db)?)
                    .map_err(|_| Error::Corrupt)?,
            ),
        },
    })
}
