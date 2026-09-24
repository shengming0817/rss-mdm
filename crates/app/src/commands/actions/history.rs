//! Bounded run summaries and separately authorized full execution evidence.
use super::storage as db;
use crate::commands::{Commands, storage};
use crate::{Error, audit::Audit, authorization::Permission, identity::Principal};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Page {
    pub after_at: Option<i64>,
    pub after_id: Option<Uuid>,
}
impl Commands {
    pub(super) async fn action_runs(
        &self,
        proof: &Principal,
        id: Uuid,
        page: &Page,
        audit: &Audit,
    ) -> Result<Value, Error> {
        if page.after_at.is_some() != page.after_id.is_some()
            || page.after_at.is_some_and(|at| at < 0)
            || page.after_id.is_some_and(|id| id.is_nil())
        {
            return Err(Error::Malformed);
        }
        self.transact((proof,id,page,audit),audit,|ctx,tx|Box::pin(async move {
            let (proof,id,page,audit)=*ctx;
            storage::lock(tx,"action-owner").await?;
            let plan=db::load_plan(tx,id).await?;
            for device in &plan.frozen.input.devices {storage::authorized(tx,proof,device,Permission::OperationRead).await?;}
            let tenant=tx.tenant_id().to_string();let at=page.after_at;let after=page.after_id.map(|id|id.to_string());
            let mut rows=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('taskId',id,'device',device,'registrationId',registration,'generation',generation,'occurrence',occurrence,'availableAt',available_at,'deadline',deadline,'state',state,'effect','unverified','result',CASE WHEN result IS NULL THEN NULL ELSE (result-'output') || jsonb_build_object('diagnostics',(result->'diagnostics')-'stdout'-'stderr') END) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND ($3::bigint IS NULL OR (available_at,id)<($3,$4::uuid)) ORDER BY available_at DESC,id DESC LIMIT 21")
                    .bind(tenant).bind(id.to_string()).bind(at).bind(after).fetch_all(c).await
            })).await?;
            let more=rows.len()>20;rows.truncate(20);
            let next=if more {rows.last().map(|row|json!({"availableAt":row["availableAt"],"taskId":row["taskId"]}))}else{None};
            storage::audit(tx,audit,200).await?;
            Ok(json!({"items":rows,"nextCursor":next}))
        })).await
    }
    pub(super) async fn action_run(
        &self,
        proof: &Principal,
        plan: Uuid,
        id: Uuid,
        audit: &Audit,
    ) -> Result<Value, Error> {
        self.transact((proof,plan,id,audit),audit,|ctx,tx|Box::pin(async move {
            let (proof,plan,id,audit)=*ctx;
            storage::lock(tx,"action-owner").await?;
            let run=db::load_run(tx,id).await?;
            if run.plan!=plan{return Err(Error::NotFound.into());}
            storage::authorized(tx,proof,&run.target.device,Permission::OperationRead).await?;
            storage::audit(tx,audit,200).await?;
            Ok(json!({"planId":plan,"taskId":id,"device":run.target.device,"registrationId":run.target.registration,"generation":run.target.generation,"availableAt":run.available_at,"deadline":run.deadline,"state":run.state,"effect":"unverified","result":run.result}))
        })).await
    }
}
