//! Asset-clock consumer. No registration callback or shared forwarding acknowledgement.
use crate::*;
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_inventory::Channel;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

impl Associations {
    pub fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("device-associations", Duration::from_secs(20));
        task.into_registration(move |stop|async move {
            while !stop.is_cancelled() {
                if self.reconcile().await.is_err() {eprintln!("{}",serde_json::json!({"event":"device_association_reconciliation_unavailable"}));}
                tokio::select!{()=stop.cancelled()=>break,()=tokio::time::sleep(Duration::from_secs(2))=>{}}
            }
            Ok(())
        })
    }
    /// A committed checkpoint covers registration/source/credential and raw inventory changes.
    pub async fn reconcile(&self) -> Result<usize> {
        let budget = AuditBudget::new(Duration::from_secs(15));
        let audit = RequestAudit::new(self.tenant.to_string(), "device_association_automatic");
        audit.identify_service("device-associations");
        let attempt = self.audit.write(self.tenant,&budget.control(),(self,&audit),|(service,audit),tx|Box::pin(async move {
            let results=tx.with_connection_context(service,|service,c|Box::pin(async move {
                let tenant=service.tenant.to_string();
                let watermark=rss_mdm_inventory_postgres::lock_watermark_in(c,service.tenant).await?;
                let prior:Option<i64>=sqlx::query_scalar("SELECT watermark FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *c).await?;
                if prior==Some(watermark){return Ok::<_,Error>(Vec::new());}
                let world=identity::world(c,service.tenant).await?;
                let mut results=Vec::new();
                let mut occupied=BTreeSet::new();
                for (index,old) in world.associations.iter().enumerate() {
                    if index%128==0{tokio::task::yield_now().await;}
                    if old.state==State::Revoked {continue;}
                    occupied.extend(old.members.iter().map(|m|m.device.clone()));
                    let effective=world.effective(old.clone());
                    let members=if effective.state==State::Confirmed { old.members.iter().map(|m|world.current(m).map(|e|e.member.clone()).ok_or(Error::Conflict)).collect::<Result<Vec<_>>>()? } else {old.members.clone()};
                    if effective.state==old.state && members==old.members {continue;}
                    let hardware=if effective.state==State::Confirmed {identity::evidence(&world,&members)} else {old.hardware.clone()};
                    let request=command(Some(old),&members,"automatic registration continuity");
                    let result=write::persist(c,&tenant,"device-associations",&request,&hardware,effective.state).await?;
                    results.push((request.operation_id,result));
                }
                for (index,mdm) in world.endpoints.iter().filter(|e|e.member.channel==Channel::Mdm).enumerate() {
                    if index%128==0{tokio::task::yield_now().await;}
                    if occupied.contains(&mdm.member.device){continue;}
                    let Some(agent)=world.peer(mdm) else {continue;};
                    let members=vec![mdm.member.clone(),agent.member.clone()];
                    if occupied.contains(&agent.member.device) || !world.unique(&members,&mdm.hardware) || !world.unique(&members,&agent.hardware) {continue;}
                    // A revoked pair is an explicit user decision, even if later generations match.
                    if world.revoked(&members) {continue;}
                    let request=command(None,&members,"automatic unique hardware match");
                    let result=write::persist(c,&tenant,"device-associations",&request,&identity::evidence(&world,&members),State::Confirmed).await?;
                    occupied.extend(members.iter().map(|m|m.device.clone()));
                    results.push((request.operation_id,result));
                }
                for (operation,result) in &results {
                    let value=serde_json::to_value(result).map_err(|_|Error::Storage)?;
                    let digest=Sha256::digest(serde_json::to_vec(result).map_err(|_|Error::Storage)?).to_vec();
                    sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,'device-associations','system',$3,$4)")
                        .bind(&tenant).bind(operation).bind(digest).bind(value).execute(&mut *c).await?;
                }
                sqlx::query("INSERT INTO mdm_devices.checkpoints(tenant_id,watermark) VALUES($1::uuid,$2) ON CONFLICT(tenant_id) DO UPDATE SET watermark=excluded.watermark")
                    .bind(&tenant).bind(watermark).execute(c).await?;
                Ok(results)
            })).await?;
            for (operation,result) in &results {
                let fact_audit=audit.fact_copy("device_association_automatic");
                fact_audit.operation(*operation,"device_association_automatic");fact_audit.target(&result.id.to_string());
                let digest=Sha256::digest(serde_json::to_vec(result).map_err(|_|Error::Storage)?);
                let fact=Fact::business(&fact_audit,&format!("device_association:{operation}"),&digest,200,"success",None)?.with_details(serde_json::json!({"association":result}))?;
                service.audit.append(tx,&fact,false).await?;
            }
            audit.mark_commit_started();
            Ok(results.len())
        })).await;
        let result = attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v.into_value())
            },
            |e| Err(model::transaction_error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(model::transaction_error(e))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |e| Err(model::transaction_error(e)),
        );
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
fn command(old: Option<&Association>, members: &[Member], evidence: &str) -> Confirm {
    Confirm {
        operation_id: Uuid::new_v4(),
        association_id: old.map(|a| a.id),
        expected_version: old.map_or(0, |a| a.version),
        mdm: members
            .iter()
            .find(|m| m.channel == Channel::Mdm)
            .expect("two selected channels")
            .clone(),
        agent: members
            .iter()
            .find(|m| m.channel == Channel::Agent)
            .expect("two selected channels")
            .clone(),
        evidence: evidence.into(),
    }
}
