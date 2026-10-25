//! Authorized recovery and asset disposition for accepted Policy retirement.
use crate::{Associations, Error, Result, ViewRef, lifecycle, read};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetState {
    Active,
    Archived,
    Deleted,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetChange {
    pub operation_id: Uuid,
    pub state: AssetState,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForceRevoke {
    pub operation_id: Uuid,
    pub reason: String,
}
#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Change<'a> {
    Asset {
        target: &'a ViewRef,
        input: &'a AssetChange,
    },
    Force {
        retirement: Uuid,
        input: &'a ForceRevoke,
    },
}
impl Change<'_> {
    fn operation(&self) -> Uuid {
        match self {
            Self::Asset { input, .. } => input.operation_id,
            Self::Force { input, .. } => input.operation_id,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Asset { .. } => "device_asset_state",
            Self::Force { .. } => "device_retirement_force_revoke",
        }
    }
}
impl Associations {
    pub async fn retirement(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<lifecycle::Retirement> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        self.audit
            .write(
                self.tenant,
                &budget.source_control(),
                (self, p, id),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |(s, p, id), c| {
                            Box::pin(async move {
                                let auth = read::authorization(c, p).await?;
                                let result = lifecycle::read_in(c, s.tenant, *id).await?;
                                for channel in &result.channels {
                                    auth.require(
                                        p,
                                        Permission::InventoryRead,
                                        Some(&channel.device),
                                    )?;
                                }
                                p.check_live()?;
                                Ok(result)
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(crate::model::transaction_error(e)),
                |e| Err(crate::model::transaction_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(crate::model::transaction_error(e)),
            )
    }
    pub async fn asset_state(
        &self,
        p: &AuthorizedPrincipal,
        target: &ViewRef,
        input: &AssetChange,
        audit: &RequestAudit,
    ) -> Result<Value> {
        self.lifecycle_change(p, Change::Asset { target, input }, audit)
            .await
    }
    pub async fn force_retirement(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: &ForceRevoke,
        audit: &RequestAudit,
    ) -> Result<Value> {
        if id.is_nil() || input.reason.is_empty() || input.reason.len() > 2048 {
            return Err(Error::Malformed);
        }
        self.lifecycle_change(
            p,
            Change::Force {
                retirement: id,
                input,
            },
            audit,
        )
        .await
    }
    async fn lifecycle_change(
        &self,
        p: &AuthorizedPrincipal,
        change: Change<'_>,
        audit: &RequestAudit,
    ) -> Result<Value> {
        if p.tenant_id() != self.tenant.to_string() || change.operation().is_nil() {
            return Err(Error::Forbidden);
        }
        p.bind_audit(audit)?;
        audit.operation(
            change.operation(),
            change.name(),
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let digest =
            Sha256::digest(serde_json::to_vec(&change).map_err(|_| Error::Malformed)?).to_vec();
        let budget = AuditBudget::new(std::time::Duration::from_secs(8));
        let attempt=self.audit.write(self.tenant,&budget.source_control(),(self,p,&change,audit,&digest),|(s,p,change,audit,digest),tx|Box::pin(async move{
    let s=*s;let p=*p;let change=*change;let audit=*audit;let digest=*digest;
    let (result,replay)=tx.with_connection_context(&mut (p,change,digest),|(p,change,digest),c|Box::pin(async move{
      rss_mdm_inventory_postgres::lock_watermark_in(c,s.tenant).await?;
      let auth=read::authorization(c,p).await?;
      let devices=match change {
        Change::Asset{target,..}=>asset_devices(c,p.tenant_id(),target).await?,
        Change::Force{retirement,..}=>lifecycle::read_in(c,s.tenant,*retirement).await?.channels.into_iter().map(|c|c.device).collect(),
      };
      for device in &devices {
        auth.require(p,Permission::InventoryRead,Some(device))?;
        auth.require(p,match change{Change::Asset{..}=>Permission::InventoryAssign,Change::Force{..}=>Permission::DeviceUnmanage},Some(device))?;
        rss_mdm_registration_service::lifecycle::lock_device_in(c,p.tenant_id(),device).await?;
      }
      let old=sqlx::query("SELECT actor,instance,digest,result FROM mdm_devices.operations WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(p.tenant_id()).bind(change.operation()).fetch_optional(&mut *c).await?;
      if let Some(old)=old {
        if old.try_get::<String,_>("actor")?!=p.principal_id()||old.try_get::<String,_>("instance")?!=p.instance_id()||old.try_get::<Vec<u8>,_>("digest")?!=**digest{return Err(Error::Conflict);}
        return Ok((old.try_get("result")?,true));
      }
      let result=match change {
        Change::Force{retirement,input}=>{
          sqlx::query("UPDATE mdm_devices.retirements SET forced_at=floor(extract(epoch FROM clock_timestamp()))::bigint,forced_by=$3 WHERE tenant_id=$1::uuid AND id=$2 AND forced_at IS NULL")
            .bind(p.tenant_id()).bind(*retirement).bind(json!({"actor":p.actor(),"reason":input.reason})).execute(&mut *c).await?;
          sqlx::query("UPDATE mdm_devices.retirement_channels SET stage='revoke',effect=CASE WHEN effect='confirmed' THEN effect ELSE 'unknown' END,reason=CASE WHEN effect='confirmed' THEN reason ELSE 'forced_revoke_cleanup_unconfirmed' END WHERE tenant_id=$1::uuid AND operation=$2 AND stage<>'complete'")
            .bind(p.tenant_id()).bind(*retirement).execute(&mut *c).await?;
          json!({"operationId":input.operation_id,"retirementId":retirement,"revocation":"pending"})
        }
        Change::Asset{input,..}=>{
          for device in &devices {
            if input.state!=AssetState::Active {
              let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')")
                .bind(p.tenant_id()).bind(device).fetch_one(&mut *c).await?;
              if active {
                let exiting:bool=sqlx::query_scalar("SELECT retirement IS NOT NULL FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(p.tenant_id()).bind(device).fetch_one(&mut *c).await?;
                if input.state==AssetState::Deleted||!exiting{return Err(Error::Conflict);}
              }
            }
            let state=serde_json::to_value(input.state).map_err(|_|Error::Malformed)?;
            sqlx::query("INSERT INTO mdm_devices.asset_states(tenant_id,device,state) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,device) DO UPDATE SET state=EXCLUDED.state")
                .bind(p.tenant_id()).bind(device).bind(state.as_str()).execute(&mut *c).await?;
          }
          json!({"operationId":input.operation_id,"devices":devices,"state":input.state})
        }
      };
      sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,$3,$4,$5,$6)")
        .bind(p.tenant_id()).bind(change.operation()).bind(p.principal_id()).bind(p.instance_id()).bind(*digest).bind(result.clone()).execute(c).await?;
      Ok::<_,Error>((result,false))
    })).await?;
    let fact=Fact::business(audit, &format!("device-lifecycle:{}",change.operation()), 200, "success", None)?.with_details(result.clone())?;
    (if replay { Ok(()) } else { s.audit.append(tx, &fact).await })?;p.check_live()?;audit.mark_commit_started();Ok(result)
  })).await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |e| Err(crate::model::transaction_error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(crate::model::transaction_error(e))
            },
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |e| Err(crate::model::transaction_error(e)),
        )
    }
}
async fn asset_devices(
    c: &mut PgConnection,
    tenant: &str,
    target: &ViewRef,
) -> Result<Vec<String>> {
    let mut devices=match target {
  ViewRef::Endpoint(id)=>{
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(&mut *c).await?;
    if !exists{return Err(Error::NotFound);}
    vec![id.clone()]
  },
  ViewRef::Association(id)=>sqlx::query_scalar("SELECT device FROM mdm_devices.members WHERE tenant_id=$1::uuid AND association_id=$2 ORDER BY device").bind(tenant).bind(id).fetch_all(c).await?,
 };
    if devices.is_empty() {
        return Err(Error::NotFound);
    }
    devices.sort();
    devices.dedup();
    Ok(devices)
}
