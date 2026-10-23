//! Bounded credential maintenance uses the existing command/Audit transaction owner.
use crate::*;
use rss_mdm_recovery_credentials::storage as materials;

impl ExecutionService {
    pub async fn validate_recovery_credentials(&self) -> std::result::Result<(), Error> {
        let Some(protection) = self.recovery_credentials.clone() else {
            return Ok(());
        };
        let tenant = checked_input(Uuid::parse_str(&self.tenant.to_string()))
            .map_err(|_| Error::Malformed)?;
        transaction::inspect(&self.runtime, self.tenant, protection, |protection, tx| {
            Box::pin(async move {
                let keys = protection.keys.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move { Ok(materials::validate_keys_in(c, tenant, &keys).await) })
                })
                .await?
                .map_err(crate::recovery_credentials::error)?;
                Ok(())
            })
        })
        .await
    }
    pub fn credential_maintenance(self: Arc<Self>) -> Option<rss_runtime::ManagedTaskRegistration> {
        self.recovery_credentials.as_ref()?;
        let (task, _) = rss_runtime::ManagedTask::prepare(
            "recovery-credential-maintenance",
            Duration::from_secs(8),
        );
        Some(task.into_registration(move|stop|async move{
            loop {
                if stop.is_cancelled(){break}
                if let Err(error)=self.maintain_recovery_credentials().await{
                    eprintln!("{}",serde_json::json!({"event":"recovery_credential_maintenance_failed","reason":error}));
                }
                tokio::select!{()=stop.cancelled()=>break,()=tokio::time::sleep(Duration::from_secs(60))=>{}}
            }Ok(())
        }))
    }
    pub async fn maintain_recovery_credentials(&self) -> std::result::Result<(), Error> {
        let Some(protection) = self.recovery_credentials.as_ref() else {
            return Ok(());
        };
        let audit = RequestAudit::new(self.tenant.to_string(), "recovery_credential_maintenance");
        audit.identify_service("recovery-credentials");
        let result=transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,protection,&audit),|ctx,tx|Box::pin(async move{
            let (service,protection,audit)=*ctx;
            let tenant=checked_input(Uuid::parse_str(&service.tenant.to_string()))?;
            let keys=protection.keys.clone();
            let prepared=tx.with_connection(move|c|Box::pin(async move{Ok(materials::prepare_rewrap_in(c,tenant,&keys).await)})).await?.map_err(crate::recovery_credentials::error)?;
            let expired=tx.with_connection(move|c|Box::pin(async move{Ok(materials::expired_in(c,tenant).await)})).await?.map_err(crate::recovery_credentials::error)?;
            service.audit_store.prepare_in(tx,audit,&[]).await?;
            let keys=protection.keys.clone();
            let rewrapped=tx.with_connection(move|c|Box::pin(async move{Ok(materials::rewrap_in(c,prepared,&keys).await)})).await?.map_err(crate::recovery_credentials::error)?;
            let mut cleared=Vec::new();
            let mut purged=Vec::new();
            let mut examined=Vec::new();
            let mut remaining_inputs=100;
            for material in expired{
                if remaining_inputs==0{break}
                let registration=material.binding.registration;
                let id=material.id;let version=material.version;
                tx.with_connection(move|c|Box::pin(async move{Ok(materials::cleanup_visited_in(c,tenant,id,version).await)})).await?.map_err(crate::recovery_credentials::error)?;
                examined.push((id,version));
                let ids=tx.with_connection(move|c|Box::pin(async move{Ok(materials::input_copies_in(c,tenant,registration).await)})).await?.map_err(crate::recovery_credentials::error)?;
                for id in ids.into_iter().take(remaining_inputs){
                    remaining_inputs-=1;
                    let mut op=storage::load(tx,&service.protection,id).await?;
                    let terminal=service.required_command(tx,&op).await?.status().is_terminal();
                    if let Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Command{command}}=&mut op.request.task{
                        for key in ["PIN","Password","CurrentPassword","NewPassword","FileVaultUnlock"]{command.fields.0.remove(key);}
                    }
                    let (_,sealed)=input_storage::seal(&service.protection,service.tenant,&input_storage::Identity{operation:id,device:&op.device,registration:op.registration,generation:op.registration_generation},&op.request)?;
                    let apple=service.apple_results.clone();
                    let purged_input=tx.with_connection(move|c|Box::pin(async move{
                        match apple.purge_credential_inputs(c,tenant.to_string(),id,terminal).await {
                            Err(e)=>return Ok(Err(e)),Ok(false)=>return Ok(Ok(false)),Ok(true)=>{}
                        }
                        sqlx::query("UPDATE mdm_commands.operations SET request=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(sealed).execute(&mut *c).await?;
                        materials::input_purged_in(c,tenant,id).await.map_err(|_|sqlx::Error::Protocol("credential maintenance unavailable".into()))?;
                        Ok(Ok(true))
                    })).await?.map_err(Error::from)?;
                    if purged_input {purged.push(id);}
                }
                let remaining=tx.with_connection(move|c|Box::pin(async move{Ok(materials::inputs_remain_in(c,tenant,registration).await)})).await?.map_err(crate::recovery_credentials::error)?;
                if remaining{continue}
                let id=material.id;let version=material.version;
                tx.with_connection(move|c|Box::pin(async move{Ok(materials::clear_expired_in(c,tenant,id,version).await)})).await?.map_err(crate::recovery_credentials::error)?;
                cleared.push((id,version));
            }
            if rewrapped>0||!cleared.is_empty()||!purged.is_empty()||!examined.is_empty(){
                let bytes=checked_input(serde_json::to_vec(&(rewrapped,&cleared,&purged,&examined)))?;
                let fact=rss_mdm_audit_integration::Fact::business(audit,&format!("recovery:maintenance:{}",audit.request_id()),&bytes,200,"success",None)?;
                service.audit_store.append_in(tx,&fact,false).await?;
            }
            Ok(())
        })).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
