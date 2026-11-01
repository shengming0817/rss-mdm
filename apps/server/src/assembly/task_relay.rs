//! One fixed relay loop shares the existing process delivery budget across concrete owners.
use std::{sync::Arc, time::Duration};
#[expect(
    clippy::too_many_arguments,
    reason = "fixed concrete owners share one relay and shutdown budget"
)]
pub(crate) fn registration(
    execution: Arc<rss_mdm_device_service::control::Service>,
    scripts: Arc<rss_mdm_script_service::worker::Worker>,
    collections: Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    software: Arc<rss_mdm_software_service::deployment::SoftwareService>,
    installation: Arc<rss_mdm_registration_service::installation::Service>,
    enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::worker::Worker>,
    access: Arc<rss_mdm_registration_service::device_access::execution::worker::Worker>,
    credentials: Option<super::credential_execution::Assembly>,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("mdm-task-relay", Duration::from_secs(20));
    task.into_registration(move|stop|async move {
        loop {
            if stop.is_cancelled(){return Ok(());}
            let result=execution.relay_once().await;execution.record_relay_health(&result);
            let mut pending=match result {Ok(n)=>n,Err(e)=>{if matches!(e,rss_mdm_device_service::control::Error::Malformed|rss_mdm_device_service::control::Error::Forbidden|rss_mdm_device_service::control::Error::Unauthorized|rss_mdm_device_service::control::Error::Unavailable(rss_mdm_device_service::control::Failure::CommandInvariant|rss_mdm_device_service::control::Failure::NativeInputIntegrity)){return Err(rss_runtime::ShutdownError::new(e));}0}};
            if stop.is_cancelled(){return Ok(());}
            match scripts.relay_once().await {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_script_service::Error::Malformed|rss_mdm_script_service::Error::Forbidden|rss_mdm_script_service::Error::Unauthorized|rss_mdm_script_service::Error::Invariant){return Err(rss_runtime::ShutdownError::new(e));}eprintln!("{}",serde_json::json!({"event":"mdm_task_relay_failure","owner":"script","reason":match e {rss_mdm_script_service::Error::CommitUnknown=>"commit_unknown",rss_mdm_script_service::Error::RollbackFailed=>"rollback_failed",_=>"transient"}}));}}
            if stop.is_cancelled(){return Ok(());}
            match collections.relay_once().await {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_inventory_service::Error::Malformed|rss_mdm_inventory_service::Error::Forbidden|rss_mdm_inventory_service::Error::Unauthorized|rss_mdm_inventory_service::Error::Unavailable(rss_mdm_inventory_service::Failure::PlanningStorage)){return Err(rss_runtime::ShutdownError::new(e));}eprintln!("{}",serde_json::json!({"event":"mdm_task_relay_failure","owner":"collection","reason":match e {rss_mdm_inventory_service::Error::CommitUnknown=>"commit_unknown",rss_mdm_inventory_service::Error::RollbackFailed=>"rollback_failed",_=>"transient"}}));}}
            if stop.is_cancelled(){return Ok(());}
            let result=software.relay_once().await; software.record_relay_health(&result);
            match result {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_software_service::deployment::Error::Malformed|rss_mdm_software_service::deployment::Error::Forbidden|rss_mdm_software_service::deployment::Error::Unauthorized|rss_mdm_software_service::deployment::Error::Unavailable(rss_mdm_software_service::deployment::Failure::CommandInvariant|rss_mdm_software_service::deployment::Failure::NativeInputIntegrity)){return Err(rss_runtime::ShutdownError::new(e));}}}
            if stop.is_cancelled(){return Ok(());}
            let result=installation.relay_once().await; installation.record_relay_health(&result);
            match result {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_registration_service::installation::Error::Malformed|rss_mdm_registration_service::installation::Error::Forbidden|rss_mdm_registration_service::installation::Error::Unauthorized|rss_mdm_registration_service::installation::Error::Unavailable(rss_mdm_registration_service::installation::Failure::CommandInvariant|rss_mdm_registration_service::installation::Failure::NativeInputIntegrity)){return Err(rss_runtime::ShutdownError::new(e));}}}
            if stop.is_cancelled(){return Ok(());}
            match enrollment.relay_once().await {
                Ok(n) => pending += n,
                Err(e) => {
                    use rss_mdm_registration_service::enrollment::tasks::Error as E;
                    let reason = match e {
                        E::Malformed | E::Forbidden | E::Unauthorized | E::Invariant => {
                            return Err(rss_runtime::ShutdownError::new(e));
                        }
                        E::CommitUnknown => "commit_unknown",
                        E::RollbackFailed => "rollback_failed",
                        E::Unavailable => "unavailable",
                        E::Conflict => "conflict",
                        E::NotFound => "not_found",
                        E::Audit(_) => "audit",
                    };
                    eprintln!("{}", serde_json::json!({"event":"mdm_task_relay_failure","owner":"enrollment","reason":reason}));
                }
            }
            if stop.is_cancelled(){return Ok(());}
            match access.relay_once().await{Ok(n)=>pending+=n,Err(e)=>{use rss_mdm_registration_service::device_access::execution::Error as E;if matches!(e,E::Malformed|E::Forbidden|E::Unauthorized|E::Invariant){return Err(rss_runtime::ShutdownError::new(e));}eprintln!("{}",serde_json::json!({"event":"mdm_task_relay_failure","owner":"access","reason":e.to_string()}));}}
            if let Some(credentials)=&credentials {
            if stop.is_cancelled(){return Ok(());}
            match credentials.worker.relay_once().await{Ok(n)=>pending+=n,Err(e)=>{use rss_mdm_recovery_credentials::tasks::Error as E;if matches!(e,E::Malformed|E::Forbidden|E::Unauthorized|E::Invariant){return Err(rss_runtime::ShutdownError::new(e));}eprintln!("{}",serde_json::json!({"event":"mdm_task_relay_failure","owner":"credential","reason":e.to_string()}));}}
                if stop.is_cancelled(){return Ok(());}
                let result=credentials.native.relay_once().await;credentials.native.record_relay_health(&result);
                match result{Ok(n)=>pending+=n,Err(e)=>{use rss_mdm_recovery_credentials::native::{Error as E,Failure as F};if matches!(e,E::Malformed|E::Forbidden|E::Unauthorized|E::Unavailable(F::CommandInvariant|F::NativeInputIntegrity)){return Err(rss_runtime::ShutdownError::new(e));}}}
            }
            if pending==0 {tokio::select!{()=stop.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(Duration::from_secs(5))=>{}}}
        }
    })
}
