//! One fixed relay loop shares the existing process delivery budget across concrete owners.
use std::{sync::Arc, time::Duration};
pub(crate) fn registration(
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    scripts: Arc<rss_mdm_script_service::worker::Worker>,
    collections: Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("mdm-task-relay", Duration::from_secs(20));
    task.into_registration(move|stop|async move {
        loop {
            if stop.is_cancelled(){return Ok(());}
            let result=execution.relay_once().await;execution.record_relay_health(&result);
            let mut pending=match result {Ok(n)=>n,Err(e)=>{if matches!(e,rss_mdm_execution_service::Error::Malformed|rss_mdm_execution_service::Error::Forbidden|rss_mdm_execution_service::Error::Unauthorized|rss_mdm_execution_service::Error::Unavailable(rss_mdm_execution_service::Failure::CommandInvariant|rss_mdm_execution_service::Failure::NativeInputIntegrity)){return Err(rss_runtime::ShutdownError::new(e));}0}};
            if stop.is_cancelled(){return Ok(());}
            match scripts.relay_once().await {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_script_service::Error::Malformed|rss_mdm_script_service::Error::Forbidden|rss_mdm_script_service::Error::Unauthorized|rss_mdm_script_service::Error::Invariant){return Err(rss_runtime::ShutdownError::new(e));}}}
            if stop.is_cancelled(){return Ok(());}
            match collections.relay_once().await {Ok(n)=>pending+=n,Err(e)=>{if matches!(e,rss_mdm_inventory_service::Error::Malformed|rss_mdm_inventory_service::Error::Forbidden|rss_mdm_inventory_service::Error::Unauthorized|rss_mdm_inventory_service::Error::Unavailable(rss_mdm_inventory_service::Failure::PlanningStorage)){return Err(rss_runtime::ShutdownError::new(e));}}}
            if pending==0 {tokio::select!{()=stop.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(Duration::from_secs(5))=>{}}}
        }
    })
}
