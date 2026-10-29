//! Integration synchronization at the real device-fenced recovery boundary.
use crate::ExecutionService;
use std::{collections::BTreeMap, sync::Arc};
pub struct Arrival {
    pub entity: String,
    pub resume: Arc<tokio::sync::Notify>,
}
pub(crate) struct Gate {
    targets: BTreeMap<String, Arc<tokio::sync::Notify>>,
    arrivals: tokio::sync::mpsc::UnboundedSender<Arrival>,
}
impl ExecutionService {
    pub fn pause_recovery_after_device_lock(
        &self,
        entities: Vec<String>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Arrival> {
        let (arrivals, receiver) = tokio::sync::mpsc::unbounded_channel();
        let targets = entities
            .into_iter()
            .map(|e| (e, Arc::new(tokio::sync::Notify::new())))
            .collect();
        assert!(
            self.recovery_gate
                .lock()
                .expect("recovery gate")
                .replace(Gate { targets, arrivals })
                .is_none()
        );
        receiver
    }
    pub(crate) async fn recovery_checkpoint(&self, entity: &str) {
        let gate = self
            .recovery_gate
            .lock()
            .expect("recovery gate")
            .as_mut()
            .and_then(|g| {
                g.targets
                    .remove(entity)
                    .map(|resume| (g.arrivals.clone(), resume))
            });
        if let Some((arrivals, resume)) = gate {
            let waiting = resume.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            let _ = arrivals.send(Arrival {
                entity: entity.to_owned(),
                resume: resume.clone(),
            });
            waiting.await;
        }
    }
}
