//! Product wake hints. PostgreSQL remains the authority for every scan and claim.
//! ref: PostgreSQL LISTEN/NOTIFY commit and initial-snapshot rules;
//! sqlx 0.9 sqlx-postgres/src/listener.rs (try_recv reports a completed reconnect).
use rss_runtime::{ManagedResource, ManagedTask, ManagedTaskRegistration, ShutdownError};
use sqlx::{
    PgConnection, PgPool,
    postgres::{PgConnectOptions, PgListener, PgPoolOptions},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub(crate) const RECOVERY: Duration = Duration::from_secs(5);
const CHANNEL: &str = "mdm_work";

#[derive(Clone, Copy)]
pub(crate) enum Work {
    Inventory,
    AutomationInput,
    Automation,
    CommandRelay,
    CommandRecovery,
    Apple,
    Windows,
}
impl Work {
    const ALL: [Self; 7] = [
        Self::Inventory,
        Self::AutomationInput,
        Self::Automation,
        Self::CommandRelay,
        Self::CommandRecovery,
        Self::Apple,
        Self::Windows,
    ];
    fn payload(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::AutomationInput => "automation_input",
            Self::Automation => "automation",
            Self::CommandRelay => "command_relay",
            Self::CommandRecovery => "command_recovery",
            Self::Apple => "apple",
            Self::Windows => "windows",
        }
    }
}
#[derive(Default)]
pub(crate) struct Signals([Notify; 7]);
impl Signals {
    pub(crate) fn get(&self, work: Work) -> &Notify {
        &self.0[work as usize]
    }
    fn received(&self, payload: &str) {
        if let Some(work) = Work::ALL.into_iter().find(|w| w.payload() == payload) {
            self.get(work).notify_one();
        }
    }
    fn scan_all(&self) {
        for work in Work::ALL {
            self.get(work).notify_one();
        }
    }
}

/// Called inside the transaction that persists work; PostgreSQL sends only at COMMIT.
pub(crate) async fn notify(connection: &mut PgConnection, work: Work) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify($1,$2)")
        .bind(CHANNEL)
        .bind(work.payload())
        .execute(connection)
        .await?;
    Ok(())
}
pub(crate) async fn notify_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    work: Work,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(move |c| Box::pin(notify(c, work))).await
}
/// One pending permit survives a notification received between the scan and this wait.
pub(crate) async fn wait(notify: &Notify, stop: &CancellationToken, nearest: Option<Duration>) {
    tokio::select! { biased;
        () = stop.cancelled() => {},
        () = notify.notified() => {},
        () = tokio::time::sleep(nearest.unwrap_or(RECOVERY).min(RECOVERY)) => {},
    }
}

#[derive(Clone)]
pub(crate) struct Listener {
    pool: PgPool,
    pub(crate) signals: Arc<Signals>,
}
impl Listener {
    pub(crate) fn new(options: PgConnectOptions) -> Self {
        Self {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(RECOVERY)
                .connect_lazy_with(options),
            signals: Arc::default(),
        }
    }
    pub(crate) fn registration(self) -> ManagedTaskRegistration {
        let (task, _) = ManagedTask::prepare("mdm-work-notifications", RECOVERY);
        task.into_registration(move |stop| async move {
            let mut failed = false;
            loop {
                let connect = async {
                    let mut listener = PgListener::connect_with(&self.pool).await?;
                    listener.listen(CHANNEL).await?;
                    Ok::<_, sqlx::Error>(listener)
                };
                let mut listener = tokio::select! { biased;
                    () = stop.cancelled() => return Ok(()),
                    result = tokio::time::timeout(RECOVERY, connect) => match result {
                        Ok(Ok(listener)) => listener,
                        _ => {
                            if !failed { eprintln!("{}", serde_json::json!({"event":"mdm_notification_connection","connected":false})); }
                            failed = true;
                            tokio::select! { () = stop.cancelled() => return Ok(()), () = tokio::time::sleep(RECOVERY) => {} }
                            continue;
                        }
                    },
                };
                // LISTEN has committed. Always scan afterwards, including after a disconnect.
                self.signals.scan_all();
                if failed { eprintln!("{}", serde_json::json!({"event":"mdm_notification_connection","connected":true})); failed = false; }
                loop {
                    tokio::select! { biased;
                        () = stop.cancelled() => return Ok(()),
                        result = listener.try_recv() => match result {
                            Ok(Some(notification)) => self.signals.received(notification.payload()),
                            // SQLx eagerly reconnects and re-LISTENs before returning None.
                            Ok(None) => self.signals.scan_all(),
                            Err(_) => {
                                if !failed { eprintln!("{}", serde_json::json!({"event":"mdm_notification_connection","connected":false})); }
                                failed = true;
                                break;
                            },
                        },
                    }
                }
                tokio::select! { () = stop.cancelled() => return Ok(()), () = tokio::time::sleep(RECOVERY) => {} }
            }
        })
    }
}
impl ManagedResource for Listener {
    fn name(&self) -> &str {
        "mdm-notification-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        RECOVERY
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.pool.close().await;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/worker_wake.rs"]
mod tests;
