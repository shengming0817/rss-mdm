//! Product wake hints. PostgreSQL remains the authority for every scan and claim.
//! ref: PostgreSQL LISTEN/NOTIFY commit and initial-snapshot rules;
//! sqlx 0.9 sqlx-postgres/src/listener.rs (try_recv reports a completed reconnect).
use sqlx::PgConnection;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub const RECOVERY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub enum Work {
    CommandRelay,
    CommandRecovery,
    Apple,
}
impl Work {
    fn payload(self) -> &'static str {
        match self {
            Self::CommandRelay => "command_relay",
            Self::CommandRecovery => "credential_native_recovery",
            Self::Apple => "apple",
        }
    }
}

/// Called inside the transaction that persists work; PostgreSQL sends only at COMMIT.
pub async fn notify(connection: &mut PgConnection, work: Work) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify('mdm_work',$1)")
        .bind(work.payload())
        .execute(connection)
        .await?;
    Ok(())
}
pub async fn notify_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    work: Work,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(move |c| Box::pin(notify(c, work))).await
}
/// One pending permit survives a notification received between the scan and this wait.
pub async fn wait(notify: &Notify, stop: &CancellationToken, nearest: Option<Duration>) {
    tokio::select! { biased;
        () = stop.cancelled() => {},
        () = notify.notified() => {},
        () = tokio::time::sleep(nearest.unwrap_or(RECOVERY).min(RECOVERY)) => {},
    }
}
