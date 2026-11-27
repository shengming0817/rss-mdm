//! A command owner updates its own exact row in the projection's borrowed transaction.
use rss_transactional_messaging::{fence::ExecutionBinding, message::MessageFingerprint};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;

pub const DISCOVERY_SQL: &str = include_str!("command-relay.sql");

pub struct Dispatch<'a> {
    pub message_id: &'a rss_transactional_messaging::message::MessageId,
    pub binding: ExecutionBinding,
    pub id: Uuid,
    pub fingerprint: MessageFingerprint,
}
impl Dispatch<'_> {
    /// The statement pins the owner table, current authored epoch and original fingerprint.
    pub async fn accept_in(
        &self,
        tx: &mut PgTransaction<'_>,
        statement: &'static str,
    ) -> Result<bool, PgError> {
        let tenant = tx.tenant_id().to_string();
        let id = self.id;
        let fingerprint = self.fingerprint;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(sqlx::query(statement)
                    .bind(tenant)
                    .bind(id)
                    .bind(fingerprint.as_bytes().as_slice())
                    .execute(c)
                    .await?
                    .rows_affected()
                    == 1)
            })
        })
        .await
    }

    /// Project the actual native command status for this original dispatch audit fact.
    pub async fn native_status_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: Uuid,
    ) -> Result<Option<String>, PgError> {
        let message = self.message_id.as_str().to_owned();
        let id = self.id.to_string();
        let fingerprint = self.fingerprint;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT public.mdm_dispatch_native_status($1,$2,$3,$4)")
                    .bind(device)
                    .bind(id)
                    .bind(message)
                    .bind(fingerprint.as_bytes().as_slice())
                    .fetch_one(c)
                    .await
            })
        })
        .await
    }
}

/// Fixed product message domains and their declared consumer logins.
pub mod lanes {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Lane {
        pub role: &'static str,
        pub domain: &'static str,
        pub owner: &'static str,
        pub tables: &'static [&'static str],
    }
    include!(concat!(env!("OUT_DIR"), "/command_lanes.rs"));
}

/// Prefix a command owner's admission CTEs with the canonical initial-state policy check.
/// The query runs against pg_catalog using the owner's ordinary login.
#[macro_export]
macro_rules! command_admission_sql {
    ($file:literal) => {
        concat!(
            "WITH command_initial_state(relation) AS (SELECT p.polrelid FROM pg_policy p ",
            "WHERE p.polname='command_initial_state' AND NOT p.polpermissive AND p.polcmd='a' ",
            "AND p.polroles @> ARRAY['mdm_command_runtime'::regrole::oid,'mdm_policy_runtime'::regrole::oid] ",
            "AND pg_get_expr(p.polwithcheck,p.polrelid)='(NOT gateway_accepted)'),\n",
            include_str!($file)
        )
    };
}
