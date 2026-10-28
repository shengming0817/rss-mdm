//! Group-owned graph coordinates used to fence resumable definition validation.
use crate::{GroupStore, InTransaction, storage::data, store::input};
use rss_transactional_messaging_postgres::PgTransaction;

impl GroupStore {
    /// Read the tenant graph revision in the initiating runtime's transaction.
    /// A tenant without an authored group graph starts at revision zero.
    pub async fn graph_revision_in(&self, tx: &mut PgTransaction<'_>) -> InTransaction<u64> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        let revision = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, i64>(
                        "SELECT revision FROM mdm_group.graph_clock WHERE tenant_id=$1::uuid",
                    )
                    .bind(tenant)
                    .fetch_optional(c)
                    .await
                })
            })
            .await?;
        Ok(Ok(data(u64::try_from(revision.unwrap_or(0)))?))
    }

    /// Advance the authored graph while the caller holds the shared graph edit fence.
    pub async fn advance_graph_in(&self, tx: &mut PgTransaction<'_>) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.graph_clock(tenant_id,revision) VALUES($1::uuid,1) ON CONFLICT(tenant_id) DO UPDATE SET revision=mdm_group.graph_clock.revision+1")
                .bind(tenant).execute(c).await?;
            Ok(())
        })).await?;
        Ok(Ok(()))
    }

    /// Remove traversal state when a definition restarts or its task becomes terminal.
    pub async fn clear_definition_walk_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: uuid::Uuid,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "DELETE FROM mdm_group.definition_walk WHERE tenant_id=$1::uuid AND task_id=$2",
                )
                .bind(tenant)
                .bind(task)
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await?;
        Ok(Ok(()))
    }

    /// Seed one bounded set of referenced nodes at a frozen graph revision.
    pub async fn seed_definition_walk_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: uuid::Uuid,
        revision: u64,
        nodes: Vec<uuid::Uuid>,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        if nodes.len() > 256 {
            return Ok(Err(crate::Rejection::InvalidInput));
        }
        let revision =
            input!(i64::try_from(revision).map_err(|_| crate::Rejection::VersionExhausted));
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.definition_walk(tenant_id,task_id,node_id,graph_revision) SELECT $1::uuid,$2,n,$3 FROM unnest($4::uuid[]) n ON CONFLICT(tenant_id,task_id,node_id) DO UPDATE SET graph_revision=excluded.graph_revision,visited=false WHERE mdm_group.definition_walk.graph_revision<>excluded.graph_revision")
                .bind(tenant).bind(task).bind(revision).bind(nodes).execute(c).await?;
            Ok(())
        })).await?;
        Ok(Ok(()))
    }

    /// Read at most sixteen unvisited nodes; an empty page proves this walk is drained.
    pub async fn definition_walk_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: uuid::Uuid,
        revision: u64,
    ) -> InTransaction<Vec<uuid::Uuid>> {
        input!(self.check_transaction(tx)?);
        let revision =
            input!(i64::try_from(revision).map_err(|_| crate::Rejection::VersionExhausted));
        let tenant = self.tenant.to_string();
        Ok(Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT node_id FROM mdm_group.definition_walk WHERE tenant_id=$1::uuid AND task_id=$2 AND graph_revision=$3 AND NOT visited ORDER BY node_id LIMIT 16")
                .bind(tenant).bind(task).bind(revision).fetch_all(c).await
        })).await?))
    }

    /// Mark one visited node without acknowledging another graph revision.
    pub async fn visit_definition_node_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: uuid::Uuid,
        revision: u64,
        node: uuid::Uuid,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let revision =
            input!(i64::try_from(revision).map_err(|_| crate::Rejection::VersionExhausted));
        let tenant = self.tenant.to_string();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_group.definition_walk SET visited=true WHERE tenant_id=$1::uuid AND task_id=$2 AND node_id=$3 AND graph_revision=$4")
                .bind(tenant).bind(task).bind(node).bind(revision).execute(c).await
        })).await?.rows_affected();
        Ok(if rows == 1 {
            Ok(())
        } else {
            Err(crate::Rejection::VersionConflict)
        })
    }
}
