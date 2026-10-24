//! Product query invalidation participates in the existing command transaction.
//!
//! Keep mutable RSS Store calls behind this private adapter: version witnesses
//! advance only for changed command facts, so no-op recovery preserves cursors.
//! Witnesses and the query revision commit or roll back with the original write.
//! Product-owned evidence uses its own capture triggers; RSS tables stay owned
//! by RSS. Registration retirement enters through the existing narrow SQL seam.
use rss_device_command as dc;
use rss_transactional_messaging::outbox::PendingMessage;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub(crate) struct CommandStore(pub(crate) rss_device_command_postgres::PgStore<()>);
pub(crate) async fn advance(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT mdm_commands.advance_query_revision($1::uuid)")
                .bind(tenant)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
async fn prepare(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT mdm_commands.lock_query_revision($1::uuid)")
                .bind(tenant)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
async fn observed(tx: &mut PgTransaction<'_>, records: Vec<(String, i64)>) -> Result<(), PgError> {
    if records.is_empty() {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let (ids, versions): (Vec<_>, Vec<_>) = records.into_iter().unzip();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "SELECT mdm_commands.observe_query_commands($1::uuid,$2::text[],$3::bigint[])",
            )
            .bind(tenant)
            .bind(ids)
            .bind(versions)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await
}
fn coordinate(command: &dc::Command) -> (String, i64) {
    (command.spec().id().as_str().to_owned(), command.version())
}
pub(crate) async fn read(tx: &mut PgTransaction<'_>) -> Result<(i64, i64), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_as("SELECT coalesce((SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=$1::uuid),0),mdm.lock_asset_watermark($1::uuid)").bind(tenant).fetch_one(c).await})).await
}
impl CommandStore {
    pub(crate) async fn now(&self, tx: &mut PgTransaction<'_>) -> Result<i64, PgError> {
        self.0.now(tx).await
    }
}
impl dc::Store for CommandStore {
    type Transaction<'a> = PgTransaction<'a>;
    type Error = PgError;
    async fn initialize(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: dc::Scope,
        coordinate: dc::Coordinate,
    ) -> Result<(), PgError> {
        prepare(tx).await?;
        self.0.initialize(tx, scope, coordinate).await
    }
    async fn advance(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: dc::Scope,
        expected: dc::Coordinate,
        next: dc::Coordinate,
    ) -> Result<(), PgError> {
        advance(tx).await?;
        self.0.advance(tx, scope, expected, next).await
    }
    async fn queue(
        &self,
        tx: &mut Self::Transaction<'_>,
        spec: dc::CommandSpec,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<dc::Command, PgError> {
        prepare(tx).await?;
        let command = self.0.queue(tx, spec, message).await?;
        observed(tx, vec![coordinate(&command)]).await?;
        Ok(command)
    }
    async fn load(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: dc::Scope,
        id: &dc::CommandId,
    ) -> Result<Option<dc::Command>, PgError> {
        self.0.load(tx, scope, id).await
    }
    async fn report(
        &self,
        tx: &mut Self::Transaction<'_>,
        report: &dc::DeviceReport,
    ) -> Result<dc::Transition, PgError> {
        prepare(tx).await?;
        let transition = self.0.report(tx, report).await?;
        observed(tx, vec![coordinate(&transition.command)]).await?;
        Ok(transition)
    }
    async fn cancel(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: dc::Scope,
        id: &dc::CommandId,
        coordinate: dc::Coordinate,
    ) -> Result<dc::Transition, PgError> {
        prepare(tx).await?;
        let transition = self.0.cancel(tx, scope, id, coordinate).await?;
        observed(tx, vec![self::coordinate(&transition.command)]).await?;
        Ok(transition)
    }
    async fn recover(
        &self,
        tx: &mut Self::Transaction<'_>,
        scope: dc::Scope,
        limit: dc::BatchLimit,
        after: Option<&dc::CommandId>,
    ) -> Result<dc::RecoveryPage, PgError> {
        prepare(tx).await?;
        let page = self.0.recover(tx, scope, limit, after).await?;
        observed(tx, page.commands.iter().map(coordinate).collect()).await?;
        Ok(page)
    }
}
