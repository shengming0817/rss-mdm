use crate::failure;
use crate::{
    inventory::{Inventory, definition},
    model::{self, FixtureAuthority},
    storage::{self, BUDGET, Clock},
};
use anyhow::Result;
use rss_observation::{
    Access, Authority, Batch, Id, JournalReadGrant, LifecycleGrant, ObservationStore, Policy,
    ReadGrant, ReceiveOutcome, VerifiedBatch,
};
use rss_observation_postgres::PgSource;
use rss_projection::{
    BatchLimit, Control, GenerationStart, ProjectionScope, ReplayBound, RunLimit, Source,
    SourceScope, Stop,
};
use rss_projection_postgres::CloseOutcome;
use sqlx::{Row, postgres::PgConnectOptions};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Product operations own component authority and lifecycle.
/// ```compile_fail
/// fn bypass(app: rss_mdm::app::App) { let _ = app.observation; }
/// ```
/// ```compile_fail
/// fn bypass(app: rss_mdm::app::App) { let _ = app.projection; }
/// ```
/// ```compile_fail
/// fn replace(app: rss_mdm::app::App) { let _ = app.clock; }
/// ```
/// ```compile_fail
/// use rss_mdm::inventory::Inventory;
/// ```
/// ```compile_fail
/// fn bypass(app: rss_mdm::app::App) { let _ = app.source(); }
/// ```
pub struct App {
    observation: Arc<rss_observation_postgres::PgStore<Clock>>,
    projection: rss_projection_postgres::PgStore,
    clock: Clock,
    authority: FixtureAuthority,
}
impl App {
    pub async fn open(
        options: &PgConnectOptions,
        authority: FixtureAuthority,
        clock: Clock,
    ) -> Result<Self> {
        let pool = storage::pool(options).await?;
        // Retain the construction guard only until the component adopts the pool.
        let observation = match rss_observation_postgres::PgStore::new(
            pool.clone(),
            clock.clone(),
            clock.deadline(),
        )
        .await
        {
            Ok(store) => Arc::new(store),
            Err(error) => {
                return failure::finish(
                    Err(failure::at("observation_open", error)),
                    [("observation_pool_close", storage::close_pool(&pool).await)],
                );
            }
        };
        drop(pool);
        let projection = async {
            let pool = storage::pool(options).await?;
            if let Err(error) = tokio::time::timeout(BUDGET, crate::admission::verify(&pool))
                .await
                .map_err(anyhow::Error::from)
                .and_then(|r| r)
            {
                return failure::finish(
                    Err(failure::at("inventory_admission", error)),
                    [("projection_pool_close", storage::close_pool(&pool).await)],
                );
            }
            let result =
                tokio::time::timeout(BUDGET, rss_projection_postgres::PgStore::new(pool.clone()))
                    .await;
            match result {
                Ok(Ok(store)) => Ok(store),
                failure => {
                    let error = match failure {
                        Ok(Err(e)) => anyhow::Error::from(e),
                        Err(e) => e.into(),
                        _ => unreachable!(),
                    };
                    failure::finish(
                        Err(failure::at("projection_open", error)),
                        [("projection_pool_close", storage::close_pool(&pool).await)],
                    )
                }
            }
        }
        .await;
        match projection {
            Ok(projection) => Ok(Self {
                observation,
                projection,
                clock,
                authority,
            }),
            Err(error) => failure::finish(
                Err(error),
                [(
                    "observation_close",
                    observation
                        .close(clock.deadline())
                        .await
                        .map_err(Into::into),
                )],
            ),
        }
    }
    fn source_scope(&self) -> Result<SourceScope> {
        Ok(SourceScope::new(
            self.authority.scope().tenant(),
            model::JOURNAL,
        )?)
    }
    fn projection_scope(&self) -> Result<ProjectionScope> {
        Ok(ProjectionScope::new(
            self.source_scope()?,
            "inventory",
            model::GENERATION,
        )?)
    }
    fn source(&self) -> Result<Arc<PgSource<Clock>>> {
        Ok(Arc::new(PgSource::new(
            self.observation.clone(),
            JournalReadGrant::verify(&self.authority, self.authority.scope().tenant())?,
            self.source_scope()?,
        )?))
    }
    pub async fn ingest(&self, batch: Batch) -> Result<ReceiveOutcome> {
        model::validate(&batch)?;
        let scope = self.authority.scope().clone();
        self.observation
            .activate(
                &LifecycleGrant::verify(&self.authority, scope.clone())?,
                None,
                &Policy::new(86400, 3600, 3600)?,
                self.clock.deadline(),
            )
            .await?;
        Ok(self
            .observation
            .receive(
                &VerifiedBatch::verify(&self.authority, scope, batch)?,
                self.clock.deadline(),
            )
            .await?)
    }
    pub async fn project(&self, cancel: &CancellationToken) -> Result<serde_json::Value> {
        // Keep the composed RSS runner future off callers' stacks.
        Box::pin(self.project_inner(cancel)).await
    }
    async fn project_inner(&self, cancel: &CancellationToken) -> Result<serde_json::Value> {
        let source = self.source()?;
        let scope = self.projection_scope()?;
        let capture = Control::new(&self.clock, self.clock.cutoff(BUDGET), cancel);
        let through = capture.run(source.high_water(source.scope())).await?;
        let window = crate::window::Window {
            source: source.clone(),
            through,
        };
        let control = Control::new(&self.clock, self.clock.cutoff(BUDGET), cancel);
        self.projection
            .initialize(
                &scope,
                &definition(),
                GenerationStart::beginning(),
                ReplayBound::Live,
                &control,
            )
            .await?;
        let claim = self
            .projection
            .takeover(&scope, &definition(), &control)
            .await?;
        let execution = self
            .projection
            .projection(claim, Inventory::new(source.clone()))?;
        let (mut applied, mut duplicates, mut filtered) = (0_u64, 0_u64, 0_u64);
        loop {
            let control = Control::new(&self.clock, self.clock.cutoff(BUDGET), cancel);
            let report = rss_projection::run(
                &window,
                &execution,
                &control,
                RunLimit::new(BatchLimit::new(64)?, 256)?,
            )
            .await
            .into_result()?;
            applied += report.applied;
            duplicates += report.duplicates;
            filtered += report.filtered;
            if report.stop == Stop::CaughtUp {
                return Ok(
                    serde_json::json!({"stop":"caught_up","applied":applied,"duplicates":duplicates,"filtered":filtered,"position":report.position.map(|p|p.get()),"through":through.map(|p|p.get())}),
                );
            }
        }
    }
    pub async fn inspect(&self, id: &Id) -> Result<serde_json::Value> {
        let scope = self.authority.scope();
        self.authority.authorize(Access::Read { scope })?;
        let receipt = self
            .observation
            .lookup(
                &ReadGrant::verify(&self.authority, scope.clone())?,
                id,
                self.clock.deadline(),
            )
            .await?;
        // RSS PgSource v1 event identity is the exact record fingerprint in lowercase hex.
        let event_id = receipt
            .as_ref()
            .map(|r| {
                r.batch()
                    .fingerprint(r.scope())
                    .map(|fp| fp.iter().map(|b| format!("{b:02x}")).collect::<String>())
            })
            .transpose()?;
        let scope = scope.encode()?;
        let source = self.source_scope()?;
        let tenant = source.tenant().to_string();
        let cancel = CancellationToken::new();
        let control = Control::new(&self.clock, self.clock.cutoff(BUDGET), &cancel);
        let (position, assets, projected) = self.projection.local_tx(&source, &control, move |tx| Box::pin(async move {
            tx.with_connection(move |conn| Box::pin(async move {
                let position: Option<i64> = sqlx::query_scalar("SELECT position FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id='inventory' AND generation=$3").bind(&tenant).bind(model::JOURNAL).bind(model::GENERATION).fetch_optional(&mut *conn).await?.flatten();
                let rows = sqlx::query("SELECT field,value,batch_id,observed_at,received_at FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$2 AND generation=$3 AND scope=$4 ORDER BY field").bind(&tenant).bind(model::JOURNAL).bind(model::GENERATION).bind(&scope).fetch_all(&mut *conn).await?;
                let mut assets = Vec::new();
                for r in rows { assets.push(serde_json::json!({"field":r.try_get::<String,_>("field")?,"value":r.try_get::<String,_>("value")?,"batchId":r.try_get::<String,_>("batch_id")?,"observedAt":r.try_get::<i64,_>("observed_at")?,"receivedAt":r.try_get::<i64,_>("received_at")?})); }
                let projected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_projection.receipts WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id='inventory' AND generation=$3 AND event_id=$4)").bind(&tenant).bind(model::JOURNAL).bind(model::GENERATION).bind(event_id).fetch_one(&mut *conn).await?;
                Ok((position, assets, projected))
            })).await
        })).await?;
        Ok(
            serde_json::json!({"receipt":receipt.map(|r|serde_json::json!({"batchId":r.batch().id().as_str(),"receivedAt":r.received_at(),"decision":r.decision()})),"projection":if projected { BatchProjection::Projected } else { BatchProjection::NotProjected },"checkpoint":position,"assets":assets}),
        )
    }
    /// Call only after every operation/worker has been joined or dropped.
    pub async fn close(&self) -> Result<()> {
        let cancel = CancellationToken::new();
        let control = Control::new(&self.clock, self.clock.cutoff(BUDGET), &cancel);
        let projection = self.projection.close(&control).await;
        let observation = self.observation.close(self.clock.deadline()).await;
        let projection = if projection == CloseOutcome::Drained {
            Ok(())
        } else {
            Err(failure::classified(
                "projection_close",
                "projection",
                match projection {
                    CloseOutcome::Cancelled => failure::ProblemKind::Cancelled,
                    CloseOutcome::Deadline => failure::ProblemKind::Deadline,
                    CloseOutcome::Drained => unreachable!(),
                },
            ))
        };
        failure::finish(
            Ok(()),
            [
                ("projection_close", projection),
                ("observation_close", observation.map_err(Into::into)),
            ],
        )
    }
}

#[cfg(feature = "integration")]
pub mod test_support;

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum BatchProjection {
    Projected,
    NotProjected,
}
