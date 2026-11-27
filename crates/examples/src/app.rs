use crate::failure;
use crate::{
    fixture::FixtureAuthority,
    storage::{self, BUDGET, Clock},
};
use anyhow::Result;
use rss_mdm_inventory as model;
use rss_mdm_inventory_postgres::{Inventory, definition};
use rss_observation::{
    Access, Authority, Batch, Id, JournalReadGrant, LifecycleGrant, ObservationStore, Policy,
    ReadGrant, ReceiveOutcome, VerifiedBatch,
};
use rss_observation_postgres::PgSource;
use rss_projection::{
    Control, GenerationStart, PageBudget, ProjectionScope, ReplayBound, RunLimit, Source,
    SourceScope, Stop,
};
use rss_projection_postgres::CloseOutcome;
use sqlx::postgres::PgConnectOptions;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Fixture operations own component authority and lifecycle.
/// ```compile_fail
/// fn bypass(app: rss_mdm_examples::app::App) { let _ = app.observation; }
/// ```
/// ```compile_fail
/// fn bypass(app: rss_mdm_examples::app::App) { let _ = app.projection; }
/// ```
/// ```compile_fail
/// fn replace(app: rss_mdm_examples::app::App) { let _ = app.clock; }
/// ```
/// ```compile_fail
/// fn bypass(app: rss_mdm_examples::app::App) { let _ = app.source(); }
/// ```
pub struct App {
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    observation: Arc<rss_observation_postgres::PgStore<Clock>>,
    projection: rss_projection_postgres::PgStore,
    clock: Clock,
    authority: FixtureAuthority,
}
impl App {
    pub async fn open(
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        options: &PgConnectOptions,
        authority: FixtureAuthority,
        clock: Clock,
    ) -> Result<Self> {
        anyhow::ensure!(
            binding.tenant() == authority.scope().tenant(),
            "fixture scope mismatch"
        );
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
        let cancel = CancellationToken::new();
        let control = Control::new(&clock, clock.cutoff(BUDGET), &cancel);
        let projection = async {
            let pool = control
                .run(async {
                    storage::pool(options).await.map_err(|_| {
                        rss_projection::Error::new(rss_projection::ErrorKind::Unavailable)
                    })
                })
                .await?;
            let result = async {
                control
                    .run(async {
                        rss_mdm_inventory_postgres::verify_admission(&pool)
                            .await
                            .map_err(|_| {
                                rss_projection::Error::new(rss_projection::ErrorKind::Unavailable)
                            })
                    })
                    .await?;
                rss_projection_postgres::PgStore::new(pool.clone(), &control).await
            }
            .await;
            match result {
                Ok(store) => Ok(store),
                Err(error) => failure::finish(
                    Err(failure::at("projection_open", error)),
                    [("projection_pool_close", storage::close_pool(&pool).await)],
                ),
            }
        }
        .await;
        match projection {
            Ok(projection) => Ok(Self {
                binding,
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
    fn source_scope(&self) -> SourceScope {
        self.projection_scope().source().clone()
    }
    fn projection_scope(&self) -> ProjectionScope {
        rss_mdm_inventory_postgres::projection_scope(self.authority.scope().tenant())
    }
    fn source(&self) -> Result<Arc<PgSource<Clock, rss_observation_postgres::LocalPages>>> {
        Ok(Arc::new(
            PgSource::new(
                self.observation.clone(),
                JournalReadGrant::verify(&self.authority, self.authority.scope().tenant())?,
                self.source_scope(),
                rss_observation::Batch::MAX_ENCODED_BYTES,
            )?
            .into_local(),
        ))
    }
    // Trusted fixture input is converted by the collection owner before journal admission.
    async fn prepare_fixture(&self, batch: &Batch) -> Result<Batch> {
        use sqlx::Connection;
        let definition = crate::fixture::definition();
        definition.validate_scope(self.authority.scope())?;
        definition.validate(batch)?;
        let progress = model::CollectionProgress::reported(
            definition.clone(),
            batch.body(),
            batch.observed_at_seconds(),
        )?;
        let mut connection =
            sqlx::PgConnection::connect_with(&storage::collection_options()?).await?;
        let mut tx = connection.begin().await?;
        let tenant = self.authority.scope().tenant();
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        rss_mdm_inventory_postgres::register_collection_in(&mut tx, tenant, &definition).await?;
        let reference = rss_mdm_inventory_postgres::seal_collection_in(
            &mut tx,
            rss_mdm_inventory_postgres::CollectionCompletion {
                trusted: true,
                scope: self.authority.scope(),
                run: batch.id().as_str(),
                sequence: batch.sequence(),
                observed_at: batch.observed_at_seconds(),
                progress: &progress,
            },
        )
        .await?;
        tx.commit().await?;
        connection.close().await?;
        Ok(reference)
    }
    pub async fn ingest(&self, batch: Batch) -> Result<ReceiveOutcome> {
        let batch = self.prepare_fixture(&batch).await?;
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
        let scope = self.projection_scope();
        let cutoff = self.clock.cutoff(BUDGET);
        let capture = Control::new(&self.clock, cutoff, cancel);
        let through = source.high_water(source.scope(), &capture).await?;
        let window = crate::window::Window {
            source: source.clone(),
            through,
        };
        let control = Control::new(&self.clock, cutoff, cancel);
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
            .projection(claim, Inventory::new(source.clone(), self.binding))?;
        let (mut applied, mut duplicates, mut filtered) = (0_u64, 0_u64, 0_u64);
        loop {
            let control = Control::new(&self.clock, cutoff, cancel);
            let report = rss_projection::run_batched(
                &window,
                &execution,
                &control,
                RunLimit::new(
                    PageBudget::new(64, rss_projection::Event::MAX_PAYLOAD_BYTES)?,
                    256,
                )?,
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
        let lookup = self
            .observation
            .lookup(
                &ReadGrant::verify(&self.authority, scope.clone())?,
                id,
                self.clock.deadline(),
            )
            .await?;
        // RSS PgSource v1 event identity is the exact record fingerprint in lowercase hex.
        let (receipt, event_id) = match &lookup {
            rss_observation::LookupOutcome::Found(record) => {
                let fingerprint = record.batch().fingerprint(record.scope())?;
                let id = fingerprint
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                (
                    serde_json::json!({"status":"found","batchId":record.batch().id().as_str(),"receivedAt":record.received_at(),"decision":record.decision()}),
                    Some(id),
                )
            }
            rss_observation::LookupOutcome::Expired => {
                (serde_json::json!({"status":"expired"}), None)
            }
            rss_observation::LookupOutcome::NotFound => {
                (serde_json::json!({"status":"not_found"}), None)
            }
        };
        let projection = self.projection_scope();
        let source = projection.source().clone();
        let tenant = source.tenant();
        let cancel = CancellationToken::new();
        let control = Control::new(&self.clock, self.clock.cutoff(BUDGET), &cancel);
        let status = match event_id {
            Some(event_id) => Some(
                self.projection
                    .receipt_status(
                        &rss_projection::ReceiptQuery::new(
                            projection.clone(),
                            definition(),
                            event_id,
                        )?,
                        &control,
                    )
                    .await?,
            ),
            None => None,
        };
        let position = status
            .and_then(|status| status.checkpoint())
            .and_then(|checkpoint| checkpoint.position)
            .map(|p| p.get());
        let projection =
            BatchProjection::from_evidence(&lookup, status.is_some_and(|s| s.is_settled()));
        let selected = scope.clone();
        let assets = self
            .projection
            .local_tx(&source, &control, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |conn| {
                        Box::pin(async move {
                            let catalog = rss_mdm_inventory_postgres::catalog_in(conn, tenant)
                                .await
                                .map_err(|_| sqlx::Error::Protocol("inspect catalog".into()))?;
                            let fields = catalog.fields().map(|f| f.key).collect::<Vec<_>>();
                            let rows = rss_mdm_inventory_postgres::read_in(
                                conn,
                                tenant,
                                &[selected],
                                &fields,
                            )
                            .await
                            .map_err(|_| sqlx::Error::Protocol("asset inspect failed".into()))?;
                            Ok(rows)
                        })
                    })
                    .await
                })
            })
            .await?;
        Ok(
            serde_json::json!({"receipt":receipt,"projection":projection,"checkpoint":position,"assets":assets}),
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

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum BatchProjection {
    Projected,
    Unconfirmed,
    NotProjected,
}

impl BatchProjection {
    fn from_evidence(receipt: &rss_observation::LookupOutcome, settled: bool) -> Self {
        match (receipt, settled) {
            (_, true) => Self::Projected,
            (rss_observation::LookupOutcome::Expired, false) => Self::Unconfirmed,
            _ => Self::NotProjected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BatchProjection;
    use rss_observation::LookupOutcome::{Expired, NotFound};

    #[test]
    fn inspect_distinguishes_missing_evidence_from_a_negative_result() {
        for (lookup, settled, expected) in [
            (Expired, false, "unconfirmed"),
            (Expired, true, "projected"),
            (NotFound, false, "not_projected"),
        ] {
            let result = BatchProjection::from_evidence(&lookup, settled);
            assert_eq!(serde_json::to_value(result).unwrap(), expected);
        }
    }
}
