use super::*;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
use std::sync::Mutex;
#[path = "completion.rs"]
mod completion;

pub(crate) struct Automation {
    service: Arc<Planning>,
    assets: Arc<assets::AssetService>,
    store: rss_reconcile_postgres::PgStore,
}
impl Automation {
    pub(crate) async fn open(
        flow: Arc<crate::flow::Flow>,
        database: &crate::config::Database,
    ) -> std::result::Result<Arc<Self>, Error> {
        Self::connect(
            flow.planning.clone(),
            flow.assets.clone(),
            database.options()?,
        )
        .await
    }
    pub(crate) async fn connect(
        service: Arc<Planning>,
        assets: Arc<assets::AssetService>,
        options: sqlx::postgres::PgConnectOptions,
    ) -> std::result::Result<Arc<Self>, Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| Error::Unavailable(Failure::AutomationConnection))?;
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let store = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await {
            Ok(store) => store,
            Err(_) => {
                pool.close().await;
                return Err(Error::Unavailable(Failure::AutomationAdmission));
            }
        };
        // Startup retries retained input without discarding its failure diagnosis.
        if rss_reconcile::DurableStore::wake(&store, &asset_target(service.tenant), &control)
            .await
            .is_err()
        {
            let _ = store.close(&control).await;
            return Err(Error::Unavailable(Failure::AutomationStorage));
        }
        Ok(Arc::new(Self {
            service,
            assets,
            store,
        }))
    }
    pub(crate) fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-asset-automation", Duration::from_secs(8));
        let _ = self.service.automation_task.set(status);
        task.into_registration(move |cancel|async move {
            let timer=Timer::new();let control=rss_reconcile::Control::new(&timer,Duration::MAX,&cancel);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:4,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=rss_reconcile::Scope::new(self.service.tenant,"mdm.assets").expect("constant domain");
            let runner=async {rss_reconcile::run(self.as_ref(),self.as_ref(),&scope,policy,&control,|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_automation_failure","diagnostic":format!("{event:?}")}));
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)};
            let bridge=async {
                loop {
                    if cancel.is_cancelled() {return Ok(());}
                    let result=async {self.service.forward_asset_changes().await?;jobs::forward_jobs(&self.service.runtime,self.service.tenant,&self.service.audit_store).await?;Ok::<_,Error>(())}.await;
                    let delay=if let Err(error)=result {
                        eprintln!("{}",serde_json::json!({"event":"mdm_automation_bridge_failure","reason":format!("{error:?}")}));
                        Duration::from_secs(1)
                    }else{Duration::from_millis(50)};
                    tokio::select! {()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(delay)=>{}}
                }
            };
            tokio::try_join!(runner,bridge).map(|_|())
        })
    }
}
pub(crate) struct Resource(pub(crate) Arc<Automation>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "asset-automation-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        match self.0.store.close(&control).await {
            rss_reconcile_postgres::CloseOutcome::Drained => Ok(()),
            _ => Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                "asset automation storage did not drain",
            ))),
        }
    }
}
fn reconcile_error(error: Error) -> rss_reconcile::Error {
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::Conflict => rss_reconcile::ErrorKind::Fenced,
        _ => rss_reconcile::ErrorKind::Transient,
    })
}
fn fault(error: Fault, reason: &Mutex<Option<Error>>) -> PgError {
    match error {
        Fault::Request(error) => {
            *reason.lock().expect("failure slot") = Some(error);
            sqlx::Error::Protocol("asset automation rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => error.into(),
    }
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for Automation {
    type State = bool;
    fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            control.check()?;
            let failure = Mutex::new(None);
            let result = self
                .service
                .runtime
                .local_tx_with_context(
                    self.service.tenant,
                    deadline(),
                    (
                        &self.service,
                        claim.target().entity(),
                        &failure,
                        &self.assets,
                    ),
                    |ctx, tx| {
                        Box::pin(async move {
                            let result = if ctx.1 == "changes" {
                                ctx.0.asset_work_pending(tx).await
                            } else {
                                match ctx
                                    .1
                                    .strip_prefix("job:")
                                    .and_then(|s| Uuid::parse_str(s).ok())
                                {
                                    Some(id) => crate::automation::jobs::read_in(tx, id)
                                        .await
                                        .map(|(_, done, _, _, _)| !done),
                                    None => Err(Error::Malformed.into()),
                                }
                            };
                            result.map_err(|e| fault(e, ctx.2))
                        })
                    },
                )
                .await
                .fold(
                    Ok,
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                    |_| {
                        Err(failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .unwrap_or(Error::Unavailable(Failure::AutomationStorage)))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                );
            Ok(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(result.map_err(reconcile_error)?),
            ))
        })
    }
    fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        Box::pin(async move {
            let failure = Mutex::new(None);
            let attempt = self
                .service
                .runtime
                .local_tx_with_context(
                    self.service.tenant,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                    (
                        &self.service,
                        claim,
                        (
                            &self.service,
                            claim.target().entity(),
                            &failure,
                            &self.assets,
                        ),
                    ),
                    |(service, claim, context), tx| {
                        Box::pin(async move {
                            service
                                .audit_store
                                .lock_in(tx)
                                .await
                                .map_err(PgError::from)?;
                            rss_reconcile_postgres::messaging::protect_in(
                                tx,
                                claim,
                                context,
                                |ctx, tx| {
                                    Box::pin(async move {
                                        let result: Result<()> = async {
                                            if ctx.1 == "changes" {
                                                let compliance = crate::compliance::Compliance::new(
                                                    (*ctx.0).clone(),
                                                );
                                                ctx.0.dispatch_assets_in(tx, &compliance).await?;
                                                return ctx.0.clear_ingress_failure_in(tx).await;
                                            }
                                            let id = checked_input(
                                                ctx.1
                                                    .strip_prefix("job:")
                                                    .ok_or(Error::Malformed)
                                                    .and_then(|s| {
                                                        Uuid::parse_str(s)
                                                            .map_err(|_| Error::Malformed)
                                                    }),
                                            )?;
                                            let (job, done, _, cursor, _) =
                                                crate::automation::jobs::read_in(tx, id).await?;
                                            if done {
                                                return Ok(());
                                            }
                                            match job {
                                                JobInput::Compliance { ref input } => {
                                                    crate::compliance::Compliance::new(
                                                        (*ctx.0).clone(),
                                                    )
                                                    .advance(tx, id, input, cursor)
                                                    .await
                                                }
                                                JobInput::AssetQuery { .. } => {
                                                    ctx.3
                                                        .advance_asset_query_in(
                                                            tx, id, &job, cursor,
                                                        )
                                                        .await
                                                }
                                                JobInput::Group { group, .. } => {
                                                    tx.prepare_outbox_partitions(&[ctx
                                                        .0
                                                        .groups
                                                        .partition(
                                                        &group.to_string(),
                                                    )?])
                                                    .await?;
                                                    ctx.0
                                                        .advance_group_job_in(tx, id, &job, cursor)
                                                        .await
                                                }
                                                JobInput::Scope { scope } => {
                                                    ctx.0
                                                        .advance_scope_job_in(tx, id, scope, cursor)
                                                        .await
                                                }
                                                JobInput::Policy { .. } => {
                                                    ctx.0.advance_policy_job_in(tx, id, &job).await
                                                }
                                            }
                                        }
                                        .await;
                                        result.map_err(|e| fault(e, ctx.2))
                                    })
                                },
                            )
                            .await
                        })
                    },
                )
                .await;
            // Only a confirmed rollback may be followed by a durable terminal
            // rejection. Unknown settlement is retried under the original identity.
            let rejection = attempt
                .fold(
                    |_| Ok(None),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                    |error| {
                        eprintln!("{}",serde_json::json!({"event":"mdm_automation_rollback","target":claim.target().entity(),"diagnostic":format!("{error:?}")}));
                        failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .map(Some)
                            .ok_or(Error::Unavailable(Failure::AutomationStorage))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                )
                .map_err(reconcile_error)?;
            let detail = match &rejection {
                Some(Error::Planning(crate::planning::error::PlanningError::Plan(detail))) => {
                    Some(detail.clone())
                }
                _ => None,
            };
            let terminal = match rejection {
                Some(Error::Conflict) => Some("superseded"),
                Some(Error::Unavailable(
                    Failure::AssetObjectLimit
                    | Failure::AssetBytesLimit
                    | Failure::AssetSourceLimit,
                )) => Some("capacity_exceeded"),
                Some(ref error) if error.is_not_found() => Some("source_unavailable"),
                Some(Error::Planning(crate::planning::error::PlanningError::Plan(ref detail))) => {
                    Some(detail.reason.code())
                }
                Some(Error::Planning(crate::planning::error::PlanningError::TargetLimit)) => {
                    Some("configuration_target_limit")
                }
                Some(Error::Malformed) => Some("invalid_input"),
                Some(error) => return Err(reconcile_error(error)),
                None => return Ok(()),
            };
            let Some(id) = claim
                .target()
                .entity()
                .strip_prefix("job:")
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Transient,
                ));
            };
            self.service.runtime.local_tx_with_context(
    self.service.tenant,
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),
    (&self.service, claim, &self.service),
    |(service, claim, context), tx| Box::pin(async move {
        service.audit_store.lock_in(tx).await.map_err(PgError::from)?;
        rss_reconcile_postgres::messaging::protect_in(tx, claim, context, |service,tx| {
                    Box::pin(async move {
                        if let Some(detail) = detail {
                            let tenant = tx.tenant_id().to_string();
                            let document = serde_json::to_value(detail).expect("closed failure DTO");
                            tx.with_connection(move |c| Box::pin(async move {
                                sqlx::query("UPDATE mdm_automation.automation_jobs SET failure_detail=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                                    .bind(tenant).bind(id.to_string()).bind(document).execute(c).await?; Ok(())
                            })).await?;
                        }
                        if terminal == Some("superseded") {
                            service
                                .retry_superseded_group_in(tx, id)
                                .await
                                .map_err(|e| fault(e, &Mutex::new(None)))?;
                        }
                        crate::automation::jobs::finish_job_in(tx, &service.audit_store, id, terminal)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))
                    })
                }).await
    }),
)
            .await
            .fold(
                Ok,
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::Transient,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::Transient,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::CommitUnknown,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::CommitUnknown,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::Transient,
                    ))
                },
            )
        })
    }
}
