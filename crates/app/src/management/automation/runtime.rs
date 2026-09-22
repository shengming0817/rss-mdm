use super::*;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
use std::sync::Mutex;

pub(crate) struct Automation {
    service: Arc<Management>,
    store: rss_reconcile_postgres::PgStore,
}
impl Automation {
    pub(crate) async fn open(
        service: Arc<Management>,
        database: &crate::config::Database,
    ) -> std::result::Result<Arc<Self>, Error> {
        Self::connect(service, database.options()?).await
    }
    pub(in crate::management) async fn connect(
        service: Arc<Management>,
        options: sqlx::postgres::PgConnectOptions,
    ) -> std::result::Result<Arc<Self>, Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| Error::Unavailable(Failure::ManagementConnection))?;
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let store = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await {
            Ok(store) => store,
            Err(_) => {
                pool.close().await;
                return Err(Error::Unavailable(Failure::ManagementAdmission));
            }
        };
        Ok(Arc::new(Self { service, store }))
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
            let runner=async {rss_reconcile::run(&self.store,self.as_ref(),&scope,policy,&control,|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_automation_failure","diagnostic":format!("{event:?}")}));
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)};
            let bridge=async {
                loop {
                    if cancel.is_cancelled() {return Ok(());}
                    let result=async {self.service.forward_asset_changes().await?;self.service.forward_jobs().await?;Ok::<_,Error>(())}.await;
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
                    (&self.service, claim.target().entity(), &failure),
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
                                    Some(id) => {
                                        ctx.0.job_in(tx, id).await.map(|(_, done, _, _, _)| !done)
                                    }
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
                    |_| Err(Error::Unavailable(Failure::ManagementStorage)),
                    |_| {
                        Err(failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .unwrap_or(Error::Unavailable(Failure::ManagementStorage)))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::ManagementStorage)),
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
            let attempt = rss_reconcile_postgres::messaging::protect(
                &self.service.runtime,
                claim,
                control,
                (&self.service, claim.target().entity(), &failure),
                |ctx, tx| {
                    Box::pin(async move {
                        let result: Result<()> = async {
                            if ctx.1 == "changes" {
                                return ctx.0.dispatch_assets_in(tx).await;
                            }
                            let id = input(
                                ctx.1
                                    .strip_prefix("job:")
                                    .ok_or(Error::Malformed)
                                    .and_then(|s| Uuid::parse_str(s).map_err(|_| Error::Malformed)),
                            )?;
                            let (job, done, _, cursor, _) = ctx.0.job_in(tx, id).await?;
                            if done {
                                return Ok(());
                            }
                            match job {
                                JobInput::Group {
                                    group,
                                    watermark,
                                    publish,
                                    automatic,
                                } => {
                                    tx.prepare_outbox_partitions(&[ctx
                                        .0
                                        .groups
                                        .partition(&group.to_string())?])
                                        .await?;
                                    ctx.0
                                        .advance_group_job_in(
                                            tx, id, group, watermark, publish, automatic, cursor,
                                        )
                                        .await
                                }
                                JobInput::Scope { scope } => {
                                    ctx.0.advance_scope_job_in(tx, id, scope, cursor).await
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
            .await;
            // Only a confirmed rollback may be followed by a durable terminal
            // rejection. Unknown settlement is retried under the original identity.
            let rejection = attempt
                .fold(
                    |_| Ok(None),
                    |_| Err(Error::Unavailable(Failure::ManagementStorage)),
                    |_| {
                        failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .map(|e| Some(e))
                            .ok_or(Error::Unavailable(Failure::ManagementStorage))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::ManagementStorage)),
                )
                .map_err(reconcile_error)?;
            let terminal = match rejection {
                Some(Error::Conflict) => Some("superseded"),
                Some(Error::Unavailable(Failure::AssetObjectLimit | Failure::AssetBytesLimit)) => {
                    Some("capacity_exceeded")
                }
                Some(Error::ManagementNotFound(_)) | Some(Error::NotFound) => {
                    Some("source_unavailable")
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
            rss_reconcile_postgres::messaging::protect(
                &self.service.runtime,
                claim,
                control,
                &self.service,
                |service, tx| {
                    Box::pin(async move {
                        if terminal == Some("superseded") {
                            service
                                .retry_superseded_group_in(tx, id)
                                .await
                                .map_err(|e| fault(e, &Mutex::new(None)))?;
                        }
                        service
                            .finish_job_in(tx, id, terminal)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))
                    })
                },
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
