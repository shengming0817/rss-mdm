//! Product process lifetime, driven by the existing RSS managed listener.
use crate::{ConfigIssue, Failure};
use crate::{Error, ProcessError, config::Config};
use rss_runtime::{
    DynManagedResource, LifecycleScope, ManagedResource, ScopeExit, ShutdownError, TotalDrainBudget,
};
use std::{sync::Arc, time::Duration};
// Product composition chooses the Tokio timer for the RSS lifecycle's time domain.
pub(crate) struct RuntimeTimer;
impl rss_request_context::Clock for RuntimeTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete product runtime clock owns the Tokio time domain"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for RuntimeTimer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
// Preparation includes five seconds of TLS and two seconds of failure audit.
// All three listeners use the same RSS owner and finite protocol budgets.
pub(crate) fn http_policy() -> rss_axum::Http1ServePolicy {
    rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            128,
            Duration::from_secs(8),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("constant listener budgets are valid"),
        Duration::from_secs(10),
        64,
        32768,
    )
    .expect("constant HTTP/1 limits are valid")
}
struct AccessResource(std::sync::Arc<crate::Database>);
impl ManagedResource for AccessResource {
    fn name(&self) -> &str {
        "access-store"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
pub async fn serve(
    config: Config,
    stop: impl std::future::Future<Output = Result<(), std::io::Error>>,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> Result<(), ProcessError> {
    let readiness = Arc::new(crate::inventory_runtime::Readiness::default());
    let stop_readiness = readiness.clone();
    let startup_cancel = tokio_util::sync::CancellationToken::new();
    let stop_cancel = startup_cancel.clone();
    let stop = async move {
        let result = stop.await;
        stop_cancel.cancel();
        stop_readiness.stop();
        result
    };
    let compiled = config
        .compile()
        .map_err(|e| ProcessError::at("startup.configuration", e))?;
    let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(40)).map_err(|_| {
            ProcessError::at("startup.budget", Error::Configuration(ConfigIssue::Budget))
        })?,
        Arc::new(RuntimeTimer),
    )
    .map_err(|_| ProcessError::at("startup.scope", Error::Unavailable(Failure::Runtime)))?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let (
                        listener,
                        app,
                        native_listeners,
                        audit_store,
                        access,
                        tenant,
                        runtime,
                        execution,
                        automation,
                        publications,
                        identity_audit,
                        timeline,
                        notifications,
                    ) = tokio::time::timeout(compiled.config.flow.startup_budget(), async {
                        let access = Arc::new(
                            crate::Database::connect(
                                compiled.config.access_database.options().map_err(|e| {
                                    ProcessError::at("startup.access_configuration", e)
                                })?,
                            )
                            .await
                            .map_err(|e| ProcessError::at("startup.access_store", e))?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(AccessResource(
                            access.clone(),
                        )));
                        let notifications = crate::worker_wake::Listener::new(
                            compiled
                                .config
                                .access_database
                                .options()
                                .map_err(|e| ProcessError::at("startup.notifications", e))?,
                            rss_request_context::TenantId::parse(
                                &compiled.config.identity.tenant_id,
                            )
                            .map_err(|_| {
                                ProcessError::at(
                                    "startup.notification_tenant",
                                    crate::Error::Malformed,
                                )
                            })?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(notifications.clone()));
                        use crate::inventory_runtime::{
                            Clock, InventoryRuntime, ObservationResource, ProjectionResource,
                        };
                        let clock = Clock::new(monotonic.clone());
                        let runtime_options =
                            compiled.config.runtime_database.options().map_err(|e| {
                                ProcessError::at("startup.runtime_database_configuration", e)
                            })?;
                        let observation =
                            ObservationResource::open(runtime_options.clone(), clock.clone())
                                .await
                                .map_err(|e| ProcessError::at("startup.observation", e.into()))?;
                        let observation_store = observation.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(observation));
                        let startup_control =
                            rss_projection::Control::new(&clock, clock.cutoff(), &startup_cancel);
                        let projection = ProjectionResource::open(
                            runtime_options,
                            clock.clone(),
                            &startup_control,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.projection", e.into()))?;
                        let projection_store = projection.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(projection));
                        let audit_store = access
                            .audit_store(&compiled.config.audit)
                            .await
                            .map_err(|e| ProcessError::at("startup.audit", e))?;
                        let audit_budget =
                            rss_mdm_audit_integration::budget::AuditBudget::with_cancellation(
                                Duration::from_secs(5),
                                startup_cancel.clone(),
                            );
                        let audit_control = audit_budget.control();
                        audit_store
                            .validate_tenant(
                                rss_request_context::TenantId::parse(
                                    &compiled.config.identity.tenant_id,
                                )
                                .map_err(|_| {
                                    ProcessError::at(
                                        "startup.audit",
                                        crate::Error::Unavailable(crate::Failure::Audit),
                                    )
                                })?,
                                &audit_control,
                            )
                            .await
                            .map_err(|error| ProcessError::at("startup.audit", error.into()))?;
                        let runtime = Arc::new(InventoryRuntime::new(
                            observation_store,
                            projection_store,
                            access.inventory(),
                            audit_store.clone(),
                            rss_request_context::TenantId::parse(
                                &compiled.config.identity.tenant_id,
                            )
                            .map_err(|_| {
                                assembly_error(Error::Configuration(ConfigIssue::Tenant))
                            })?,
                            clock,
                            readiness,
                        ));
                        let protection = compiled
                            .config
                            .native_protector()
                            .map_err(|e| ProcessError::at("startup.native_protection", e))?;
                        let content = crate::execution_assembly::open_content(
                            &compiled.config,
                            protection.clone(),
                        )
                        .map_err(|e| ProcessError::at("startup.content", e))?;
                        let planning = compiled
                            .config
                            .flow
                            .open(
                                audit_store.clone(),
                                rss_request_context::TenantId::parse(
                                    &compiled.config.identity.tenant_id,
                                )
                                .map_err(|_| {
                                    assembly_error(Error::Flow(
                                        rss_mdm_flow_service::Error::Malformed,
                                    ))
                                })?,
                                Arc::new(crate::clock::SystemClock),
                                content.clone(),
                                |resource| {
                                    startup.stage_resource(DynManagedResource::new_box(resource))
                                },
                            )
                            .await
                            .map_err(|e| ProcessError::at("startup.flow", e))?;
                        let execution = crate::execution_assembly::open(
                            &compiled.config,
                            protection,
                            audit_store.clone(),
                            content,
                            planning.publications.services.clone(),
                            rss_device_command_postgres::CommandClock::Postgres,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.execution", e))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            rss_mdm_execution_service::Resource(execution.service.clone()),
                        ));
                        let automation = crate::automation::Automation::connect(
                            planning.planning.clone(),
                            planning.assets.clone(),
                            planning.compliance.clone(),
                            compiled
                                .config
                                .flow
                                .storage
                                .database
                                .options()
                                .map_err(|e| ProcessError::at("startup.asset_automation", e))?,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.asset_automation", e.into()))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            crate::automation::Resource(automation.clone()),
                        ));
                        let listen = compiled.config.listen;
                        let tenant = compiled.config.identity.tenant_id.clone();
                        let gateway = compiled.config.trusted_gateway;
                        let identity = crate::identity::Identity::connect(
                            &compiled.config,
                            compiled.identity_management.clone(),
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(|error| ProcessError::at("startup.identity", error))?;
                        let identity_audit = crate::identity_audit::Worker::open(
                            &compiled.config,
                            identity.audit_readiness.clone(),
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(|error| ProcessError::at("startup.identity_audit", error))?;
                        let timeline = access
                            .timeline(audit_store.clone(), identity.tenant, &planning.cursor_key)
                            .map_err(|e| ProcessError::at("startup.timeline", e))?;
                        timeline.initialize().await.map_err(|_| {
                            ProcessError::at(
                                "startup.timeline",
                                Error::Unavailable(Failure::Database),
                            )
                        })?;
                        let mut app = crate::api::from_compiled(
                            compiled,
                            crate::api::AssemblyDependencies {
                                timeline: timeline.clone(),
                                audit_store: audit_store.clone(),
                                clock: Arc::new(crate::clock::SystemClock),
                                monotonic,
                                access: access.clone(),
                                runtime: runtime.clone(),
                                flow: planning.clone(),
                                execution: execution.clone(),
                                identity,
                            },
                        )
                        .map_err(assembly_error)?;
                        app.browser = app.browser.layer(axum::middleware::from_fn_with_state(
                            gateway,
                            crate::identity::ingress,
                        ));
                        let listener =
                            tokio::net::TcpListener::bind(listen).await.map_err(|e| {
                                ProcessError::Io {
                                    stage: "startup.listener_bind",
                                    kind: e.kind(),
                                }
                            })?;
                        let mut native_listeners = Vec::new();
                        for (kind, router) in app.listeners.drain(..) {
                            let listener = tokio::net::TcpListener::bind(router.listen)
                                .await
                                .map_err(|e| ProcessError::Io {
                                    stage: kind.name(),
                                    kind: e.kind(),
                                })?;
                            native_listeners.push((kind, listener, router));
                        }
                        listener_receipt(&listener, &mut std::io::stdout().lock()).map_err(
                            |e| ProcessError::Io {
                                stage: "startup.listener_receipt",
                                kind: e.kind(),
                            },
                        )?;
                        Ok::<_, ProcessError>((
                            listener,
                            app,
                            native_listeners,
                            audit_store,
                            access,
                            tenant,
                            runtime,
                            execution,
                            automation,
                            planning.publications.clone(),
                            identity_audit,
                            timeline,
                            notifications,
                        ))
                    })
                    .await
                    .map_err(|_| ProcessError::Stage {
                        stage: "startup",
                        kind: "total deadline exceeded",
                    })??;
                    let signals = notifications.signals.clone();
                    let mut launch = startup.commit();
                    launch.stage_task_with_token(notifications.registration().critical());
                    if let Some(apple) = app.apple {
                        launch.stage_task_with_token(
                            rss_mdm_apple_channel::push::registration(
                                apple.channel.clone(),
                                execution.clone(),
                                access.apple_store(),
                                audit_store.clone(),
                                tenant.clone(),
                                signals.handle(crate::worker_wake::Work::Apple),
                            )
                            .critical(),
                        );
                    }
                    launch.stage_deferred_task_with_token(publications.registration().critical());
                    launch.stage_deferred_task_with_token(identity_audit.registration().critical());
                    launch.stage_deferred_task_with_token(timeline.registration().critical());
                    launch.stage_deferred_task_with_token(
                        execution.registration(signals.execution()).critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        automation.registration(signals.flow()).critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        runtime
                            .registration(signals.handle(crate::worker_wake::Work::Inventory))
                            .critical(),
                    );
                    if native_listeners
                        .iter()
                        .any(|(kind, _, _)| kind.windows_retention())
                    {
                        launch.stage_task_with_token(
                            rss_mdm_windows_channel::retention::registration(
                                access.windows_store(),
                                audit_store.clone(),
                                tenant.clone(),
                                signals.handle(crate::worker_wake::Work::Windows),
                            )
                            .critical(),
                        );
                    }
                    launch.stage_task_with_token(
                        rss_axum::serve_http1_registration(
                            listener,
                            app.browser,
                            rss_axum::PlainTransport,
                            "mdm-http",
                            http_policy(),
                        )
                        .critical(),
                    );
                    for (kind, listener, router) in native_listeners {
                        launch.stage_task_with_token(
                            crate::native::tls::registration(
                                listener,
                                router,
                                audit_store.clone(),
                                tenant.clone(),
                                kind,
                            )
                            .critical(),
                        );
                    }
                    launch.finish();
                    std::future::pending().await
                })
            },
            stop,
        )
        .await
        .map_err(|_| ProcessError::at("lifecycle.drive", Error::Unavailable(Failure::Runtime)))?;
    let clean = outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean());
    if let Ok(receipt) = outcome.shutdown() {
        for failure in receipt.failures() {
            use rss_runtime::ShutdownFailureKind as K;
            let kind = match failure.kind {
                K::Failed(_) => "failed",
                K::TimedOut(_) => "timed_out",
                K::Panicked => "panicked",
                K::Cancelled => "cancelled",
                K::TaskUnknown => "task_unknown",
                K::DeadlineExceeded => "deadline_exceeded",
                K::BudgetExhausted => "budget_exhausted",
            };
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_shutdown_failure","resource":failure.name,"kind":kind})
            );
        }
    }
    finish(outcome.exit(), clean)
}
fn assembly_error(error: Error) -> ProcessError {
    let stage = match error {
        Error::Configuration(ConfigIssue::EnrollmentCa) => "startup.windows_ca",
        Error::Configuration(ConfigIssue::ProtocolKey) => "startup.protocol_key",
        Error::Configuration(ConfigIssue::NativeTls) => "startup.native_tls",
        Error::Configuration(ConfigIssue::WindowsListeners) => "startup.windows_listeners",
        _ => "startup.identity",
    };
    ProcessError::at(stage, error)
}
fn finish(
    exit: &ScopeExit<(), ProcessError, std::io::Error>,
    clean: bool,
) -> Result<(), ProcessError> {
    match exit {
        ScopeExit::CriticalTaskExited(exit) => Err(ProcessError::CriticalTask {
            task: exit.name().into(),
            reason: exit.reason(),
            cleanup_failed: !clean,
        }),
        ScopeExit::Completed(Err(error)) => Err(error.clone()),
        _ if !clean => Err(ProcessError::Stage {
            stage: "shutdown",
            kind: "resource drain failed",
        }),
        ScopeExit::StopRequested(Ok(())) => Ok(()),
        ScopeExit::StopRequested(Err(e)) => Err(ProcessError::Io {
            stage: "shutdown.signal",
            kind: e.kind(),
        }),
        _ => Err(ProcessError::Stage {
            stage: "lifecycle",
            kind: "scope terminated",
        }),
    }
}
// Report the address of the listener we still own, including OS-assigned ports.
// ref: tokio net/tcp/listener.rs (bind port 0 + local_addr).
fn listener_receipt(
    listener: &tokio::net::TcpListener,
    output: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(
        output,
        "{}",
        serde_json::json!({"event":"listener-bound", "address":listener.local_addr()?.to_string()})
    )?;
    output.flush()
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
}

#[cfg(test)]
#[path = "../tests/lifecycle/unit.rs"]
mod tests;
