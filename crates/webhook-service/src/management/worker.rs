use super::*;
use rss_transactional_messaging::policy::OperationDeadline;
use webhooks::transport::{AuthorizationFailure, AuthorizedTarget, Publication, TargetAuthorizer};
struct Authorizer {
    runtime: Arc<PgRuntime>,
    host: Arc<authority::Host>,
}
impl TargetAuthorizer for Authorizer {
    async fn authorize(
        &self,
        p: &Publication<'_>,
        deadline: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        if p.tenant().to_string() != self.host.tenant.to_string() {
            return Err(AuthorizationFailure::Denied);
        }
        let id = Uuid::parse_str(p.id().as_str()).map_err(|_| AuthorizationFailure::Denied)?;
        let target = p.target().id().as_str().to_owned();
        let version = p.target().version().get();
        let fingerprint = p.fingerprint().as_bytes().to_vec();
        let host = self.host.clone();
        self.runtime
            .local_tx(p.tenant(), deadline, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(async {
                                let b = storage::binding(c, host.tenant, id).await?;
                                if b.subscription.id.to_string() != target
                                    || b.subscription.target_version as u64 != version
                                    || b.fingerprint != fingerprint
                                {
                                    return Err(webhooks::Error::Denied);
                                }
                                let now = host
                                    .clock
                                    .unix_seconds()
                                    .map_err(|_| webhooks::Error::Storage)?;
                                host.policies
                                    .target(c, &host.protection, host.tenant, &b.subscription, now)
                                    .await
                            }
                            .await)
                        })
                    })
                    .await?
                    .map_err(PgError::from)
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(AuthorizationFailure::Unavailable),
                |e| {
                    Err(
                        if e.kind()
                            == rss_transactional_messaging::error::MessagingErrorKind::Permanent
                        {
                            AuthorizationFailure::Denied
                        } else {
                            AuthorizationFailure::Unavailable
                        },
                    )
                },
                |_| Err(AuthorizationFailure::Unavailable),
                |_| Err(AuthorizationFailure::Unavailable),
                |_| Err(AuthorizationFailure::Unavailable),
            )
    }
}
struct Wall(Arc<dyn Clock>);
impl webhooks::transport::WallClock for Wall {
    fn unix_seconds(&self) -> i64 {
        // reason: negative UTC makes the adapter reject signing if the host clock is unavailable.
        self.0.unix_seconds().unwrap_or(-1)
    }
}
struct Diagnostics;
impl rss_transactional_messaging::observability::TransactionalMessagingEmitter for Diagnostics {
    fn emit(
        &self,
        event: rss_transactional_messaging::observability::TransactionalMessagingObservation,
    ) {
        // reason: product delivery observations are persisted separately; only closed runtime failures log.
        if let rss_transactional_messaging::observability::TransactionalMessagingObservation::RuntimeFailure { phase, kind } = event {
            eprintln!("{}", serde_json::json!({"event":"webhook_runtime_failure", "phase":phase.as_label(), "kind":kind.as_label()}));
        }
    }
}
impl Service {
    pub async fn run(
        self: Arc<Self>,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<(), rss_transactional_messaging::error::MessagingError> {
        webhooks::worker::run(
            self.runtime.clone(),
            self.host.clone(),
            Authorizer {
                runtime: self.runtime.clone(),
                host: self.host.clone(),
            },
            Arc::new(self.timer.clone()),
            Wall(self.host.clock.clone()),
            Arc::new(Diagnostics),
            token,
        )
        .await
    }
}
