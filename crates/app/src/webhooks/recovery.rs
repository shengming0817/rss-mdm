use super::*;
use recovery::{Authorization, AuthorizationSubject, Authorizer, Challenge, RecoveryStore};
use rss_transactional_messaging_recovery as recovery;
struct Grant<'a> {
    backend: &'a Backend,
    proof: Arc<AuthorizedPrincipal>,
    audit: RequestAudit,
    command: Command,
}
impl Authorizer for Grant<'_> {
    async fn authorize(
        &self,
        challenge: Challenge<'_>,
        _deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Authorization, recovery::Error> {
        let Command::Redrive {
            delivery,
            operation,
            version,
        } = self.command
        else {
            return Err(recovery::Error::Unauthorized);
        };
        let AuthorizationSubject::Mutation(m) = challenge.subject() else {
            return Err(recovery::Error::Unauthorized);
        };
        let recovery::Target::Outbox(id) = m.target() else {
            return Err(recovery::Error::Unauthorized);
        };
        if challenge.tenant() != self.backend.tenant
            || id.as_str() != delivery.to_string()
            || m.operation().to_string() != operation.to_string()
            || m.version().get() as u64 != version
            || !matches!(m.action(), recovery::Action::Redrive)
        {
            return Err(recovery::Error::Unauthorized);
        }
        self.backend
            .execute_transaction(
                self.proof.clone(),
                self.audit.fact_copy("webhook_redrive_intent"),
                self.command.clone(),
            )
            .await
            .map_err(|_| recovery::Error::Unauthorized)?;
        Ok(challenge.authorized())
    }
}
impl Backend {
    pub(super) async fn redrive(
        &self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> Result<Value, HttpError> {
        let Command::Redrive {
            delivery,
            operation,
            version,
        } = command.clone()
        else {
            return Err(HttpError::Malformed);
        };
        proof.manage(Permission::WebhookReplay)?;
        proof.bind_audit(&audit)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(HttpError::Forbidden);
        }
        // The authorization intent and RSS recovery settle in separate transactions.
        // Only the recovery attempt owns the request's write outcome.
        audit.require_request_settlement();
        audit.operation(operation, "webhook_redrive");
        let request = recovery::Mutation::new(
            self.tenant,
            recovery::OperationId::parse(&operation.to_string())
                .map_err(|_| HttpError::Malformed)?,
            recovery::Target::Outbox(
                rss_transactional_messaging::message::MessageId::parse(&delivery.to_string())
                    .map_err(|_| HttpError::Malformed)?,
            ),
            recovery::Version::new(version.try_into().map_err(|_| HttpError::Malformed)?)
                .map_err(|_| HttpError::Malformed)?,
            recovery::Action::Redrive,
        )
        .map_err(|_| HttpError::Malformed)?;
        let timer = crate::lifecycle::RuntimeTimer;
        let cutoff = rss_request_context::Deadline::from_timeout(&timer, Duration::from_secs(6))
            .map_err(|_| HttpError::Malformed)?;
        let authorized = recovery::authorize_mutation(
            &Grant {
                backend: self,
                proof,
                audit: audit.clone(),
                command,
            },
            request,
            &timer,
            cutoff,
        )
        .await
        .map_err(|_| HttpError::Forbidden)?;
        let remaining = cutoff
            .remaining(rss_request_context::Clock::now(&timer))
            .unwrap_or(Duration::ZERO);
        audit.mark_commit_started();
        let attempt = self
            .recovery
            .mutate(
                &authorized,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining),
            )
            .await;
        attempt.fold(|receipt|{audit.mark_committed();Ok(serde_json::json!({"id":delivery,"operationId":operation,"status":"redriven","recoveryVersion":receipt.version.get()}))},|e|{audit.mark_rolled_back();Err(project(e))},|e|{audit.mark_rolled_back();Err(project(e))},|_|{audit.mark_rollback_failed();Err(HttpError::RollbackFailed)},|_|Err(HttpError::CommitUnknown),|e|{audit.mark_rolled_back();Err(project(e))})
    }
}
fn project(error: recovery::Error) -> HttpError {
    match error {
        recovery::Error::Unauthorized => HttpError::Forbidden,
        recovery::Error::NotFound => HttpError::NotFound,
        recovery::Error::Invalid => HttpError::Malformed,
        recovery::Error::Conflict | recovery::Error::Expired | recovery::Error::NotExpired => {
            HttpError::Conflict
        }
        _ => unavailable(),
    }
}
