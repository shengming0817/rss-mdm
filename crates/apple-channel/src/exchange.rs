//! One decoded Apple request participates in the caller-owned execution transaction.
use crate::{Apple, Error, device::DevicePrincipal, execution::channels as ports, protocol};
use sqlx::PgConnection;
use std::sync::Arc;

struct Exchange {
    apple: Arc<Apple>,
    dictionary: plist::Dictionary,
    bytes: Vec<u8>,
    udid: String,
    user: String,
    command: Option<uuid::Uuid>,
    status: protocol::Status,
}
pub fn prepare(
    apple: Arc<Apple>,
    dictionary: plist::Dictionary,
    bytes: Vec<u8>,
) -> Result<Box<dyn ports::AppleExchange>, Error> {
    let message = protocol::management(&dictionary)?;
    let udid = message.udid.to_owned();
    let user = message.user.map(|id| id.to_string()).unwrap_or_default();
    let command = message.command;
    let status = message.status;
    Ok(Box::new(Exchange {
        apple,
        dictionary,
        bytes,
        udid,
        user,
        command,
        status,
    }))
}
impl ports::AppleExchange for Exchange {
    fn user_key(&self) -> &str {
        &self.user
    }
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> ports::Pending<'a, ()> {
        Box::pin(async move {
            crate::flow_store::current(c, p, &self.udid, &self.user)
                .await
                .map_err(Into::into)
        })
    }
    fn reception<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> ports::Pending<'a, ports::AppleReception> {
        Box::pin(async move {
            let Some(id) = self.command else {
                return Ok(ports::AppleReception::Idle);
            };
            if self.user.is_empty() {
                if let Some(facts) = crate::agent_collection::receive(
                    c,
                    &self.apple.protection,
                    p,
                    id,
                    self.status,
                    &self.dictionary,
                    &self.bytes,
                )
                .await
                .map_err(ports::Rejection::from)?
                {
                    return Ok(ports::AppleReception::Collection(facts));
                }
                let mut facts = Vec::new();
                if crate::collection::receive(
                    c,
                    &self.apple.protection,
                    &mut facts,
                    p,
                    id,
                    self.status,
                    &self.dictionary,
                    &self.bytes,
                )
                .await
                .map_err(ports::Rejection::from)?
                {
                    return Ok(ports::AppleReception::Collection(facts));
                }
            }
            let attempt = crate::attempt::lock(
                c,
                &self.apple.protection,
                p,
                id,
                crate::attempt::Owner::Command,
                &self.bytes,
            )
            .await
            .map_err(ports::Rejection::from)?
            .ok_or(ports::Rejection::Conflict)?;
            Ok(match attempt {
                crate::attempt::Reception::Replay => ports::AppleReception::Replay,
                crate::attempt::Reception::Ready(attempt) => {
                    ports::AppleReception::Command(Box::new(CommandAttempt {
                        attempt,
                        key: self.apple.protection.clone(),
                        status: self.status,
                        user: self.user,
                    }))
                }
            })
        })
    }
}
struct CommandAttempt {
    attempt: crate::attempt::Attempt,
    key: Arc<rss_mdm_native_protection::Protector>,
    status: protocol::Status,
    user: String,
}
impl ports::AppleAttempt for CommandAttempt {
    fn operation(&self) -> Option<uuid::Uuid> {
        self.attempt.operation
    }
    fn settle<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        eligible: bool,
        command: ports::AppleCommand,
        target: ports::AppleRegistration,
    ) -> ports::Pending<'a, rss_mdm_apple_mdm::native::evidence::Settlement> {
        Box::pin(async move {
            use rss_mdm_apple_mdm::native::{
                evidence::{self, Phase, Settlement as S},
                profiles::Verification,
                request::Request,
            };
            let phase: Phase =
                serde_json::from_value(serde_json::Value::String(self.attempt.phase.clone()))
                    .map_err(|_| {
                        ports::Rejection::from(Error::Unavailable(crate::Failure::AppleStorage))
                    })?;
            let scope = if phase.prerequisite() {
                self.user.is_empty()
            } else {
                self.user == command.target.user_key()
            };
            let accepted = eligible && scope && self.attempt.latest && self.attempt.valid;
            let profile = matches!(
                command.request,
                Request::InstallProfile { .. } | Request::RemoveProfile { .. }
            );
            let query = matches!(&command.request, Request::Command {command} if rss_mdm_apple_mdm::native::outcome::family(&command.request_type)==Ok(rss_mdm_apple_mdm::native::outcome::Family::Query));
            let fact =
                evidence::settlement(phase, self.status, self.attempt.outcome, profile, query);
            self.attempt
                .settle(c, self.status, accepted)
                .await
                .map_err(ports::Rejection::from)?;
            if !accepted {
                return Ok(S::Waiting);
            }
            if fact != S::Profile {
                return Ok(fact);
            }
            Ok(
                match crate::profiles::confirm(c, &self.key, &target, command.operation)
                    .await
                    .map_err(ports::Rejection::from)?
                {
                    Verification::Matched => S::Reported,
                    Verification::Failed => S::Rejected,
                    Verification::Unknown | Verification::Mismatched => S::Waiting,
                },
            )
        })
    }
}
