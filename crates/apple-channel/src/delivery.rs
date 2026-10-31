//! Apple owns native request transactions, response ordering and durable protocol facts.
use crate::protocol_types::Apple as _;
use crate::{Apple, Error, Failure, participants::Business, protocol_types::*};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
pub struct Delivery {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit: Arc<AuditStore>,
    pub business: Arc<dyn Business>,
    pub facts: Arc<crate::flow_store::Store>,
}
impl Delivery {
    pub async fn management(
        &self,
        apple: Arc<Apple>,
        p: &DevicePrincipal,
        exchange: Box<dyn AppleExchange>,
        audit: &RequestAudit,
    ) -> Result<Vec<u8>, Error> {
        self.run(audit, (self, apple, p, Some(exchange), audit), |ctx, tx| {
            Box::pin(async move {
                let (s, apple, p, exchange, audit) = ctx;
                let p = *p;
                s.business.prepare(tx, p, audit).await?;
                let exchange = exchange.take().ok_or(Error::Conflict)?;
                let user = exchange.user_key().to_owned();
                let principal = p.clone();
                let a = (*audit).clone();
                let business = s.business.clone();
                let reception = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(async {
                                exchange.current(c, &principal).await?;
                                exchange
                                    .reception(business.as_ref(), c, &principal, &a)
                                    .await
                            }
                            .await)
                        })
                    })
                    .await
                    .map_err(storage)??;
                if !matches!(reception, AppleReception::Replay) {
                    s.business.authenticated(tx, p).await?;
                }
                let mut collection = None;
                match reception {
                    AppleReception::Command(attempt) => {
                        let id = attempt.operation().ok_or(Error::Conflict)?;
                        let admission = s.business.command(tx, p, id).await?;
                        let version = admission.command.input_version.clone();
                        let fact = tx
                            .with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(attempt
                                        .settle(
                                            c,
                                            admission.eligible,
                                            admission.command,
                                            admission.target,
                                        )
                                        .await)
                                })
                            })
                            .await
                            .map_err(storage)??;
                        s.business.settle(tx, p, id, &version, fact, audit).await?;
                    }
                    AppleReception::Collection { facts, run } => {
                        for fact in &facts {
                            s.audit.append_in(tx, fact).await?;
                        }
                        collection = run;
                    }
                    AppleReception::Idle | AppleReception::Replay => {}
                }
                s.business.finish(tx, p, collection, audit).await?;
                let bytes = s.send(tx, apple.clone(), p, &user, audit).await?;
                s.business.settle_failures(tx, p, audit).await?;
                audit.require_final_request();
                Ok(bytes)
            })
        })
        .await
    }
    async fn send(
        &self,
        tx: &mut PgTransaction<'_>,
        apple: Arc<Apple>,
        p: &DevicePrincipal,
        user: &str,
        audit: &RequestAudit,
    ) -> Result<Vec<u8>, Error> {
        if user.is_empty() {
            let owner = apple.clone();
            let p = p.clone();
            let a = audit.clone();
            let reply = tx
                .with_connection(move |c| Box::pin(async move { Ok(owner.trust(c, &p, &a).await) }))
                .await
                .map_err(storage)??;
            for fact in &reply.facts {
                self.audit.append_in(tx, fact).await?;
            }
            if !reply.bytes.is_empty() {
                return Ok(reply.bytes);
            }
        }
        let mut after = Uuid::nil();
        loop {
            let ids = self.business.candidates(tx, p, user, after).await?;
            if ids.is_empty() {
                break;
            }
            for id in ids {
                after = id;
                let mut admission = self.business.command(tx, p, id).await?;
                if !admission.eligible || !admission.dispatch {
                    continue;
                }
                let prerequisites = admission.command.target.user_key() != user;
                if prerequisites
                    && (!user.is_empty() || admission.command.target.user_key().is_empty())
                {
                    continue;
                }
                if !prerequisites {
                    if matches!(
                        admission.command.request,
                        rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                    ) {
                        let facts = self.facts.clone();
                        let principal = p.clone();
                        let scope = admission.command.target.user_key().to_owned();
                        let ids = tx
                            .with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(facts.declaration_candidates(c, &principal, &scope).await)
                                })
                            })
                            .await
                            .map_err(storage)??;
                        admission.command.authorized_declarations = self
                            .authorized_declarations(
                                tx,
                                p,
                                admission.command.target.user_key(),
                                ids,
                            )
                            .await?;
                    }
                    match self
                        .assets(tx, &admission.command.request, &admission.command.target)
                        .await
                    {
                        Ok(assets) => admission.command.assets = assets,
                        Err(
                            Error::Malformed
                            | Error::NotFound
                            | Error::Conflict
                            | Error::Unsupported,
                        ) => {
                            self.business
                                .rejected(
                                    tx,
                                    p,
                                    id,
                                    rss_mdm_apple_mdm::native::Error::Constraint.to_string(),
                                )
                                .await?;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                let owner = apple.clone();
                let principal = p.clone();
                let dispatch = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(if prerequisites {
                                owner.prerequisites(c, &principal, &admission.command).await
                            } else {
                                owner.command(c, &principal, &admission.command).await
                            })
                        })
                    })
                    .await
                    .map_err(storage)??;
                match dispatch {
                    AppleDispatch::Ready(bytes) => return Ok(bytes),
                    AppleDispatch::Waiting => {}
                    AppleDispatch::Rejected(e) => {
                        self.business.rejected(tx, p, id, e.to_string()).await?
                    }
                }
            }
        }
        let source = self.business.clone();
        let principal = p.clone();
        let user = user.to_owned();
        let reply = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(apple
                        .collection(source.as_ref(), c, &principal, &user)
                        .await)
                })
            })
            .await
            .map_err(storage)??;
        for fact in &reply.facts {
            self.audit.append_in(tx, fact).await?;
        }
        Ok(reply.bytes)
    }
    async fn authorized_declarations(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        user: &str,
        ids: Vec<Uuid>,
    ) -> Result<Vec<Uuid>, Error> {
        let mut authorized = Vec::new();
        for admission in self.business.declarations(tx, p, user, ids).await? {
            match self
                .assets(tx, &admission.command.request, &admission.command.target)
                .await
            {
                Ok(_) => authorized.push(admission.command.operation),
                Err(Error::Malformed | Error::NotFound | Error::Conflict | Error::Unsupported) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(authorized)
    }
    pub async fn ddm(
        &self,
        p: &DevicePrincipal,
        exchange: Box<dyn AppleDdmExchange>,
        audit: &RequestAudit,
    ) -> Result<AppleDdmReply, Error> {
        self.run(audit, (self, p, Some(exchange), audit), |ctx, tx| {
            Box::pin(async move {
                let (s, p, exchange, audit) = ctx;
                let p = *p;
                s.business.prepare(tx, p, audit).await?;
                let exchange = exchange.take().ok_or(Error::Conflict)?;
                let principal = p.clone();
                let (exchange, ids) = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(async {
                                exchange.current(c, &principal).await?;
                                let ids = exchange.candidates(c, &principal).await?;
                                Ok::<_, Error>((exchange, ids))
                            }
                            .await)
                        })
                    })
                    .await
                    .map_err(storage)??;
                let authorized = s
                    .authorized_declarations(tx, p, exchange.user_key(), ids)
                    .await?;
                let principal = p.clone();
                let reply = tx
                    .with_connection(move |c| {
                        Box::pin(
                            async move { Ok(exchange.respond(c, &principal, authorized).await) },
                        )
                    })
                    .await
                    .map_err(storage)??;
                for fact in &reply.facts {
                    s.audit.append_in(tx, fact).await?;
                }
                for fact in &reply.synchronized {
                    s.business.synchronized(tx, p, fact).await?;
                }
                audit.require_final_request();
                Ok(reply)
            })
        })
        .await
    }
    pub async fn asset(
        &self,
        p: &DevicePrincipal,
        operation: Uuid,
        reader: Box<dyn AppleAssetRead>,
        audit: &RequestAudit,
    ) -> Result<
        (
            rss_mdm_apple_mdm::native::ddm::AssetBinding,
            rss_mdm_content_service::Verified,
        ),
        Error,
    > {
        self.run(
            audit,
            (self, p, operation, Some(reader), audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, id, reader, audit) = ctx;
                    let (request, target) = s.business.asset_authority(tx, p, *id).await?;
                    let current = s.assets(tx, &request, &target).await?;
                    let principal = (*p).clone();
                    let reader = reader.take().ok_or(Error::Conflict)?;
                    let selected = tx
                        .with_connection(move |c| {
                            Box::pin(async move { Ok(reader.binding(c, &principal).await) })
                        })
                        .await
                        .map_err(storage)??
                        .ok_or(Error::NotFound)?;
                    let expected = serde_json::to_vec(&selected).map_err(|_| Error::Malformed)?;
                    for binding in current {
                        if serde_json::to_vec(&binding).map_err(|_| Error::Malformed)? == expected {
                            let verified =
                                s.business.artifact(tx, &selected.selection).await?.verified;
                            audit.require_final_request();
                            return Ok((selected, verified));
                        }
                    }
                    Err(Error::Conflict)
                })
            },
        )
        .await
    }
    pub(crate) async fn run<C: Send, R: Send, F>(
        &self,
        audit: &RequestAudit,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> Pending<'a, R> + Send,
    {
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::from_secs(6),
                ),
                (context, Some(operation), &failure, &self.audit, audit),
                |(context, operation, failure, store, audit), tx| {
                    Box::pin(async move {
                        store
                            .bind_in(tx)
                            .await
                            .map_err(|e| rejection(e.into(), failure))?;
                        match operation.take().expect("one request")(context, tx).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => Err(rejection(e, failure)),
                        }
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| {
                audit.mark_rolled_back();
                Err(failure
                    .into_inner()
                    .expect("request rejection")
                    .unwrap_or(Error::Unavailable(Failure::Database)))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )
    }
    async fn assets(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &rss_mdm_apple_mdm::native::request::Request,
        target: &Target,
    ) -> Result<Vec<rss_mdm_apple_mdm::native::ddm::AssetBinding>, Error> {
        use rss_mdm_apple_mdm::native::{ddm::AssetBinding, request::Request};
        let Request::Declarations {
            assets,
            declarations,
        } = request
        else {
            return Ok(Vec::new());
        };
        if assets.len() > 4096 {
            return Err(Error::Malformed);
        }
        let mut bindings = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for asset in assets {
            if !ids.insert(&asset.identifier) {
                return Err(Error::Malformed);
            }
            let supplied = self.business.artifact(tx, asset).await?;
            let artifact = supplied.artifact;
            let verified = supplied.verified;
            if artifact.length() == 0 || artifact.length() > 16 * 1024 * 1024 {
                return Err(Error::Malformed);
            }
            let legacy=declarations.iter().any(|d|d.declaration_type=="com.apple.configuration.legacy" && (d.identifier==asset.identifier || d.payload.0.get("ProfileAssetReference").is_some_and(|v|matches!(v,rss_mdm_apple_mdm::native::input::FieldValue::String(id) if id==&asset.identifier))));
            let profile = if legacy {
                use futures::TryStreamExt;
                let chunks = verified
                    .stream(0, artifact.length())
                    .await
                    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                let bytes: Vec<u8> = chunks.into_iter().flat_map(|v| v.to_vec()).collect();
                let channel = if target.user_key().is_empty() {
                    rss_mdm_apple_mdm::applicability::Channel::Device
                } else {
                    rss_mdm_apple_mdm::applicability::Channel::User
                };
                Some(
                    rss_mdm_apple_mdm::native::profiles::from_native(
                        &bytes,
                        &asset.profile_schemas,
                        channel,
                    )
                    .map_err(|_| Error::Malformed)?,
                )
            } else {
                if !asset.profile_schemas.is_empty() {
                    return Err(Error::Malformed);
                }
                None
            };
            let apple_silicon = supplied.apple_silicon;
            bindings.push(AssetBinding {
                selection: asset.clone(),
                reference: artifact.reference().as_str().into(),
                length: artifact.length(),
                sha256: artifact.digest().bytes(),
                apple_silicon,
                profile,
            });
        }
        Ok(bindings)
    }
}
fn rejection(e: Error, failure: &Mutex<Option<Error>>) -> PgError {
    *failure.lock().expect("request rejection") = Some(e);
    sqlx::Error::Protocol("Apple request rejected".into()).into()
}
fn storage(e: PgError) -> Error {
    e.into()
}
