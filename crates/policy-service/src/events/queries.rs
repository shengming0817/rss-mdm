//! Device-scoped batch/member queries use the same directory contract and current read authority.
use super::*;
use rss_mdm_query::directory::Schema;
pub static BATCHES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Batch>("policy_event_batches", &["id"], 64, 1000, &[rss_mdm_query::directory::Exclusion{path:"request.executionContext.sourceCredentials",reason:"Each credential pairs its source and identity; this directory does not define a same-credential selector"}])
        .expect("Public event batch model")
});
pub static MEMBERS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Member>("policy_event_members", &["id"],64,1000,&[
    rss_mdm_query::directory::Exclusion { path:"decision.operations", reason:"Operation references are object arrays requiring kind and identity to match the same element" },
    rss_mdm_query::directory::Exclusion { path:"operations", reason:"Per-operation live progress has heterogeneous owner-specific evidence; inspect each original operation" },
]).expect("Public event member model")
});
use rss_mdm_query::cursor::CursorCodec;
impl Events {
    pub async fn member_receipt(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        crate::transaction::inspect(
            &self.application.runtime,
            self.application.tenant,
            (self, p, device),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, device) = *ctx;
                    crate::action_admission::current(tx, p).await?.require(
                        p,
                        Permission::OperationRead,
                        Some(device),
                    )?;
                    let row = rss_mdm_policy_postgres::events::member_operation_in(
                        s.profile(),
                        tx,
                        id,
                        device.into(),
                    )
                    .await?;
                    p.check_live()?;
                    Ok(row.map(|(policy, revision, state)| {
                        let mut value =
                            rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                        value.object = Some(policy.to_string());
                        value.revision = Some(revision);
                        value.state = Some(state);
                        value
                    }))
                })
            },
        )
        .await
    }
    /// Resolve the original caller namespace, without replaying event dispatch.
    pub async fn operation_receipt(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        let caller = Caller::Management { actor: p.actor() }.key()?;
        crate::transaction::inspect(
            &self.application.runtime,
            self.application.tenant,
            (self, p, device, caller),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, device, caller) = ctx;
                    crate::action_admission::current(tx, p).await?.require(
                        p,
                        Permission::OperationRead,
                        Some(device),
                    )?;
                    let row = rss_mdm_policy_postgres::events::operation_in(
                        s.profile(),
                        tx,
                        caller.clone(),
                        id,
                        device.to_string(),
                    )
                    .await?;
                    p.check_live()?;
                    Ok(row.map(|(batch, at)| {
                        let mut value =
                            rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                        value.object = Some(device.to_string());
                        value.recorded_at = Some(at);
                        value.accepted = Some(true);
                        value.executions.push(batch);
                        value
                    }))
                })
            },
        )
        .await
    }
    pub async fn read_management(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        self.read(
            Requester::Management(proof),
            device,
            batch,
            members,
            query,
            audit,
        )
        .await
    }
    pub async fn read_agent(
        &self,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        if p.tenant() != self.application.tenant {
            return Err(Error::Forbidden);
        }
        self.read(
            Requester::Agent(p),
            p.device(),
            batch,
            members,
            query,
            audit,
        )
        .await
    }
    async fn read(
        &self,
        reader: Requester<'_>,
        device: &str,
        batch: Option<Uuid>,
        members: bool,
        query: &rss_mdm_query::directory::Query,
        audit: &RequestAudit,
    ) -> std::result::Result<ReadResult, Error> {
        let profile = self.profile();

        let (proof, principal) = match reader {
            Requester::Management(proof) => (Some(proof), None),
            Requester::Agent(principal) => (None, Some(principal)),
        };
        let target = principal.map(|p| Target {
            device: p.device().into(),
        });
        let agent = target.as_ref();
        let schema = if members { &MEMBERS } else { &BATCHES };
        query.require_schema(schema).map_err(crate::query_error)?;
        audit.set_action(
            "policy_event_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let p = &self.application;
        crate::transaction::inspect(
            &self.application.runtime,
            p.tenant,
            (
                self, proof, principal, agent, device, batch, members, &query,
            ),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, principal, agent, device, batch, members, q) = *ctx;
                    if let Some(principal) = principal {
                        s.execution
                            .verify_event_device_in(tx, principal, None)
                            .await?;
                    }
                    let identity = if let Some(proof) = proof {
                        let snapshot = crate::action_admission::current(tx, proof).await?;
                        snapshot.require(proof, Permission::OperationRead, Some(device))?;
                        json!(snapshot.query_binding(proof)?)
                    } else {
                        let target = agent.ok_or(Error::Forbidden)?;
                        if !event_device_current_in(profile, tx, target).await? {
                            return Err(Error::Forbidden.into());
                        }
                        json!(target)
                    };
                    let binding = q
                        .binding(&(
                            s.application.tenant.to_string(),
                            identity,
                            device,
                            batch,
                            members,
                        ))
                        .map_err(crate::query_error)?;
                    let codec = CursorCodec::from_key(s.application.cursor_key.clone());
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    if let Some(id) = batch {
                        let device = device.to_owned();
                        let exists: bool = rss_mdm_policy_postgres::directory::batch_exists_in(
                            profile, tx, id, device,
                        )
                        .await?;
                        if !exists {
                            return Err(Error::NotFound.into());
                        }
                    }
                    let items = rss_mdm_policy_postgres::directory::events_in(
                        profile,
                        tx,
                        q,
                        after.as_ref(),
                        rss_mdm_policy_postgres::directory::EventTarget { device, batch },
                        members,
                        if members {
                            &MEMBER_BINDINGS
                        } else {
                            &BATCH_BINDINGS
                        },
                    )
                    .await?;
                    let result = if members {
                        let mut items: Vec<Member> = stored(
                            items
                                .into_iter()
                                .map(serde_json::from_value)
                                .collect::<std::result::Result<_, _>>(),
                        )?;
                        for item in &mut items {
                            if let wire::PolicyEventDecision::Accepted { operations: refs } =
                                &item.decision
                            {
                                for reference in refs {
                                    item.operations.push(
                                        s.progress.policy_event_operation_in(tx, reference).await?,
                                    );
                                }
                            }
                        }
                        ReadResult::Members(
                            q.page_typed(items, &codec, &binding)
                                .map_err(crate::query_error)?,
                        )
                    } else {
                        let items: Vec<Batch> = stored(
                            items
                                .into_iter()
                                .map(serde_json::from_value)
                                .collect::<std::result::Result<_, _>>(),
                        )?;
                        if batch.is_some() {
                            ReadResult::Batch(Box::new(
                                items.into_iter().next().ok_or(Error::NotFound)?,
                            ))
                        } else {
                            ReadResult::Batches(
                                q.page_typed(items, &codec, &binding)
                                    .map_err(crate::query_error)?,
                            )
                        }
                    };
                    if let Some(proof) = proof {
                        proof.check_live()?;
                    }
                    Ok(result)
                })
            },
        )
        .await
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub event: wire::PolicyEventName,
    pub created_at: i64,
    pub deadline: i64,
    pub request: wire::PolicyEventRequest,
    pub processing_failure: Option<String>,
    pub members: u64,
    pub admission: std::collections::BTreeMap<DecisionState, u64>,
}
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    Pending,
    Accepted,
    NoChange,
    Rejected,
    Expired,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub revision: i64,
    pub state: DecisionState,
    pub decision: wire::PolicyEventDecision,
    #[serde(skip_deserializing)]
    pub operations: Vec<super::participants::EventOperationProgress>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ReadResult {
    Batch(Box<Batch>),
    Batches(rss_mdm_query::Page<rss_mdm_query::directory::Projection<Batch>>),
    Members(rss_mdm_query::Page<rss_mdm_query::directory::Projection<Member>>),
}

impl ReadResult {
    pub fn batch(self) -> std::result::Result<Batch, Error> {
        match self {
            Self::Batch(value) => Ok(*value),
            _ => Err(Error::Unavailable(Failure::PolicyStorage)),
        }
    }
    pub fn batches(
        self,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Batch>>, Error>
    {
        match self {
            Self::Batches(value) => Ok(value),
            _ => Err(Error::Unavailable(Failure::PolicyStorage)),
        }
    }
    pub fn members(
        self,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Member>>, Error>
    {
        match self {
            Self::Members(value) => Ok(value),
            _ => Err(Error::Unavailable(Failure::PolicyStorage)),
        }
    }
}

pub static BATCH_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &BATCHES,
            &[
                rss_mdm_query_postgres::Source::json("id", "row#>'{id}'"),
                rss_mdm_query_postgres::Source::json("operationId", "row#>'{operationId}'"),
                rss_mdm_query_postgres::Source::json("event", "row#>'{event}'"),
                rss_mdm_query_postgres::Source::json("createdAt", "row#>'{createdAt}'"),
                rss_mdm_query_postgres::Source::json("deadline", "row#>'{deadline}'"),
                rss_mdm_query_postgres::Source::json("request", "row#>'{request}'"),
                rss_mdm_query_postgres::Source::json(
                    "processingFailure",
                    "row#>'{processingFailure}'",
                ),
                rss_mdm_query_postgres::Source::json("members", "row#>'{members}'"),
                rss_mdm_query_postgres::Source::json("admission", "row#>'{admission}'"),
            ],
        )
        .expect("Complete public model storage binding")
    });

pub static MEMBER_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &MEMBERS,
            &[
                rss_mdm_query_postgres::Source::json("id", "row#>'{id}'"),
                rss_mdm_query_postgres::Source::json("policyId", "row#>'{policyId}'"),
                rss_mdm_query_postgres::Source::json("versionId", "row#>'{versionId}'"),
                rss_mdm_query_postgres::Source::json("revision", "row#>'{revision}'"),
                rss_mdm_query_postgres::Source::json("state", "row#>'{state}'"),
                rss_mdm_query_postgres::Source::json("decision", "row#>'{decision}'"),
            ],
        )
        .expect("Complete public model storage binding")
    });
