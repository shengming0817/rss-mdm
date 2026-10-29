//! Device-scoped batch/member queries use the same directory contract and current read authority.
use super::*;
pub use rss_mdm_policy_postgres::directory::{BATCHES, MEMBERS};
use rss_mdm_query::cursor::CursorCodec;
impl Events {
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
        let (proof, principal) = match reader {
            Requester::Management(proof) => (Some(proof), None),
            Requester::Agent(principal) => (None, Some(principal)),
        };
        let target = principal.map(|p| Target {
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
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
                        if !s.execution.event_device_current_in(tx, target).await? {
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
                        let exists: bool =
                            rss_mdm_policy_postgres::directory::batch_exists_in(tx, id, device)
                                .await?;
                        if !exists {
                            return Err(Error::NotFound.into());
                        }
                    }
                    let items = rss_mdm_policy_postgres::directory::events_in(
                        tx,
                        q,
                        after.as_ref(),
                        device,
                        batch,
                        agent.map(|t| t.registration),
                        members,
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
                                        s.execution
                                            .policy_event_operation_in(tx, reference)
                                            .await?,
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
    pub operations: Vec<rss_mdm_execution_service::policy_events::EventOperationProgress>,
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
