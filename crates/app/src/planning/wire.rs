//! Product HTTP projections; storage/core serialization is not the wire contract.
//! ref: serde_derive 1.0.228 src/internals/case.rs
use super::*;
use serde::{Deserialize, Serialize};
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub(super) struct $name { $(pub $field: $ty),* }
    };
}
view!(Group { id: Uuid, kind: rss_mdm_group_postgres::GroupKind, name: String, description: String, revision: i64, member_version: i64, member_count: usize, rule_version: Option<String>, deleted: bool });
view!(GroupRead { group: Group, criteria: Option<Criteria>, member_set: Option<Uuid> });
view!(GroupReceipt {
    operation: Uuid,
    group: Group,
    added: usize,
    removed: usize,
    task: Option<Uuid>
});
view!(ScopeRead {
    id: Uuid,
    revision: u64,
    definition: ScopeDefinition,
    resolution:Option<Uuid>,
    resolution_revision:u64
});
view!(ScopeReceipt {
    id: Uuid,
    revision: u64,
    task:Option<Uuid>
});
view!(PolicyRead { id: String, storage_revision: u64, revision: u64, status: String, plan: Option<String>, fresh: bool });
view!(PolicyReceipt { policy: String, request: String, storage_revision: u64, plan_id: Option<String>, plan_is_fresh: bool, task:Option<Uuid> });
view!(SavedPlan {
    receipt: PolicyReceipt,
    preview: Uuid,
    plan: Option<String>,
    dispatch:String
});
view!(JobAccepted {
    task: Uuid,
    kind: String,
    target: String,
    status_url: String
});
view!(TaskRead {task:Uuid,kind:String,target:String,status:String,processed:u64,members:u64,plan:Option<String>,failure:Option<String>,failure_detail:Option<crate::planning::error::PlanFailure>,execution:Option<PlanExecutionAdmission>,policy_revision:Option<u64>});
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Response {
    JobAccepted(JobAccepted),
    TaskRead(Box<TaskRead>),
    GroupRead(GroupRead),
    GroupPage(pages::GroupPage),
    ScopePage(pages::ScopePage),
    PolicyPage(pages::PolicyPage),
    GroupReceipt(GroupReceipt),
    ScopeRead(ScopeRead),
    ScopeReceipt(ScopeReceipt),
    PolicyRead(PolicyRead),
    PolicyReceipt(PolicyReceipt),
    SavedPlan(SavedPlan),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::PlanningStorage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_fields_have_one_spelling_and_responses_are_typed() {
        let id = Uuid::new_v4();
        let valid =
            serde_json::json!({"operationId":id,"expectedRevision":1,"input":{"preview":id}});
        assert!(serde_json::from_value::<Operation<SavePlan>>(valid.clone()).is_ok());
        let mut old = valid;
        old["operation_id"] = old["operationId"].take();
        assert!(serde_json::from_value::<Operation<SavePlan>>(old).is_err());
        let request =
            serde_json::json!({"action":"approve","ring":"test","publisher_subject":"operator"});
        assert!(
            serde_json::from_value::<crate::software_publication::http::Change>(request).is_err()
        );
        let value=Response::decode(serde_json::json!({"policy":"p","request":"r","storage_revision":1,"plan_id":null,"plan_is_fresh":false})).unwrap();
        let wire = serde_json::to_value(value).unwrap();
        assert_eq!(wire["storageRevision"], 1);
        assert!(wire.get("storage_revision").is_none());
        assert!(Response::decode(serde_json::json!({"invented":"untyped"})).is_err());
    }
}
