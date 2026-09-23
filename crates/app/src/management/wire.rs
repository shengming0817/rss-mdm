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
    definition: ScopeDefinition
});
view!(ScopeReceipt {
    id: Uuid,
    revision: u64,
    task:Option<Uuid>
});
view!(PolicyRead { id: String, storage_revision: u64, revision: u64, status: String, plan: Option<String>, fresh: bool });
view!(PolicyReceipt { policy: String, request: String, storage_revision: u64, plan_id: Option<String>, plan_is_fresh: bool, task:Option<Uuid> });
view!(ResourceReceipt {
    resource: String,
    request: String,
    storage_revision: u64
});
view!(ResourceRead { id: String, revision: u64, kind: String, versions: Vec<ResourceVersion> });
view!(ResourceVersion { id: String, digest: [u8;32], state: String, variants: Vec<super::resources::Variant> });
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
view!(TaskRead {task:Uuid,kind:String,target:String,status:String,processed:u64,members:u64,plan:Option<String>,failure:Option<String>});
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Response {
    JobAccepted(JobAccepted),
    TaskRead(TaskRead),
    Asset(assets::AssetEnvelope),
    GroupRead(GroupRead),
    GroupPage(pages::GroupPage),
    ScopePage(pages::ScopePage),
    PolicyPage(pages::PolicyPage),
    GroupReceipt(GroupReceipt),
    ScopeRead(ScopeRead),
    ScopeReceipt(ScopeReceipt),
    PolicyRead(PolicyRead),
    PolicyReceipt(PolicyReceipt),
    ResourceRead(ResourceRead),
    ResourceReceipt(ResourceReceipt),
    SavedPlan(SavedPlan),
}
impl Response {
    pub fn decode(value: Value) -> std::result::Result<Self, Error> {
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::ManagementStorage))
    }
}
view!(Approval {
    approver: String,
    publisher: String,
    at: i64,
    digest: [u8; 32]
});
view!(Publication {
    id: [u8; 32],
    attempt: u64,
    outcome: String
});
view!(CandidateRing { ring: String, state: String, publication: Option<Publication>, approval: Option<Approval> });
#[derive(Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
pub(super) struct Candidate {
    pub id: String,
    pub revision: u64,
    pub content_digest: [u8; 32],
    pub disposition: String,
    pub manifest_digest: [u8; 32],
    pub source_snapshot: [u8; 32],
    pub rings: Vec<CandidateRing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<Submission>,
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
        assert!(serde_json::from_value::<super::super::publications::Change>(request).is_err());
        let value=Response::decode(serde_json::json!({"policy":"p","request":"r","storage_revision":1,"plan_id":null,"plan_is_fresh":false})).unwrap();
        let wire = serde_json::to_value(value).unwrap();
        assert_eq!(wire["storageRevision"], 1);
        assert!(wire.get("storage_revision").is_none());
        assert!(Response::decode(serde_json::json!({"invented":"untyped"})).is_err());
    }
}

// Brew declaration fields are product wire; WinGet manifest remains source-owned JSON.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Submission {
    Winget { manifest: Value },
    Brew { recipe: Box<BrewRecipe> },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrewRecipe {
    package: String,
    version: String,
    name: String,
    description: String,
    homepage: String,
    payload: BrewPayload,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum BrewPayload {
    Cask {
        artifacts: Vec<crate::software_publication::BrewArtifact>,
        install: crate::software_publication::CaskInstall,
    },
    Formula {
        source: crate::software_publication::PublicArtifact,
        executable: String,
        bottles: Vec<Bottle>,
        dependencies: Vec<crate::software_publication::BrewDependency>,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bottle {
    tag: String,
    root_url: String,
    artifact: crate::software_publication::PublicArtifact,
}
impl From<crate::software_publication::Submission> for Submission {
    fn from(value: crate::software_publication::Submission) -> Self {
        use crate::software_publication as p;
        match value {
            p::Submission::Winget { manifest } => Self::Winget { manifest },
            p::Submission::Brew { recipe: r } => Self::Brew {
                recipe: Box::new(BrewRecipe {
                    package: r.package,
                    version: r.version,
                    name: r.name,
                    description: r.description,
                    homepage: r.homepage,
                    payload: match r.payload {
                        p::BrewPayload::Cask { artifacts, install } => {
                            BrewPayload::Cask { artifacts, install }
                        }
                        p::BrewPayload::Formula {
                            source,
                            executable,
                            bottles,
                            dependencies,
                        } => BrewPayload::Formula {
                            source,
                            executable,
                            bottles: bottles
                                .into_iter()
                                .map(|b| Bottle {
                                    tag: b.tag,
                                    root_url: b.root_url,
                                    artifact: b.artifact,
                                })
                                .collect(),
                            dependencies,
                        },
                    },
                }),
            },
        }
    }
}
impl From<Submission> for crate::software_publication::Submission {
    fn from(value: Submission) -> Self {
        use crate::software_publication as p;
        match value {
            Submission::Winget { manifest } => Self::Winget { manifest },
            Submission::Brew { recipe: r } => Self::Brew {
                recipe: Box::new(p::BrewRecipe {
                    package: r.package,
                    version: r.version,
                    name: r.name,
                    description: r.description,
                    homepage: r.homepage,
                    payload: match r.payload {
                        BrewPayload::Cask { artifacts, install } => {
                            p::BrewPayload::Cask { artifacts, install }
                        }
                        BrewPayload::Formula {
                            source,
                            executable,
                            bottles,
                            dependencies,
                        } => p::BrewPayload::Formula {
                            source,
                            executable,
                            bottles: bottles
                                .into_iter()
                                .map(|b| p::BottleInput {
                                    tag: b.tag,
                                    root_url: b.root_url,
                                    artifact: b.artifact,
                                })
                                .collect(),
                            dependencies,
                        },
                    },
                }),
            },
        }
    }
}
