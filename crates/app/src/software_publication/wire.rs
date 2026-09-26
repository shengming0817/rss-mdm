use serde::{Deserialize, Serialize};
use serde_json::Value;
macro_rules! view {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(rename_all(serialize = "camelCase"), deny_unknown_fields)]
        pub(crate) struct $name { $(pub $field: $ty),* }
    };
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
pub(crate) struct Candidate {
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

// Brew declaration fields are product wire; WinGet manifest remains source-owned JSON.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Submission {
    Winget { manifest: Value },
    Brew { recipe: Box<BrewRecipe> },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BrewRecipe {
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
