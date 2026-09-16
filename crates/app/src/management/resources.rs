use super::*;
use rss_mdm_resource as r;
use rss_mdm_resource_postgres as pg;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Software,
    Script,
    Configuration,
}
impl Kind {
    fn core(&self) -> r::Kind {
        match self {
            Self::Software => r::Kind::Software,
            Self::Script => r::Kind::Script,
            Self::Configuration => r::Kind::Configuration,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Windows,
    Macos,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    reference: String,
    length: u64,
    sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Declaration {
    Software {
        source: String,
        package: String,
        version: String,
        artifact: Artifact,
        install: String,
        detect: String,
        uninstall: Option<String>,
    },
    Script {
        artifact: Artifact,
        interpreter: String,
        detect: String,
    },
    Configuration {
        artifact: Artifact,
        schema: String,
        apply: String,
        detect: String,
        remove: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Variant {
    platform: Platform,
    architecture: Architecture,
    key: String,
    declaration: Declaration,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    Create {
        kind: Kind,
    },
    Version {
        version: String,
        kind: Kind,
        variants: Vec<Variant>,
    },
    Activate {
        version: String,
    },
    Deprecate {
        version: String,
    },
    Archive {
        version: String,
    },
}
fn id(s: &str) -> Result<r::Id> {
    input(r::Id::new(s))
}
fn artifact(a: &Artifact) -> Result<r::Artifact> {
    input(r::Artifact::new(
        id(&a.reference)?,
        a.length,
        r::Digest::from_bytes(a.sha256),
    ))
}
fn variant(v: &Variant) -> Result<r::Variant> {
    let declaration = match &v.declaration {
        Declaration::Software {
            source,
            package,
            version,
            artifact: a,
            install,
            detect,
            uninstall,
        } => r::Declaration::Software {
            package: r::Package::new(id(source)?, id(package)?, id(version)?),
            artifact: artifact(a)?,
            install: id(install)?,
            detect: id(detect)?,
            uninstall: uninstall.as_ref().map(|s| id(s)).transpose()?,
        },
        Declaration::Script {
            artifact: a,
            interpreter,
            detect,
        } => r::Declaration::Script {
            artifact: artifact(a)?,
            interpreter: id(interpreter)?,
            detect: id(detect)?,
        },
        Declaration::Configuration {
            artifact: a,
            schema,
            apply,
            detect,
            remove,
        } => r::Declaration::Configuration {
            artifact: artifact(a)?,
            schema: id(schema)?,
            apply: id(apply)?,
            detect: id(detect)?,
            remove: remove.as_ref().map(|s| id(s)).transpose()?,
        },
    };
    Ok(r::Variant::new(
        match v.platform {
            Platform::Windows => r::Platform::Windows,
            Platform::Macos => r::Platform::MacOS,
        },
        match v.architecture {
            Architecture::X86_64 => r::Architecture::X86_64,
            Architecture::Aarch64 => r::Architecture::Aarch64,
        },
        id(&v.key)?,
        declaration,
    ))
}
impl Management {
    pub(super) async fn resource_change(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        op: &Operation<Change>,
        at: Timepoint,
    ) -> Result<Value> {
        let rid = id(resource)?;
        let command = match &op.input {
            Change::Create { kind } => pg::Command::Create(kind.core()),
            Change::Version {
                version,
                kind,
                variants,
            } => pg::Command::Insert(input(r::Version::new(
                self.tenant,
                rid.clone(),
                id(version)?,
                kind.core(),
                variants.iter().map(variant).collect::<Result<_>>()?,
            ))?),
            Change::Activate { version } => pg::Command::Activate(id(version)?),
            Change::Deprecate { version } => pg::Command::Deprecate(id(version)?),
            Change::Archive { version } => {
                checked(
                    self.resources
                        .lock_version_in(tx, &rid, &id(version)?)
                        .await?,
                )?;
                let tenant = self.tenant.to_string();
                let resource = resource.to_owned();
                let version_copy = version.clone();
                let references=tx.with_connection(move |c|Box::pin(async move {
     sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM mdm_management.resource_references WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3) + (SELECT count(*) FROM mdm_software_composition.subjects WHERE tenant_id=$1::uuid AND resource=$2 AND version=$3)")
      .bind(tenant).bind(resource).bind(version_copy).fetch_one(c).await
    })).await?;
                pg::Command::Archive {
                    version: id(version)?,
                    references: references as u64,
                }
            }
        };
        json(&checked(
            self.resources
                .execute_in(
                    tx,
                    &pg::Request {
                        id: id(&op.operation_id.to_string())?,
                        resource: rid,
                        expected_storage_revision: op.expected_revision,
                        as_of: at,
                        command,
                    },
                )
                .await?,
        )?)
    }
    pub(super) async fn resource_read(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
    ) -> Result<Value> {
        let stored =
            checked(self.resources.get_in(tx, &id(resource)?).await?)?.ok_or(Error::NotFound)?;
        let snapshot = stored.resource.snapshot();
        Ok(
            json!({"id":resource,"revision":stored.storage_revision,"kind":format!("{:?}",snapshot.kind),"versions":snapshot.versions.iter().map(|v|json!({"id":v.version.label().as_str(),"digest":v.version.digest().bytes(),"state":format!("{:?}",v.state),"variants":v.version.variants().iter().map(variant_view).collect::<Vec<_>>()})).collect::<Vec<_>>() }),
        )
    }
}

fn artifact_view(a: &r::Artifact) -> Artifact {
    Artifact {
        reference: a.reference().as_str().into(),
        length: a.length(),
        sha256: a.digest().bytes(),
    }
}
fn variant_view(v: &r::Variant) -> Variant {
    let text = |id: &r::Id| id.as_str().to_owned();
    let declaration = match v.declaration() {
        r::Declaration::Software {
            package,
            artifact,
            install,
            detect,
            uninstall,
        } => Declaration::Software {
            source: text(package.source()),
            package: text(package.package()),
            version: text(package.version()),
            artifact: artifact_view(artifact),
            install: text(install),
            detect: text(detect),
            uninstall: uninstall.as_ref().map(text),
        },
        r::Declaration::Script {
            artifact,
            interpreter,
            detect,
        } => Declaration::Script {
            artifact: artifact_view(artifact),
            interpreter: text(interpreter),
            detect: text(detect),
        },
        r::Declaration::Configuration {
            artifact,
            schema,
            apply,
            detect,
            remove,
        } => Declaration::Configuration {
            artifact: artifact_view(artifact),
            schema: text(schema),
            apply: text(apply),
            detect: text(detect),
            remove: remove.as_ref().map(text),
        },
    };
    Variant {
        platform: match v.platform() {
            r::Platform::Windows => Platform::Windows,
            r::Platform::MacOS => Platform::Macos,
        },
        architecture: match v.architecture() {
            r::Architecture::X86_64 => Architecture::X86_64,
            r::Architecture::Aarch64 => Architecture::Aarch64,
        },
        key: text(v.key()),
        declaration,
    }
}
