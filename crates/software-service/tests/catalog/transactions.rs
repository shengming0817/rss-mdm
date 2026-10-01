use super::*;
use crate::materials::{self, pg};
use anyhow::Context;
use catalog::{Catalog, Operation, SourceChange, VerifiedContent, VersionChange};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_resource as r;
use rss_mdm_resource_postgres as resource;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction, PgTransactionFault};
use serde_json::json;
use std::{future::Future, pin::Pin, sync::Arc};
use uuid::Uuid;

async fn transaction<C: Send, R: Send, F>(runtime: &PgRuntime, context: C, work: F) -> Result<R>
where
    F: for<'c> FnOnce(
            &'c mut C,
            &'c mut PgTransaction<'_>,
        ) -> Pin<Box<dyn Future<Output = catalog::Result<R>> + Send + 'c>>
        + Send,
{
    let attempt = runtime
        .local_tx_with_context(
            pg::tenant(),
            pg::deadline(),
            (context, Some(work)),
            |state, tx| {
                Box::pin(async move {
                    let (context, work) = state;
                    work.take().expect("one callback")(context, tx)
                        .await
                        .map_err(|error| {
                            eprintln!("catalog callback failed: {error:?}");
                            sqlx::Error::Protocol("catalog fixture rejected".into()).into()
                        })
                })
            },
        )
        .await;
    Ok(attempt.fold(Ok, Err, Err, Err, Err, Err)?)
}
struct Fixture {
    runtime: Arc<PgRuntime>,
    catalog: Catalog,
}
impl Fixture {
    async fn open() -> Self {
        let runtime = pg::runtime_at(None, "mdm_flow_runtime").await;
        let audit = pg::audit_store_for("mdm_flow_runtime").await;
        let catalog = Catalog::new(
            runtime.clone(),
            pg::tenant(),
            materials::host(runtime.clone(), audit).audit,
        );
        Self { runtime, catalog }
    }
    async fn source(&self, operation: &Operation<SourceChange>, rollback: bool) -> Result<Value> {
        let audit = RequestAudit::new(pg::tenant().to_string(), "software_source_write");
        audit.set_principal("operator", materials::INSTANCE);
        let result = transaction(
            &self.runtime,
            (&self.catalog, &audit, operation),
            |context, tx| {
                Box::pin(async move {
                    let (catalog, audit, operation) = *context;
                    let result = catalog
                        .source_in(tx, audit, pg::case::name("private-fixture"), "1", operation)
                        .await?;
                    if rollback {
                        return Err(catalog::Error::Input);
                    }
                    Ok(result)
                })
            },
        )
        .await;
        audit.finalize(None);
        result
    }
    async fn source_allowed(&self, snapshot: r::SoftwareSource) -> Result<()> {
        transaction(&self.runtime, (&self.catalog, snapshot), |context, tx| {
            Box::pin(async move {
                context
                    .0
                    .source_admitted_in(tx, &context.1)
                    .await
                    .map(|_| ())
            })
        })
        .await
    }
    async fn change(
        &self,
        version: &r::Version,
        operation: &Operation<VersionChange>,
        digest: [u8; 32],
    ) -> Result<Value> {
        let audit = RequestAudit::new(pg::tenant().to_string(), "software_version_write");
        audit.set_principal("operator", materials::INSTANCE);
        let content = Content(digest);
        let result = transaction(
            &self.runtime,
            (&self.catalog, &audit, version, operation, &content),
            |context, tx| {
                Box::pin(async move {
                    let (catalog, audit, version, operation, content) = *context;
                    catalog
                        .version_change_in(
                            tx,
                            audit,
                            version.resource().as_str(),
                            version.label().as_str(),
                            operation,
                            Some(content),
                        )
                        .await
                })
            },
        )
        .await;
        audit.finalize(None);
        result
    }
    async fn resolve(&self, version: &r::Version) -> Result<()> {
        transaction(&self.runtime, (&self.catalog, version), |context, tx| {
            Box::pin(async move {
                context
                    .0
                    .resolve_admitted_in(
                        tx,
                        context.1.resource().as_str(),
                        context.1.label().as_str(),
                        r::Platform::Windows,
                        r::Architecture::X86_64,
                        &r::Id::new("default").unwrap(),
                    )
                    .await
                    .map(|_| ())
            })
        })
        .await
    }
    async fn version(&self, mut definition: Value) -> Result<r::Version> {
        let id = r::Id::new(Uuid::new_v4().to_string())?;
        definition["package"] = json!(format!("Private.{}", id.as_str()));
        let version = r::Version::new(
            pg::tenant(),
            id.clone(),
            r::Id::new("v1")?,
            r::Kind::Software,
            vec![r::Variant::new(
                r::Platform::Windows,
                r::Architecture::X86_64,
                r::Id::new("default")?,
                r::Declaration::Software {
                    definition: serde_json::from_value(definition)?,
                },
            )],
        )?;
        let store =
            resource::ResourceStore::new(self.runtime.clone(), pg::tenant(), pg::deadline())
                .await?;
        for (revision, command) in [
            (0, resource::Command::Create(r::Kind::Software)),
            (1, resource::Command::Insert(version.clone())),
        ] {
            store
                .execute(
                    &resource::Request {
                        id: r::Id::new(Uuid::new_v4().to_string())?,
                        resource: id.clone(),
                        expected_storage_revision: revision,
                        as_of: pg::at(1),
                        command,
                    },
                    pg::deadline(),
                )
                .await?;
        }
        Ok(version)
    }
}
struct Content([u8; 32]);
impl VerifiedContent for Content {
    fn resource_digest(&self) -> [u8; 32] {
        self.0
    }
}
fn register() -> Operation<SourceChange> {
    serde_json::from_value(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"register","definition":{
        "id":pg::case::name("private-fixture"),"revision":"1","protocol":{"kind":"private"}
    }}})).unwrap()
}
fn approve(revision: u64) -> Operation<VersionChange> {
    Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: revision,
        input: VersionChange::Approve {
            evidence: vec!["review".into()],
        },
    }
}
async fn approved_source(fixture: &Fixture) -> Result<Value> {
    let registered = fixture.source(&register(), false).await?;
    fixture
        .source(
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                input: SourceChange::Approve {
                    evidence: vec!["review".into()],
                },
            },
            false,
        )
        .await?;
    Ok(registered["snapshot"].clone())
}

#[tokio::test]
#[ignore = "MODULE=software.catalog: borrowed transaction, atomic audit and source ACK recovery"]
async fn source_receipts_follow_the_borrowed_transaction() -> Result<()> {
    let fixture = Fixture::open().await;
    let operation = register();
    let tenant = pg::tenant();
    let audit_sql = format!(
        "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{tenant}' ORDER BY position"
    );
    let audit_before = pg::sql(&audit_sql);
    ensure!(fixture.source(&operation, true).await.is_err());
    ensure!(
        pg::sql(&format!(
            "SELECT count(*) FROM mdm_software.sources WHERE tenant_id='{tenant}' AND id='{}' AND revision='1'",
            pg::case::name("private-fixture")
        )) == "0"
    );
    ensure!(
        pg::sql(&format!(
            "SELECT count(*) FROM mdm_software.operations WHERE tenant_id='{tenant}' AND id='{}'",
            operation.operation_id
        )) == "0"
    );
    ensure!(pg::sql(&audit_sql) == audit_before);
    fixture
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    ensure!(fixture.source(&operation, false).await.is_err());
    let original: Value = serde_json::from_str(&pg::sql(&format!(
        "SELECT response FROM mdm_software.operations WHERE tenant_id='{tenant}' AND id='{}'",
        operation.operation_id
    )))?;
    let first_audit = pg::sql(&audit_sql);
    ensure!(first_audit.lines().count() == audit_before.lines().count() + 1);
    let replayed = fixture.source(&operation, false).await?;
    ensure!(replayed == original);
    ensure!(pg::sql(&audit_sql) == first_audit);
    let snapshot: r::SoftwareSource = serde_json::from_value(replayed["snapshot"].clone())?;
    ensure!(fixture.source_allowed(snapshot.clone()).await.is_err());
    let approval = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        input: SourceChange::Approve {
            evidence: vec!["review".into()],
        },
    };
    let approved = fixture.source(&approval, false).await?;
    fixture.source_allowed(snapshot.clone()).await?;
    let mut wrong = snapshot.clone();
    wrong.sha256 = [0; 32];
    ensure!(fixture.source_allowed(wrong).await.is_err());
    fixture
        .source(
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 2,
                input: SourceChange::Withdraw {
                    evidence: vec!["withdrawal".into()],
                },
            },
            false,
        )
        .await?;
    ensure!(fixture.source(&approval, false).await? == approved);
    ensure!(fixture.source_allowed(snapshot).await.is_err());
    fixture.runtime.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=software.catalog: exact content and dependency approvals, withdrawal recheck"]
async fn dependency_admission_uses_exact_current_approval() -> Result<()> {
    let fixture = Fixture::open().await;
    let source = approved_source(&fixture).await?;
    let definition = materials::private_definition(source, b"abc");
    let dependency = fixture
        .version(definition.clone())
        .await
        .context("dependency version")?;
    let mut dependent_definition = definition.clone();
    dependent_definition["dependencies"] = json!([{"resource":dependency.resource().as_str(),"version":"v1","sha256":dependency.digest().bytes()}]);
    let dependent = fixture
        .version(dependent_definition.clone())
        .await
        .context("dependent version")?;
    let approval = approve(0);
    ensure!(
        fixture
            .change(&dependent, &approval, dependent.digest().bytes())
            .await
            .is_err()
    );
    ensure!(
        pg::sql(&format!(
            "SELECT count(*) FROM mdm_software.operations WHERE tenant_id='{}' AND id='{}'",
            pg::tenant(),
            approval.operation_id
        )) == "0"
    );
    ensure!(
        pg::sql(&format!(
            "SELECT count(*) FROM mdm_software.approvals WHERE tenant_id='{}' AND resource='{}'",
            pg::tenant(),
            dependent.resource().as_str()
        )) == "0"
    );
    ensure!(
        fixture
            .change(&dependency, &approve(0), [0; 32])
            .await
            .is_err()
    );
    fixture
        .change(&dependency, &approve(0), dependency.digest().bytes())
        .await
        .context("dependency approval")?;
    fixture
        .change(&dependent, &approval, dependent.digest().bytes())
        .await
        .context("dependent approval")?;
    fixture
        .resolve(&dependent)
        .await
        .context("resolve approved dependency")?;
    let mut wrong = dependent_definition.clone();
    wrong["dependencies"][0]["sha256"] = json!(vec![0; 32]);
    let wrong = fixture.version(wrong).await?;
    ensure!(
        fixture
            .change(&wrong, &approve(0), wrong.digest().bytes())
            .await
            .is_err()
    );
    let withdrawal = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        input: VersionChange::Withdraw {
            evidence: vec!["withdrawn".into()],
        },
    };
    fixture
        .change(&dependency, &withdrawal, dependency.digest().bytes())
        .await?;
    ensure!(fixture.resolve(&dependent).await.is_err());
    let after = fixture.version(dependent_definition).await?;
    ensure!(
        fixture
            .change(&after, &approve(0), after.digest().bytes())
            .await
            .is_err()
    );
    fixture.runtime.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=software.catalog: source conversion + Resource atomicity and original identity recovery"]
async fn import_receipt_survives_unknown_commit_and_source_withdrawal() -> Result<()> {
    use rss_mdm_software_service::imports::{self, ImportRequest};
    let fixture = Fixture::open().await;
    let mut source = crate::imported_fixture::source();
    source.id = pg::case::name("private-fixture").to_owned();
    fixture
        .source(
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                input: SourceChange::Register {
                    definition: source.clone(),
                },
            },
            false,
        )
        .await?;
    fixture
        .source(
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                input: SourceChange::Approve {
                    evidence: vec!["reviewed fixed community snapshot".into()],
                },
            },
            false,
        )
        .await?;
    let mut input = crate::imported_fixture::input();
    input["source"] = json!(source.snapshot()?);
    input["resource"] = json!(Uuid::new_v4().to_string());
    let input: ImportRequest = serde_json::from_value(input)?;
    let prepared = imports::prepare(
        pg::tenant(),
        &source,
        &input,
        &crate::imported_fixture::documents(),
    )?;
    let op = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        input,
    };
    let resources =
        resource::ResourceStore::new(fixture.runtime.clone(), pg::tenant(), pg::deadline()).await?;
    let audit = RequestAudit::new(pg::tenant().to_string(), "software_import");
    audit.set_principal("operator", materials::INSTANCE);
    let run = |prepared| {
        transaction(
            &fixture.runtime,
            (&fixture.catalog, &resources, &audit, &op, prepared),
            |ctx, tx| {
                Box::pin(async move {
                    let (catalog, resources, audit, op, prepared) = *ctx;
                    catalog.import_in(tx, resources, audit, op, prepared).await
                })
            },
        )
    };
    fixture
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    ensure!(run(Some(&prepared)).await.is_err());
    let original = run(None).await?;
    ensure!(original["resourceDigest"] == json!(prepared.version.digest().bytes()));
    fixture
        .source(
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 2,
                input: SourceChange::Withdraw {
                    evidence: vec!["source withdrawn".into()],
                },
            },
            false,
        )
        .await?;
    ensure!(run(None).await? == original);
    let mut changed = op.clone();
    changed.input.installer_length += 1;
    ensure!(
        transaction(
            &fixture.runtime,
            (&fixture.catalog, &resources, &audit, &changed, &prepared),
            |ctx, tx| Box::pin(async move {
                let (c, r, a, o, p) = *ctx;
                c.import_in(tx, r, a, o, Some(p)).await
            })
        )
        .await
        .is_err()
    );
    audit.finalize(None);
    fixture.runtime.close().await;
    Ok(())
}
