use crate::publication_support::{Server, pg, seed};
use crate::resource_catalog::{self as resources, Command};
use std::sync::Arc;

fn archive(input: &rss_mdm_software_service::publication::PublishInput) -> Command {
    Command::Resource {
        id: input.resource.as_str().to_owned(),
        change: resources::Operation {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: input.expected_resource_revision,
            input: resources::Change::Archive {
                version: input.version.as_str().to_owned(),
            },
        },
    }
}

#[tokio::test]
#[ignore = "real PG retained publication reference + HTTPS: make t2 MODULE=planning.resource_archive"]
async fn publication_reference_survives_admission_withdrawal_and_fences_archive() {
    let server = Server::new().await;
    let runtime = pg::runtime().await;
    let content = crate::publication_support::stored_content().await;
    let (audit, audit_pool) = pg::audit_store(runtime.clone()).await;
    let publication = server
        .service(runtime.clone(), audit, content.clone(), server.winget())
        .await;
    let planning = crate::planning::test_support::planning(pg::tenant()).await;

    let referenced = seed(runtime.clone(), &content, &server, server.winget_document()).await;
    crate::publication_support::submit_publication(&publication, &referenced).await;
    crate::publication_support::withdraw_version(&referenced).await;
    assert!(matches!(
        execute(&planning, &archive(&referenced)).await,
        Err(crate::Error::Resource(
            rss_mdm_resource_service::Error::Conflict
        ))
    ));

    planning.runtime.close().await;
    content.close().await;
    audit_pool.close().await;
    runtime.close().await;
}

async fn execute(
    service: &crate::planning::test_support::Planning,
    command: &Command,
) -> std::result::Result<serde_json::Value, crate::Error> {
    let audit = crate::planning::test_support::RequestAudit::new(
        service.tenant.to_string(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.set_principal("operator", crate::test_support::INSTANCE);
    let catalog = crate::resource_assembly::catalog(
        service.audit_store.clone(),
        service.runtime.clone(),
        service.tenant,
        Arc::new(crate::clock::SystemClock),
    )
    .await
    .unwrap();
    let result = catalog.execute(command, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result.map_err(Into::into)
}
