use crate::publication_support::{Server, pg, seed};
use crate::resource_catalog::{self as resources, Command};

fn archive(input: &rss_mdm_software_service::publication::CandidateInput) -> Command {
    Command::Resource {
        id: input.resource.as_str().to_owned(),
        change: crate::planning::test_support::operation(
            input.expected_resource_revision,
            resources::Change::Archive {
                version: input.version.as_str().to_owned(),
            },
        ),
    }
}

#[tokio::test]
#[ignore = "real PG reference/archival concurrency + HTTPS: make t2 MODULE=planning.resource_archive"]
async fn candidate_reference_survives_admission_withdrawal_and_fences_archive() {
    let server = Server::new().await;
    let runtime = pg::runtime().await;
    let publication = server.service(runtime.clone(), server.winget()).await;
    let planning = crate::planning::test_support::planning(pg::tenant()).await;

    let referenced = seed(runtime.clone(), &server, server.winget_document()).await;
    publication
        .create_candidate(&referenced, pg::cutoff())
        .await
        .unwrap();
    crate::publication_support::withdraw_version_admission(&referenced).await;
    for record in crate::audit_test_support::decode_hex(&pg::sql(&format!(
        "SELECT encode(canonical,'hex') FROM rss_audit.records WHERE tenant_id='{}' ORDER BY position", pg::tenant()
    ))).unwrap() {
        rss_mdm_timeline_service::project(record.decoded.event()).unwrap();
    }
    assert!(matches!(
        execute(&planning, &archive(&referenced)).await,
        Err(crate::Error::Service(rss_mdm_flow_service::Error::Conflict))
    ));

    let mut document = server.winget_document();
    let rss_mdm_software_service::publication::ExportDocument::Winget { manifest } = &mut document
    else {
        unreachable!()
    };
    manifest["PackageIdentifier"] = serde_json::json!("Acme.Race");
    let racing = seed(runtime.clone(), &server, document).await;
    let archive = archive(&racing);
    let (created, archived) = tokio::join!(
        publication.create_candidate(&racing, pg::cutoff()),
        execute(&planning, &archive)
    );
    // Current enterprise approval already protects the version before the publication is added.
    assert!(created.is_ok(), "candidate creation: {created:?}");
    assert!(matches!(
        archived,
        Err(crate::Error::Service(rss_mdm_flow_service::Error::Conflict))
    ));
    assert!(
        publication
            .candidate(&racing.candidate, pg::cutoff())
            .await
            .unwrap()
            .is_some()
    );

    planning.runtime.close().await;
    runtime.close().await;
}

async fn execute(
    service: &crate::planning::test_support::Planning,
    command: &Command,
) -> std::result::Result<serde_json::Value, crate::Error> {
    let audit = crate::planning::test_support::RequestAudit::new(
        service.tenant.to_string(),
        "management_write",
    );
    audit.set_principal("operator", crate::test_support::INSTANCE);
    let result = service.catalog.execute(command, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result.map_err(Into::into)
}
