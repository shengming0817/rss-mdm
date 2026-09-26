use crate::publication_support::{Server, pg, seed};
use crate::resource_catalog::{self as resources, Command};
use crate::software_publication::Error as PublicationError;

fn archive(input: &crate::software_publication::CandidateInput) -> Command {
    Command::Resource {
        id: input.resource.as_str().to_owned(),
        change: super::operation(
            input.expected_resource_revision,
            resources::Change::Archive {
                version: input.version.as_str().to_owned(),
            },
        ),
    }
}

#[tokio::test]
#[ignore = "real PG reference/archival concurrency + HTTPS: publication-t2"]
async fn candidate_reference_blocks_archive_and_race_is_atomic() {
    let server = Server::new().await;
    let runtime = pg::runtime().await;
    let publication = server.service(runtime.clone(), server.winget()).await;
    let planning = super::planning(pg::tenant()).await;

    let referenced = seed(runtime.clone(), &server, server.winget_submission()).await;
    publication
        .create_candidate(&referenced, pg::cutoff())
        .await
        .unwrap();
    assert!(matches!(
        execute(&planning, &archive(&referenced)).await,
        Err(crate::Error::Conflict)
    ));

    let racing = seed(runtime.clone(), &server, server.winget_submission()).await;
    let archive = archive(&racing);
    let (created, archived) = tokio::join!(
        publication.create_candidate(&racing, pg::cutoff()),
        execute(&planning, &archive)
    );
    match (created, archived) {
        (Ok(_), Err(crate::Error::Conflict)) => assert!(
            publication
                .candidate(&racing.candidate, pg::cutoff())
                .await
                .unwrap()
                .is_some()
        ),
        // Archive may win before the first immutable-version read, in which case
        // the version is no longer usable content. Either ordering must leave no candidate.
        (Err(PublicationError::Conflict | PublicationError::Content), Ok(_)) => assert!(
            publication
                .candidate(&racing.candidate, pg::cutoff())
                .await
                .unwrap()
                .is_none()
        ),
        result => panic!("reference and archival must serialize: {result:?}"),
    }

    planning.runtime.close().await;
    runtime.close().await;
}

async fn execute(
    service: &super::Planning,
    command: &Command,
) -> std::result::Result<serde_json::Value, crate::Error> {
    let audit = super::RequestAudit::new(service.tenant.to_string(), "management_write");
    audit.set_principal("operator", "mdm");
    let result = service.catalog.execute(command, &audit, &|| Ok(())).await;
    audit.finalize(None);
    result
}
