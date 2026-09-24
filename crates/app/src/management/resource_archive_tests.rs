use super::super::{Command, resources};
use crate::publication_support::{Server, pg, seed};
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
    let management = super::management(pg::tenant()).await;

    let referenced = seed(runtime.clone(), &server, server.winget_submission()).await;
    publication
        .create_candidate(&referenced, pg::cutoff())
        .await
        .unwrap();
    assert!(matches!(
        super::execute(&management, &archive(&referenced)).await,
        Err(crate::Error::Conflict)
    ));

    let racing = seed(runtime.clone(), &server, server.winget_submission()).await;
    let archive = archive(&racing);
    let (created, archived) = tokio::join!(
        publication.create_candidate(&racing, pg::cutoff()),
        super::execute(&management, &archive)
    );
    match (created, archived) {
        (Ok(_), Err(crate::Error::Conflict)) => assert!(
            publication
                .candidate(&racing.candidate, pg::cutoff())
                .await
                .unwrap()
                .is_some()
        ),
        (Err(PublicationError::Conflict), Ok(_)) => assert!(
            publication
                .candidate(&racing.candidate, pg::cutoff())
                .await
                .unwrap()
                .is_none()
        ),
        result => panic!("reference and archival must serialize: {result:?}"),
    }

    management.runtime.close().await;
    runtime.close().await;
}
