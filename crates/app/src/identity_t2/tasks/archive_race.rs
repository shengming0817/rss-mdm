use super::*;
pub(super) async fn verify(
    author: &mut Browser,
    router: &Router,
    definition: &Value,
    bytes: &[u8],
) -> Result<()> {
    // Both requests traverse authenticated HTTP; the resource-version lock serializes reference creation and archive.
    let id = Uuid::new_v4();
    resource(
        author,
        router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    resource(author,router,id,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"fixture-script","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    resource(
        author,
        router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let policy = Uuid::new_v4();
    let create = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,EMPTY_SCOPE)}});
    let policy_path = format!("/api/v2/policies/{policy}");
    let archive = json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}});
    let path = format!("/api/v3/resources/{id}");
    let mut archiver = author.clone();
    let (created, archived) = tokio::try_join!(
        author.call(router, Method::POST, &policy_path, Some(create)),
        archiver.call(router, Method::POST, &path, Some(archive.clone()))
    )?;
    ensure!(
        created.0.is_success() != archived.0.is_success(),
        "archive race: {created:?} / {archived:?}"
    );
    if created.0.is_success() {
        ensure!(archived.0 == StatusCode::CONFLICT);
        post(
            author,
            router,
            &policy_path,
            json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
        )
        .await?;
        let historical = archiver
            .call(router, Method::POST, &path, Some(archive))
            .await?;
        ensure!(
            historical.0 == StatusCode::CONFLICT,
            "disabled policy lost historical reference: {historical:?}"
        );
    } else {
        ensure!(
            created.0 == StatusCode::CONFLICT,
            "archived resource admitted: {created:?}"
        );
    }
    Ok(())
}
