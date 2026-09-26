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
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let plan = Uuid::new_v4();
    let create = json!({"operationId":plan,"resource":id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"manual"},"notBefore":now,"until":now+3600,"jitterSeconds":0,"window":null},"runLifetimeSeconds":300});
    let archive = json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}});
    let path = format!("/api/v3/resources/{id}");
    let mut archiver = author.clone();
    let (created, archived) = tokio::try_join!(
        author.call(router, Method::POST, "/api/v3/script-plans", Some(create)),
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
            &format!("/api/v3/script-plans/{plan}/cancel"),
            json!({"operationId":Uuid::new_v4()}),
        )
        .await?;
        let historical = archiver
            .call(router, Method::POST, &path, Some(archive))
            .await?;
        ensure!(
            historical.0 == StatusCode::CONFLICT,
            "cancelled plan lost historical reference: {historical:?}"
        );
    } else {
        ensure!(
            created.0 == StatusCode::CONFLICT && created.1["code"] == "script_resource_unavailable",
            "archived resource admitted: {created:?}"
        );
    }
    Ok(())
}
