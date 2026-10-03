//! Certificate-bound immutable native asset delivery.
use super::*;
/// A URL locates a frozen binding. Certificate, generation, active native scope and
/// current execution authority are independently required by the consuming use case.
pub async fn asset_binding(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    operation: Uuid,
    identifier: &str,
) -> Result<Option<native::ddm::AssetBinding>, Error> {
    crate::device::store::lock_channel(c, &p.tenant().to_string(), p.device(), p.channel()).await?;
    crate::device::store::revalidate_source(c, p, rss_mdm_inventory::ReportSource::MdmApple)
        .await?;
    let row=sqlx::query("SELECT user_key,snapshot FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND retired_at IS NULL")
        .bind(p.tenant().to_string()).bind(operation).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user: String = row.try_get("user_key").map_err(db)?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND state='active')")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(&user).fetch_one(c).await.map_err(db)?;
    if !active {
        return Err(Error::Unauthorized);
    }
    let sealed: Vec<u8> = row.try_get("snapshot").map_err(db)?;
    let plain = key
        .open_bytes(&sealed, &aad(p, &user, operation, "apple.ddm.publication")?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let publication: Publication = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    Ok(publication
        .assets
        .into_iter()
        .find(|a| a.selection.identifier == identifier))
}
pub async fn asset(
    axum::extract::State(app): axum::extract::State<std::sync::Arc<crate::HttpState>>,
    axum::Extension(peer): axum::Extension<rss_mdm_certificate::HandshakePeer>,
    axum::Extension(audit): axum::Extension<rss_mdm_audit_integration::RequestAudit>,
    axum::extract::Path((operation, identifier)): axum::extract::Path<(Uuid, String)>,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let apple = app.apple()?;
    let leaf = apple.authority.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let p = app
        .devices
        .management_principal(&app.mount.credential(leaf.fingerprint()))
        .await?;
    audit.identify_device(p.registration());
    audit.target(p.device());
    audit.registration(p.registration());
    let reader = Box::new(AssetRead {
        key: apple.protection.clone(),
        operation,
        identifier,
    });
    let (binding, verified) = app
        .execution
        .apple_asset(&p, operation, reader, &audit)
        .await?;
    let bytes = verified
        .stream(0, binding.length)
        .await
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    Ok((
        [
            ("content-type", binding.selection.content_type),
            ("cache-control", "no-store".into()),
            ("content-length", binding.length.to_string()),
        ],
        axum::body::Body::from_stream(bytes),
    )
        .into_response())
}

struct AssetRead {
    key: std::sync::Arc<Protector>,
    operation: Uuid,
    identifier: String,
}
impl channels::AppleAssetRead for AssetRead {
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> channels::Pending<'a, Option<native::ddm::AssetBinding>> {
        Box::pin(async move {
            asset_binding(c, &self.key, p, self.operation, &self.identifier)
                .await
                .map_err(Into::into)
        })
    }
}
