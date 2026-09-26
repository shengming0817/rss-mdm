use super::ArtifactWriter;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::post,
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use serde::Deserialize;
use std::sync::Arc;
pub(crate) struct HttpState {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) tenant: TenantId,
    pub(crate) content: Option<Arc<dyn ArtifactWriter>>,
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new().route(
        "/resources/{id}/content",
        post(upload).layer(DefaultBodyLimit::max(16_777_216)),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    version: String,
    variant: String,
    platform: crate::planning::action_contract::Platform,
    architecture: crate::planning::action_contract::Architecture,
}
async fn upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Upload>,
    bytes: Bytes,
) -> Result<StatusCode, Error> {
    auth.proof
        .require(crate::authorization::Permission::ResourceWrite, None)?;
    audit.set_action("management_write");
    audit.target(&id);
    crate::transaction::run(
        &app.audit_store,
        &app.runtime,
        app.tenant,
        &audit,
        (&app, &auth.proof, id, input, bytes, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (service, proof, id, input, bytes, audit) = ctx;
                crate::action_admission::lock(tx, "action-owner").await?;
                let tenant = proof.tenant_id().to_owned();
                let instance = proof.instance_id().to_owned();
                if tx.tenant_id().to_string() != tenant {
                    return Err(Error::Forbidden.into());
                }
                let snapshot = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            crate::authorization::lock_on(c, &tenant, &instance)
                                .await
                                .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                            Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                snapshot.require(proof, crate::authorization::Permission::ResourceWrite, None)?;
                let (version, state) = rss_mdm_resource_postgres::lock_reference_in(
                    tx,
                    &rss_mdm_resource::Id::new(id.as_str()).map_err(|_| Error::Malformed)?,
                    &rss_mdm_resource::Id::new(&input.version).map_err(|_| Error::Malformed)?,
                )
                .await?
                .map_err(|_| Error::Conflict)?;
                if state == rss_mdm_resource::State::Archived {
                    return Err(Error::Conflict.into());
                }
                let variant = version
                    .resolve(
                        match input.platform {
                            crate::planning::action_contract::Platform::Windows => {
                                rss_mdm_resource::Platform::Windows
                            }
                            crate::planning::action_contract::Platform::Macos => {
                                rss_mdm_resource::Platform::MacOS
                            }
                        },
                        match input.architecture {
                            crate::planning::action_contract::Architecture::X86_64 => {
                                rss_mdm_resource::Architecture::X86_64
                            }
                            crate::planning::action_contract::Architecture::Aarch64 => {
                                rss_mdm_resource::Architecture::Aarch64
                            }
                        },
                        &rss_mdm_resource::Id::new(&input.variant).map_err(|_| Error::Malformed)?,
                    )
                    .map_err(|_| Error::Malformed)?;
                let rss_mdm_resource::Declaration::Script {
                    artifact,
                    definition,
                } = variant.declaration()
                else {
                    return Err(Error::Malformed.into());
                };
                if definition.spec().profile == rss_mdm_resource::ScriptProfile::OsqueryInfoV1
                    && bytes.as_ref() != b"SELECT version FROM osquery_info;\n"
                {
                    return Err(Error::Malformed.into());
                }
                let content = service.content.clone().ok_or(Error::Unsupported)?;
                let artifact = artifact.clone();
                let bytes = bytes.clone();
                tokio::task::spawn_blocking(move || content.put(&artifact, &bytes))
                    .await
                    .map_err(|_| Error::Unavailable(crate::Failure::CommandStorage))??;
                proof.require(crate::authorization::Permission::ResourceWrite, None)?;
                proof.check_live()?;
                service
                    .audit_store
                    .append_request_in(tx, audit, 201, "success")
                    .await?;
                Ok(())
            })
        },
        crate::transaction::TransactionOwner::ResourceCatalog,
    )
    .await?;
    Ok(StatusCode::CREATED)
}

use rss_mdm_audit_integration::RequestAudit;
