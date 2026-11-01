//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;

use crate::authorize_action;
use rss_mdm_policy::Definition;
use rss_mdm_policy::pages::Preview;
pub async fn preview(
    s: &Queries,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<super::records::Preview, crate::queries::QueryError> {
    query
        .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    input.definition.validate()?;
    proof.manage(Permission::PolicyRead)?;
    if input.definition.action.resource().is_some() {
        proof.manage(Permission::ResourceRead)?;
    }
    authorize_preview(proof.authorization()?, proof, &input.definition)?;
    if !matches!(input.definition.action, Action::UnmanageDevice { .. }) {
        return Err(Error::Unsupported.into());
    }
    s.snapshot(proof, (s, proof, input, query, codec), |ctx, c, basis| {
        Box::pin(async move {
            let (s, proof, input, query, codec) = *ctx;
            let authorization = &basis.grant;
            authorization.require(proof, Permission::PolicyRead, None)?;
            if input.definition.action.resource().is_some() {
                authorization.require(proof, Permission::ResourceRead, None)?;
            }
            authorize_preview(authorization, proof, &input.definition)?;
            let authority = authorization.query_binding(proof)?;
            let scope = input.definition.scope;
            let definition = json!([input.definition, input.scope_result]);
            let limit = query.limit();
            let binding = rss_mdm_scope_service::window::binding_on(
                &s.source,
                c,
                proof,
                &authority,
                rss_mdm_policy::pages::PREVIEW_SCHEMA.id,
                scope,
                &definition,
            )
            .await?;
            let after = rss_mdm_scope_service::window::after(codec, query, &binding)?;
            super::lifecycle::preview_on(s, c, input, after.as_deref(), limit, codec, &binding)
                .await
        })
    })
    .await
    .map_err(Into::into)
}

fn authorize_preview(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> Result<(), crate::Error> {
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    authorize_action(snapshot, proof, &definition.action)
}
