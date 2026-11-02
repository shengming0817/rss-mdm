//! Read-only native wrapping of the original authorized signing receipt.
use crate::{Error, Services, boundary::Administrator};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use rss_mdm_apple_mdm::{
    applicability::{Channel, Context, Enrollment, Version},
    native::{Target, ddm::DeclarationInput, profiles::ProfileInput},
};
use std::sync::Arc;
#[derive(Default, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    pub macos_version: Option<String>,
    pub profile_url: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Templates {
    pub format_version: u8,
    pub operation: uuid::Uuid,
    pub digest: String,
    pub native_digest: String,
    pub signed: rss_mdm_agent_wire::da::SignedConfiguration,
    pub mac: Option<Mac>,
    pub windows: Option<rss_mdm_windows_mdm::da::Templates>,
    pub mutable_metadata: Vec<&'static str>,
    pub status_mapping: serde_json::Value,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Mac {
    pub profile: ProfileInput,
    pub mobileconfig: String,
    pub legacy: Option<DeclarationInput>,
    pub legacy_unavailable: Option<&'static str>,
}
pub(crate) async fn templates(
    State(s): State<Arc<Services>>,
    Administrator(p): Administrator,
    Path(id): Path<uuid::Uuid>,
    Query(options): Query<Options>,
) -> Result<Json<Templates>, Error> {
    let artifact = s
        .business
        .as_ref()
        .ok_or(Error::Unavailable)?
        .service
        .configuration_operation(&s.configurations, &p, id)
        .await?;
    Ok(Json(render(id, artifact, &options)?))
}
pub fn render(
    operation: uuid::Uuid,
    signed: rss_mdm_agent_wire::da::SignedConfiguration,
    options: &Options,
) -> Result<Templates, Error> {
    let configuration = signed.decode().map_err(|_| Error::Malformed)?;
    let mac = if configuration.content.mac.is_some() {
        let version = options.macos_version.as_deref().ok_or(Error::Malformed)?;
        let context = Context {
            version: Some(Version::parse(version).map_err(|_| Error::Malformed)?),
            channel: Channel::Device,
            enrollment: Enrollment::Device,
            supervised: Some(true),
            automated_enrollment: Some(false),
            user_approved: Some(true),
            apple_silicon: None,
        };
        let target = Target {
            context: &context,
            access_rights: &[],
        };
        let profile = rss_mdm_apple_mdm::da::profile(&signed).map_err(|_| Error::Malformed)?;
        let compiled = profile.compile(&target).map_err(|_| Error::Malformed)?;
        let legacy = options
            .profile_url
            .as_ref()
            .map(|url| rss_mdm_apple_mdm::da::legacy(&profile, url).map_err(|_| Error::Malformed))
            .transpose()?;
        if let Some(legacy) = &legacy {
            legacy
                .compile(&signed.digest, &target)
                .map_err(|_| Error::Malformed)?;
        }
        Some(Mac {
            profile,
            mobileconfig: String::from_utf8(compiled.bytes).map_err(|_| Error::Malformed)?,
            legacy_unavailable: legacy.is_none().then_some("mdm_profile_transport_required"),
            legacy,
        })
    } else {
        if options.macos_version.is_some() || options.profile_url.is_some() {
            return Err(Error::Malformed);
        }
        None
    };
    let windows = Some(rss_mdm_windows_mdm::da::templates(&signed).map_err(|_| Error::Malformed)?);
    Ok(Templates {
        format_version: 1,
        operation,
        digest: signed.digest.clone(),
        native_digest: configuration.native.digest,
        signed,
        mac,
        windows,
        mutable_metadata: vec![
            "PayloadDisplayName",
            "PayloadDescription",
            "PayloadOrganization",
        ],
        status_mapping: status_mapping(),
    })
}
/// Declarative mappings only; unavailable vendor connectors are not represented as installed.
pub fn status_mapping() -> serde_json::Value {
    let fields = serde_json::json!([
 {"name":"contractVersion","path":"report.contractVersion","type":"integer","nullable":true},
 {"name":"clientVersion","path":"report.clientVersion","type":"string","nullable":true},
 {"name":"health","path":"report.health","type":"string","values":["unknown","ready","degraded","blocked"]},
 {"name":"binding","path":"report.binding","type":"string","values":["unknown","ready","degraded","blocked"]},
 {"name":"factor","path":"report.factor","type":"string","values":["unknown","ready","degraded","blocked"]},
 {"name":"configurationDigest","path":"report.configurationDigest","type":"string","nullable":true},
 {"name":"applicationState","path":"report.state","type":"string","values":["unknown","received","validated","applied","rejected"]},
 {"name":"sourceState","path":"report.sources[].state","type":"array","values":["missing","present","read_failed","invalid","expired","conflict","withdrawn"]},
 {"name":"delivery","path":"report.sources[].delivery","type":"array","values":["da","managed_mandatory"]},
 {"name":"receivedAt","path":"receipt.receivedAt","type":"integer","nullable":true},
 {"name":"reportedEvidence","path":"receipt.evidence","type":"string","values":["reported","verified"],"meaning":"receipt authority only"},
 {"name":"stale","path":"stale","type":"boolean"}]);
    let mappings=fields.as_array().expect("fixed declaration").iter().map(|f|serde_json::json!({"source":f["name"],"jamf":{"attribute":format!("RSS DA {}",f["name"].as_str().expect("field")),"type":"String"},"intune":{"settingName":format!("RSSDA_{}",f["name"].as_str().expect("field")),"dataType":"String"},"conversion":{"missing":"unknown","boolean":"true or false","integer":"decimal string","array":"canonical JSON string","string":"unchanged"}})).collect::<Vec<_>>();
    serde_json::json!({"version":1,"fields":fields,"vendorMappings":mappings,"connectors":{"rss":"native","jamf":"unavailable","intune":"unavailable"},"semantics":{"absent":"unknown","stale":"retain reported value with stale=true; never satisfy a compliance predicate implicitly","reported":"device observation","verified":"requires independent authority evidence; applied and ready never imply verified","compliance":"explicit consumer policy required"}})
}
