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
    pub status_mapping: StatusMapping,
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
/// Fixed native-to-vendor mapping metadata; consumers must explicitly evaluate compliance.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatusMapping {
    pub version: u8,
    pub fields: Vec<StatusField>,
    pub vendor_mappings: Vec<VendorMapping>,
    pub connectors: Connectors,
    pub semantics: Semantics,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatusField {
    pub name: &'static str,
    pub path: &'static str,
    #[serde(rename = "type")]
    pub kind: StatusType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meaning: Option<&'static str>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StatusType {
    Integer,
    String,
    Array,
    Boolean,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct VendorMapping {
    pub source: &'static str,
    pub jamf: JamfMapping,
    pub intune: IntuneMapping,
    pub conversion: Conversion,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct JamfMapping {
    pub attribute: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntuneMapping {
    pub setting_name: String,
    pub data_type: &'static str,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Conversion {
    pub missing: &'static str,
    pub boolean: &'static str,
    pub integer: &'static str,
    pub array: &'static str,
    pub string: &'static str,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Connectors {
    pub rss: &'static str,
    pub jamf: &'static str,
    pub intune: &'static str,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct Semantics {
    pub absent: &'static str,
    pub stale: &'static str,
    pub reported: &'static str,
    pub verified: &'static str,
    pub compliance: &'static str,
}
/// Declarative mappings only; unavailable vendor connectors are not represented as installed.
pub fn status_mapping() -> StatusMapping {
    use StatusType::{Array, Boolean, Integer, String};
    let health: &[&str] = &["unknown", "ready", "degraded", "blocked"];
    let fields = vec![
        (
            "contractVersion",
            "report.contractVersion",
            Integer,
            Some(true),
            None,
            None,
        ),
        (
            "clientVersion",
            "report.clientVersion",
            String,
            Some(true),
            None,
            None,
        ),
        ("health", "report.health", String, None, Some(health), None),
        (
            "binding",
            "report.binding",
            String,
            None,
            Some(health),
            None,
        ),
        ("factor", "report.factor", String, None, Some(health), None),
        (
            "configurationDigest",
            "report.configurationDigest",
            String,
            Some(true),
            None,
            None,
        ),
        (
            "applicationState",
            "report.state",
            String,
            None,
            Some(&["unknown", "received", "validated", "applied", "rejected"][..]),
            None,
        ),
        (
            "sourceState",
            "report.sources[].state",
            Array,
            None,
            Some(
                &[
                    "missing",
                    "present",
                    "read_failed",
                    "invalid",
                    "expired",
                    "conflict",
                    "withdrawn",
                ][..],
            ),
            None,
        ),
        (
            "delivery",
            "report.sources[].delivery",
            Array,
            None,
            Some(&["da", "managed_mandatory"][..]),
            None,
        ),
        (
            "receivedAt",
            "receipt.receivedAt",
            Integer,
            Some(true),
            None,
            None,
        ),
        (
            "reportedEvidence",
            "receipt.evidence",
            String,
            None,
            Some(&["reported", "verified"][..]),
            Some("receipt authority only"),
        ),
        ("stale", "stale", Boolean, None, None, None),
    ]
    .into_iter()
    .map(
        |(name, path, kind, nullable, values, meaning)| StatusField {
            name,
            path,
            kind,
            nullable,
            values,
            meaning,
        },
    )
    .collect::<Vec<_>>();
    let vendor_mappings = fields
        .iter()
        .map(|f| VendorMapping {
            source: f.name,
            jamf: JamfMapping {
                attribute: format!("RSS DA {}", f.name),
                kind: "String",
            },
            intune: IntuneMapping {
                setting_name: format!("RSSDA_{}", f.name),
                data_type: "String",
            },
            conversion: Conversion {
                missing: "unknown",
                boolean: "true or false",
                integer: "decimal string",
                array: "canonical JSON string",
                string: "unchanged",
            },
        })
        .collect();
    StatusMapping {
        version: 1,
        fields,
        vendor_mappings,
        connectors: Connectors {
            rss: "native",
            jamf: "unavailable",
            intune: "unavailable",
        },
        semantics: Semantics {
            absent: "unknown",
            stale: "retain reported value with stale=true; never satisfy a compliance predicate implicitly",
            reported: "device observation",
            verified: "requires independent authority evidence; applied and ready never imply verified",
            compliance: "explicit consumer policy required",
        },
    }
}
