//! Generate protocol documentation directly from the current Rust DTOs.
use rss_mdm_agent_wire::{enroll, pki, runtime};
fn main() {
    let schemas = serde_json::json!({
        "pki": {
            "Trust": schemars::schema_for!(pki::Trust),
            "Acknowledgement": schemars::schema_for!(pki::Acknowledgement),
        },
        "runtime": {
            "BindingProfile": schemars::schema_for!(runtime::BindingProfile),
            "ReportRequest": schemars::schema_for!(runtime::ReportRequest),
            "ReportAck": schemars::schema_for!(runtime::ReportAck),
            "ReportStatus": schemars::schema_for!(runtime::ReportStatus),
            "ErrorBody": schemars::schema_for!(runtime::ErrorBody),
            "TaskClaimRequest": schemars::schema_for!(runtime::TaskClaimRequest),
            "TaskEventRequest": schemars::schema_for!(runtime::TaskEventRequest),
            "TaskPayload": schemars::schema_for!(runtime::TaskPayload),
            "SignedTask": schemars::schema_for!(runtime::SignedTask),
            "TaskClaimResponse": schemars::schema_for!(runtime::TaskClaimResponse),
            "TaskEventAck": schemars::schema_for!(runtime::TaskEventAck),
            "TaskAuthorization": schemars::schema_for!(runtime::TaskAuthorization),
            "TaskResource": schemars::schema_for!(runtime::TaskResource),
            "SelfServiceInvoke": schemars::schema_for!(runtime::SelfServiceInvoke),
            "SelfServiceDirectory": schemars::schema_for!(runtime::SelfServiceDirectory),
            "SelfServiceDirectoryResponse": schemars::schema_for!(runtime::SelfServiceDirectoryResponse),
            "SelfServiceAccepted": schemars::schema_for!(runtime::SelfServiceAccepted),
            "SelfServiceStatus": schemars::schema_for!(runtime::SelfServiceStatus),
        },
        "enroll": {
            "ConfigurationFile": schemars::schema_for!(enroll::configuration::ConfigurationFile),
            "ConfigurationExchange": schemars::schema_for!(enroll::configuration::Exchange),
            "ConfigurationExchangeStatus": schemars::schema_for!(enroll::configuration::ExchangeStatus),
            "ReservationCancel": schemars::schema_for!(enroll::configuration::Cancel),
            "Package": schemars::schema_for!(enroll::configuration::Package),

            "GrantRequest": schemars::schema_for!(enroll::GrantRequest),
            "CertificateRequest": schemars::schema_for!(enroll::CertificateRequest),
            "ActivationRequest": schemars::schema_for!(enroll::ActivationRequest),
            "StatusRequest": schemars::schema_for!(enroll::StatusRequest),
            "GrantReceipt": schemars::schema_for!(enroll::GrantReceipt),
            "Candidate": schemars::schema_for!(enroll::Candidate),
            "ActivationReceipt": schemars::schema_for!(enroll::ActivationReceipt),
            "Progress": schemars::schema_for!(enroll::Progress),
            "RecoverIssuance": schemars::schema_for!(enroll::RecoverIssuance),
            "NativeGrantRequest": schemars::schema_for!(enroll::NativeGrantRequest),
            "ErrorBody": schemars::schema_for!(enroll::ErrorBody),
            "RenewalStatusRequest": schemars::schema_for!(enroll::RenewalStatusRequest),
        },
    });
    println!("{}", serde_json::to_string_pretty(&schemas).unwrap());
}
