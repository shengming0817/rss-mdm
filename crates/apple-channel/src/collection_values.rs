//! Allowlisted ordinary Inventory evidence. Original bytes exist only for native validation and MAC.
use crate::Error;
use plist::{Dictionary, Value};
use rss_mdm_resource::NativeAdapter;
use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

fn fields(d: &Dictionary, names: &[(&str, &str)]) -> Result<Map<String, Json>, Error> {
    names
        .iter()
        .filter_map(|(native, canonical)| d.get(native).map(|v| (*canonical, v)))
        .map(|(key, value)| Ok((key.into(), scalar(value)?)))
        .collect()
}
fn scalar(value: &Value) -> Result<Json, Error> {
    match value {
        Value::String(v) if v.len() <= 4096 => Ok(json!(v)),
        Value::Boolean(v) => Ok(json!(v)),
        Value::Integer(v) => v.as_signed().map(|v| json!(v)).ok_or(Error::Malformed),
        Value::Real(v) if v.is_finite() => Ok(json!(v)),
        Value::Array(v) if v.len() <= 1024 => v
            .iter()
            .map(scalar)
            .collect::<Result<Vec<_>, _>>()
            .map(Json::Array),
        _ => Err(Error::Malformed),
    }
}
fn security_property(key: &str) -> &str {
    match key {
        "BlockAllIncoming" => "block_all_incoming",
        "FirewallEnabled" => "firewall_enabled",
        "LoggingEnabled" => "logging_enabled",
        "LoggingOption" => "logging_option",
        "StealthMode" => "stealth_mode",
        "AllowOroms" => "allow_oroms",
        "ChangePending" => "change_pending",
        "PasswordExists" => "password_exists",
        "EnrolledViaDEP" => "enrolled_via_dep",
        "IsActivationLockManageable" => "is_activation_lock_manageable",
        "IsUserEnrollment" => "is_user_enrollment",
        "UserApprovedEnrollment" => "user_approved_enrollment",
        "ExternalBootLevel" => "external_boot_level",
        "SecureBootLevel" => "secure_boot_level",
        "ReducedSecurity" => "reduced_security",
        _ => unreachable!("fixed security property"),
    }
}
pub(crate) fn normalize(adapter: NativeAdapter, d: &Dictionary) -> Result<Json, Error> {
    use NativeAdapter::*;
    match adapter {
        AppleDeviceInformation => {
            let d = d
                .get("QueryResponses")
                .and_then(Value::as_dictionary)
                .ok_or(Error::Malformed)?;
            Ok(Json::Object(fields(
                d,
                &[
                    ("Model", "Model"),
                    ("ModelName", "ModelName"),
                    ("ModelNumber", "ModelNumber"),
                    ("ProductName", "ProductName"),
                    ("OSVersion", "OSVersion"),
                    ("BuildVersion", "BuildVersion"),
                    ("DeviceName", "DeviceName"),
                    ("SerialNumber", "SerialNumber"),
                    ("IsAppleSilicon", "IsAppleSilicon"),
                    ("DeviceCapacity", "DeviceCapacity"),
                    ("AvailableDeviceCapacity", "AvailableDeviceCapacity"),
                    ("WiFiMAC", "WiFiMAC"),
                    ("EthernetMAC", "EthernetMAC"),
                    ("ActiveManagedUsers", "ActiveManagedUsers"),
                    ("HostName", "HostName"),
                    ("LocalHostName", "LocalHostName"),
                    (
                        "SystemIntegrityProtectionEnabled",
                        "SystemIntegrityProtectionEnabled",
                    ),
                    ("IsActivationLockEnabled", "IsActivationLockEnabled"),
                    (
                        "IsDeviceLocatorServiceEnabled",
                        "IsDeviceLocatorServiceEnabled",
                    ),
                    ("BatteryLevel", "BatteryLevel"),
                    ("IsSupervised", "IsSupervised"),
                    ("IsMDMLostModeEnabled", "IsMDMLostModeEnabled"),
                    ("AwaitingConfiguration", "AwaitingConfiguration"),
                    ("SupplementalBuildVersion", "SupplementalBuildVersion"),
                    ("SupplementalOSVersionExtra", "SupplementalOSVersionExtra"),
                ],
            )?))
        }
        AppleSecurity => {
            let d = d
                .get("SecurityInfo")
                .and_then(Value::as_dictionary)
                .ok_or(Error::Malformed)?;
            let mut result = fields(
                d,
                &[
                    ("FDE_Enabled", "FDE_Enabled"),
                    ("FDE_HasPersonalRecoveryKey", "FDE_HasPersonalRecoveryKey"),
                    (
                        "FDE_HasInstitutionalRecoveryKey",
                        "FDE_HasInstitutionalRecoveryKey",
                    ),
                    (
                        "SystemIntegrityProtectionEnabled",
                        "SystemIntegrityProtectionEnabled",
                    ),
                    ("IsRecoveryLockEnabled", "IsRecoveryLockEnabled"),
                    (
                        "BootstrapTokenAllowedForAuthentication",
                        "BootstrapTokenAllowedForAuthentication",
                    ),
                    (
                        "BootstrapTokenRequiredForSoftwareUpdate",
                        "BootstrapTokenRequiredForSoftwareUpdate",
                    ),
                    (
                        "BootstrapTokenRequiredForKernelExtensionApproval",
                        "BootstrapTokenRequiredForKernelExtensionApproval",
                    ),
                ],
            )?;
            for (name, keys) in [
                (
                    "FirewallSettings",
                    &[
                        "BlockAllIncoming",
                        "FirewallEnabled",
                        "LoggingEnabled",
                        "LoggingOption",
                        "StealthMode",
                    ][..],
                ),
                (
                    "FirmwarePasswordStatus",
                    &["AllowOroms", "ChangePending", "PasswordExists"][..],
                ),
                (
                    "ManagementStatus",
                    &[
                        "EnrolledViaDEP",
                        "IsActivationLockManageable",
                        "IsUserEnrollment",
                        "UserApprovedEnrollment",
                    ][..],
                ),
                (
                    "SecureBoot",
                    &["ExternalBootLevel", "SecureBootLevel", "ReducedSecurity"][..],
                ),
            ] {
                if let Some(v) = d.get(name) {
                    let d = v.as_dictionary().ok_or(Error::Malformed)?;
                    result.insert(
                        name.into(),
                        Json::Object(fields(
                            d,
                            &keys
                                .iter()
                                .map(|k| (*k, security_property(k)))
                                .collect::<Vec<_>>(),
                        )?),
                    );
                }
            }
            Ok(Json::Object(result))
        }
        AppleInstalledApplications | AppleProfiles | AppleCertificates | AppleUsers => {
            let (name, keys): (&str, &[(&str, &str)]) = match adapter {
                AppleInstalledApplications => (
                    "InstalledApplicationList",
                    &[
                        ("Identifier", "id"),
                        ("Name", "name"),
                        ("Path", "path"),
                        ("Version", "version"),
                        ("ShortVersion", "short_version"),
                        ("BundleSize", "bundle_bytes"),
                        ("DynamicSize", "dynamic_bytes"),
                        ("Installing", "installing"),
                        ("IsValidated", "validated"),
                        ("AppStoreVendable", "app_store"),
                        ("DeviceBasedVPP", "device_vpp"),
                        ("ExternalVersionIdentifier", "external_version"),
                        ("HasUpdateAvailable", "update_available"),
                        ("AdHocCodeSigned", "ad_hoc_signed"),
                        ("BetaApp", "beta"),
                    ],
                ),
                AppleProfiles => (
                    "ProfileList",
                    &[
                        ("PayloadUUID", "id"),
                        ("PayloadIdentifier", "identifier"),
                        ("PayloadDisplayName", "name"),
                        ("PayloadDescription", "description"),
                        ("PayloadOrganization", "organization"),
                        ("PayloadVersion", "version"),
                        ("HasRemovalPasscode", "removal_passcode"),
                        ("IsEncrypted", "encrypted"),
                        ("IsManaged", "managed"),
                        ("PayloadRemovalDisallowed", "removal_disallowed"),
                        ("Source", "source"),
                    ],
                ),
                AppleCertificates => (
                    "CertificateList",
                    &[("CommonName", "common_name"), ("IsIdentity", "identity")],
                ),
                AppleUsers => (
                    "Users",
                    &[
                        ("UserGUID", "id"),
                        ("UID", "uid"),
                        ("UserName", "name"),
                        ("FullName", "full_name"),
                        ("HasSecureToken", "secure_token"),
                        ("IsLoggedIn", "logged_in"),
                        ("MobileAccount", "mobile_account"),
                    ],
                ),
                _ => unreachable!(),
            };
            let rows = d
                .get(name)
                .and_then(Value::as_array)
                .ok_or(Error::Malformed)?;
            if rows.len() > 100000 {
                return Err(Error::Malformed);
            }
            let items = rows
                .iter()
                .map(|row| {
                    let d = row.as_dictionary().ok_or(Error::Malformed)?;
                    let mut out = fields(d, keys)?;
                    if adapter == AppleCertificates {
                        let der = d
                            .get("Data")
                            .and_then(Value::as_data)
                            .ok_or(Error::Malformed)?;
                        let cert =
                            openssl::x509::X509::from_der(der).map_err(|_| Error::Malformed)?;
                        let id = Sha256::digest(der)
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>();
                        out.insert("id".into(), json!(id));
                        out.insert(
                            "serial".into(),
                            json!(
                                cert.serial_number()
                                    .to_bn()
                                    .and_then(|v| v.to_hex_str())
                                    .map_err(|_| Error::Malformed)?
                                    .to_string()
                            ),
                        );
                        out.insert("not_before".into(), json!(cert.not_before().to_string()));
                        out.insert("not_after".into(), json!(cert.not_after().to_string()));
                    }
                    Ok(Json::Object(out))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(json!({"items":items}))
        }
        WindowsRead => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_apple_mdm::protocol::dictionary;
    #[test]
    fn security_response_never_retains_recovery_material_or_unknown_nested_fields() {
        let response = dictionary([(
            "SecurityInfo",
            dictionary([
                ("FDE_Enabled", true.into()),
                ("FDE_PersonalRecoveryKeyCMS", Value::Data(vec![1, 2, 3])),
                ("FDE_PersonalRecoveryKeyDeviceKey", "serial-index".into()),
                (
                    "FirewallSettings",
                    dictionary([
                        ("FirewallEnabled", true.into()),
                        ("FutureSecret", "secret".into()),
                    ])
                    .into(),
                ),
            ])
            .into(),
        )]);
        let result = normalize(NativeAdapter::AppleSecurity, &response).unwrap();
        assert_eq!(
            result,
            json!({"FDE_Enabled":true,"FirewallSettings":{"firewall_enabled":true}})
        );
    }
    #[test]
    fn profile_optional_absence_is_not_filled_and_payloads_are_not_retained() {
        let response = dictionary([(
            "ProfileList",
            Value::Array(vec![
                dictionary([
                    ("PayloadUUID", "one".into()),
                    ("PayloadIdentifier", "com.example.profile".into()),
                    (
                        "PayloadContent",
                        Value::Array(vec![dictionary([("Password", "secret".into())]).into()]),
                    ),
                    (
                        "SignerCertificates",
                        Value::Array(vec![Value::Data(vec![1, 2, 3])]),
                    ),
                ])
                .into(),
            ]),
        )]);
        assert_eq!(
            normalize(NativeAdapter::AppleProfiles, &response).unwrap(),
            json!({"items":[{"id":"one","identifier":"com.example.profile"}]})
        );
    }
    #[test]
    fn applications_preserve_optional_attributes_and_repeated_identifiers() {
        let raw = dictionary([(
            "InstalledApplicationList",
            Value::Array(vec![
                dictionary([
                    ("Name", "Anonymous".into()),
                    ("Path", "/Applications/Anonymous.app".into()),
                ])
                .into(),
                dictionary([
                    ("Identifier", "com.example.same".into()),
                    ("Path", "/Applications/One.app".into()),
                ])
                .into(),
                dictionary([
                    ("Identifier", "com.example.same".into()),
                    ("Path", "/Applications/Two.app".into()),
                ])
                .into(),
                Dictionary::new().into(),
            ]),
        )]);
        assert_eq!(
            normalize(NativeAdapter::AppleInstalledApplications, &raw).unwrap(),
            json!({"items":[{"name":"Anonymous","path":"/Applications/Anonymous.app"},
                {"id":"com.example.same","path":"/Applications/One.app"},
                {"id":"com.example.same","path":"/Applications/Two.app"},{}]})
        );
    }
    #[test]
    fn absent_list_is_not_an_empty_snapshot() {
        for (adapter, key) in [
            (NativeAdapter::AppleUsers, "Users"),
            (
                NativeAdapter::AppleInstalledApplications,
                "InstalledApplicationList",
            ),
        ] {
            assert!(normalize(adapter, &Dictionary::new()).is_err());
            assert_eq!(
                normalize(adapter, &dictionary([(key, Value::Array(vec![]))])).unwrap(),
                json!({"items":[]})
            );
        }
    }
}

#[cfg(test)]
mod hardware_fixtures {
    use super::*;
    use rss_mdm_apple_mdm::{
        applicability::{Channel, Context, Enrollment, Version},
        native::{Command, Target},
    };
    #[test]
    fn intel_t2_and_silicon_keep_distinct_security_evidence() {
        for (name, silicon, bytes) in [
            (
                "intel",
                false,
                include_bytes!("../../../fixtures/apple-collection/intel.plist").as_slice(),
            ),
            (
                "t2",
                false,
                include_bytes!("../../../fixtures/apple-collection/t2.plist").as_slice(),
            ),
            (
                "silicon",
                true,
                include_bytes!("../../../fixtures/apple-collection/silicon.plist").as_slice(),
            ),
        ] {
            let context = Context {
                version: Some(Version::parse("15.0").unwrap()),
                channel: Channel::Device,
                enrollment: Enrollment::Device,
                supervised: Some(true),
                automated_enrollment: Some(true),
                user_approved: Some(true),
                apple_silicon: Some(silicon),
            };
            let rights = crate::native::rights(8191);
            let target = Target {
                context: &context,
                access_rights: &rights,
            };
            let body = rss_mdm_apple_mdm::protocol::decode(bytes).unwrap();
            Command::new("SecurityInfo", Dictionary::new(), &target)
                .unwrap()
                .validate_response(&body, &target)
                .unwrap();
            let normalized = normalize(NativeAdapter::AppleSecurity, &body).unwrap();
            assert!(!normalized.to_string().contains("fixture-only"));
            assert!(!normalized.to_string().contains("RecoveryKeyCMS"));
            assert_eq!(normalized.get("IsRecoveryLockEnabled").is_some(), silicon);
            assert_eq!(normalized.get("FirmwarePasswordStatus").is_some(), !silicon);
            assert_eq!(
                normalized["SecureBoot"]["secure_boot_level"],
                if name == "intel" {
                    "not supported"
                } else {
                    "full"
                }
            );
        }
    }
}
