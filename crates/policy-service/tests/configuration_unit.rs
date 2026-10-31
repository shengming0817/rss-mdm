use serde_json::json;
#[test]
fn configuration_cannot_withdraw_a_different_native_object_or_claim_a_query() {
    let make = |uri: &str, operation: &str| json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":uri,"instance":[],"operation":operation,"value":null}}});
    let a = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana";
    let b = "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera";
    let invalid: crate::configuration::Configuration = serde_json::from_value(
        json!({"target":{"kind":"device"},"apply":make(a,"delete"),"remove":make(b,"delete")}),
    )
    .unwrap();
    assert!(
        invalid.validate().is_err(),
        "withdrawal must not touch another owner's object"
    );
    let query: crate::configuration::Configuration = serde_json::from_value(
        json!({"target":{"kind":"device"},"apply":make(a,"get"),"remove":null}),
    )
    .unwrap();
    assert!(
        query.validate().is_err(),
        "reading state does not confer configuration ownership"
    );
}
#[test]
fn native_configuration_is_not_a_software_admission_bypass() {
    let input:crate::configuration::Configuration=serde_json::from_value(json!({"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/*/DownloadInstall","instance":["{11111111-1111-4111-8111-111111111111}"],"operation":"add","value":{"type":"xml","value":"<MsiInstallJob/>"}}}},"remove":null})).unwrap();
    assert!(input.validate().is_err());
}

#[test]
fn native_parent_and_child_claims_overlap_only_on_same_scope_and_segment_boundaries() {
    use crate::configuration::Object;
    let object = |key: &str, user: &str| Object {
        platform: "windows".into(),
        kind: "csp".into(),
        key: key.into(),
        user: user.into(),
    };
    let parent = object("./Vendor/MSFT/WiFi/Profile/one", "");
    let child = object("./Vendor/MSFT/WiFi/Profile/one/Proxy", "");
    assert!(parent.overlaps(&child));
    assert!(child.overlaps(&parent));
    assert!(!parent.overlaps(&object("./Vendor/MSFT/WiFi/Profile/one-two/Proxy", "")));
    assert!(!parent.overlaps(&object(
        "./Vendor/MSFT/WiFi/Profile/one/Proxy",
        "different-user"
    )));
}
#[test]
fn ordinary_ddm_configuration_cannot_replace_credential_escrow_recipient() {
    let make = |schema: &str| -> crate::configuration::Configuration {
        serde_json::from_value(json!({"target":{"kind":"device"},"apply":{"platform":"macos","request":{"kind":"declarations","declarations":[{"identifier":"legacy","declarationType":"com.apple.configuration.legacy","payload":{}}],"assets":[{"identifier":"legacy","resource":"profile","version":"v1","variant":"default","versionDigest":vec![1u8;32],"contentType":"application/x-apple-aspen-config","profileSchemas":[schema]}]}},"remove":null})).unwrap()
    };
    assert!(
        make("mdm/profiles/com.apple.security.firewall.yaml")
            .validate()
            .is_ok()
    );
    assert!(matches!(
        make("mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml").validate(),
        Err(crate::Error::Unsupported)
    ));
}

#[test]
fn apple_status_blueprints_are_real_native_configurations() {
    use rss_mdm_resource::blueprints::{self, Definition};
    for blueprint in blueprints::catalog()
        .into_iter()
        .filter(|b| b.id.starts_with("macos.ddm."))
    {
        let Definition::Configuration { content } = blueprint.definition else {
            panic!("DDM configuration");
        };
        let configuration: crate::configuration::Configuration =
            serde_json::from_value(serde_json::to_value(content).unwrap()).unwrap();
        configuration.validate().unwrap();
        assert!(!configuration.objects().unwrap().is_empty());
        use rss_mdm_apple_mdm::{
            applicability::{Channel, Context, Enrollment, Version},
            native::{Target, ddm::DeclarationSet, request::Request},
        };
        let context = Context {
            version: Some(Version::parse("27.0").unwrap()),
            channel: Channel::Device,
            enrollment: Enrollment::Device,
            supervised: Some(true),
            automated_enrollment: Some(true),
            user_approved: Some(true),
            apple_silicon: Some(true),
        };
        let target = Target {
            context: &context,
            access_rights: &[],
        };
        let crate::configuration::Task::Macos {
            request: Request::Declarations { declarations, .. },
        } = configuration.apply
        else {
            panic!("native declaration");
        };
        let compiled = declarations
            .iter()
            .map(|d| d.compile("v2", &target))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{}: {e:?}", blueprint.id));
        DeclarationSet::new("fixture", compiled).unwrap();
    }
}
