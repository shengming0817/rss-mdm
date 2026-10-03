use rss_mdm_resource::{Architecture, Platform, SoftwareDefinition};
use serde_json::{Value, json};

fn invocation() -> Value {
    json!({"runAs":"system","arguments":["/quiet"],"environment":{},"timeoutSeconds":600,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[3010]}})
}
fn definition(behavior: Value, version: &str) -> Value {
    json!({"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"Acme.App","version":version,"provenance":{"kind":"private"},"artifacts":{"installer":{"reference":"installer","origin":null,"length":3,"sha256":vec![2;32]}},"behavior":behavior,"signatures":[],"reboot":"report","downgrade":"deny","dependencies":[],"export":{"kind":"disabled"}})
}
fn exe() -> Value {
    definition(
        json!({"kind":"exe","installer":"installer","scope":"system","install":invocation(),"upgrade":"in_place","uninstall":null,"layout":{"setup.exe":"installer"},"detect":{"kind":"registry","scope":"system","key":"Software\\Acme\\App","value":"Version","version":"1.0"},"upgradeInvocation":invocation()}),
        "1.0",
    )
}

#[test]
fn unsigned_offline_exe_is_valid_and_every_behavior_change_is_frozen() {
    let original: SoftwareDefinition = serde_json::from_value(exe()).unwrap();
    original
        .validate_target(Platform::Windows, Architecture::X86_64)
        .unwrap();
    assert!(
        original
            .validate_target(Platform::MacOS, Architecture::X86_64)
            .is_err()
    );
    for (path, replacement) in [
        (
            "/behavior/upgradeInvocation/arguments",
            json!(["/upgrade-only"]),
        ),
        ("/behavior/install/arguments", json!(["/unattended"])),
        ("/behavior/layout", json!({"private/setup.exe":"installer"})),
        ("/behavior/install/exitCodes/reboot", json!([1641])),
        ("/behavior/upgrade", json!("deny")),
    ] {
        let mut input = exe();
        *input.pointer_mut(path).unwrap() = replacement;
        let changed: SoftwareDefinition = serde_json::from_value(input).unwrap();
        assert_ne!(original.canonical(), changed.canonical(), "{path}");
    }
}

#[test]
fn old_shape_mixed_payload_and_undeclared_offline_content_are_rejected() {
    for mutate in [
        |v: &mut Value| {
            v["format"] = json!("exe");
        },
        |v: &mut Value| {
            v["behavior"]["executor"] = json!("powershell7");
        },
        |v: &mut Value| {
            v["behavior"]["layout"] = json!({"setup.exe":"missing"});
        },
        |v: &mut Value| {
            v["behavior"]["layout"] = json!({"../setup.exe":"installer"});
        },
        |v: &mut Value| {
            v["behavior"]["install"]["exitCodes"]["reboot"] = json!([0]);
        },
        |v: &mut Value| {
            v["behavior"]["install"]["runAs"] = json!("logged_in_user");
        },
    ] {
        let mut input = exe();
        mutate(&mut input);
        assert!(serde_json::from_value::<SoftwareDefinition>(input).is_err());
    }
}

fn native_budget() -> Value {
    let mut v = invocation();
    v["arguments"] = json!([]);
    v
}
fn msix(deployment: Value, bundle: bool) -> Value {
    let identity = json!({"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"x86_64","resourceId":""});
    let container = if bundle {
        json!({"kind":"bundle","installer":"installer","members":[{"path":"Acme.x64.msix","identity":identity,"length":3,"sha256":vec![2;32]}]})
    } else {
        json!({"kind":"package","installer":"installer"})
    };
    let mut invocation = native_budget();
    if deployment["kind"] == "target_user_registration" {
        invocation["runAs"] = json!("logged_in_user");
    }
    definition(
        json!({"kind":"msix","container":container,"identity":identity,"dependencies":[],"deployment":deployment,"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":true,"invocation":invocation,"upgrade":"in_place"}),
        "1.0.0.0",
    )
}

#[test]
fn dmg_explicit_app_and_pkg_payloads_are_distinct_frozen_forms() {
    let app = json!({"kind":"app_copy","application":{"path":"Applications/企业.app","bundleId":"com.acme.app","version":"1.0","targetName":"企业.app"},"uninstall":true});
    let pkg = json!({"kind":"contained_pkg","path":"Packages/Acme.pkg","length":123,"sha256":vec![3;32],"receipt":"com.acme.app","uninstall":null});
    for payload in [app, pkg] {
        let input = definition(
            json!({"kind":"dmg","image":"installer","volume":"Acme","scope":"system","invocation":native_budget(),"upgrade":"in_place","payload":payload}),
            "1.0",
        );
        let value: SoftwareDefinition = serde_json::from_value(input.clone()).unwrap();
        value
            .validate_target(Platform::MacOS, Architecture::Aarch64)
            .unwrap();
        assert!(
            value
                .validate_target(Platform::Windows, Architecture::Aarch64)
                .is_err()
        );
        let mut bad = input;
        if bad["behavior"]["payload"]["kind"] == "app_copy" {
            bad["behavior"]["payload"]["application"]["path"] = json!("../escape.app");
        } else {
            bad["behavior"]["payload"]["path"] = json!("../escape.pkg");
        }
        assert!(serde_json::from_value::<SoftwareDefinition>(bad).is_err());
    }
}

#[test]
fn msix_user_registration_and_device_provisioning_have_distinct_material() {
    let user = msix(
        json!({"kind":"target_user_registration","target":{"kind":"exact","identity":"S-1-5-21-100-200-300-1001"}}),
        false,
    );
    let provision = msix(json!({"kind":"device_provisioning"}), false);
    let a: SoftwareDefinition = serde_json::from_value(user).unwrap();
    let b: SoftwareDefinition = serde_json::from_value(provision).unwrap();
    assert_ne!(a.canonical(), b.canonical());
    a.validate_target(Platform::Windows, Architecture::X86_64)
        .unwrap();
    assert!(
        a.validate_target(Platform::Windows, Architecture::Aarch64)
            .is_err()
    );
    let bundle = msix(json!({"kind":"device_provisioning"}), true);
    let _: SoftwareDefinition = serde_json::from_value(bundle.clone()).unwrap();
    for mutate in [
        |v: &mut Value| {
            v["behavior"]["container"]["members"][0]["identity"]["publisher"] = json!("CN=Other");
        },
        |v: &mut Value| {
            let extra = v["behavior"]["container"]["members"][0].clone();
            v["behavior"]["container"]["members"]
                .as_array_mut()
                .unwrap()
                .push(extra);
        },
        |v: &mut Value| {
            v["behavior"]["allowUnsigned"] = json!(true);
        },
    ] {
        let mut bad = bundle.clone();
        mutate(&mut bad);
        assert!(serde_json::from_value::<SoftwareDefinition>(bad).is_err());
    }
}
#[test]
fn msix_bundle_resource_members_may_be_neutral_but_must_share_the_application_identity() {
    let mut input = msix(json!({"kind":"device_provisioning"}), true);
    let resource = json!({"path":"Acme.language.msix","identity":{"name":"Acme.App","publisher":"CN=Acme","version":[1,0,0,0],"architecture":"neutral","resourceId":"en-us"},"length":8,"sha256":vec![3;32]});
    input["behavior"]["container"]["members"]
        .as_array_mut()
        .unwrap()
        .push(resource);
    let valid: SoftwareDefinition = serde_json::from_value(input.clone()).unwrap();
    valid
        .validate_target(Platform::Windows, Architecture::X86_64)
        .unwrap();
    input["behavior"]["container"]["members"][1]["identity"]["publisher"] = json!("CN=Other");
    assert!(serde_json::from_value::<SoftwareDefinition>(input).is_err());
}

#[test]
fn current_native_behavior_requires_explicit_removal_support() {
    let mut input = exe();
    input["behavior"]
        .as_object_mut()
        .unwrap()
        .remove("uninstall");
    assert!(serde_json::from_value::<SoftwareDefinition>(input).is_err());
}

#[test]
fn app_copy_rejects_retired_directory_digest_including_null() {
    let input = definition(
        json!({"kind":"dmg","image":"installer","volume":"Acme","scope":"system","invocation":native_budget(),"upgrade":"in_place","payload":{"kind":"app_copy","application":{"path":"Acme.app","targetName":"Acme.app","bundleId":"com.acme.app","version":"1.0"},"uninstall":true}}),
        "1.0",
    );
    let definition: SoftwareDefinition = serde_json::from_value(input.clone()).unwrap();
    definition
        .validate_target(Platform::MacOS, Architecture::Aarch64)
        .unwrap();
    for digest in [json!(vec![2; 32]), json!(null)] {
        let mut old = input.clone();
        old["behavior"]["payload"]["application"]["materialSha256"] = digest;
        assert!(serde_json::from_value::<SoftwareDefinition>(old).is_err());
    }
}
