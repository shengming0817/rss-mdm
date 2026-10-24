use super::*;
#[test]
fn package_identities_are_format_specific() {
    assert!(
        Identity::WindowsMsi {
            product: Uuid::nil(),
            publisher: Some("RSS".into())
        }
        .validate()
        .is_err()
    );
    assert!(
        Identity::Macos {
            receipt: "com.rss.agent.pkg".into(),
            bundle: "com.rss.agent".into(),
            team: "RSS1234567".into()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn material_only_releases_do_not_invalidate_native_absence() {
    use rss_mdm_agent_wire::runtime::TaskPlatform;
    use rss_mdm_software_service::agent_packages::AdmittedPackage;
    let release = |behavior: serde_json::Value| -> AdmittedPackage {
        AdmittedPackage {
            metadata: serde_json::from_value(serde_json::json!({"releaseId":Uuid::new_v4(),"tenantId":Uuid::new_v4(),"target":{"platform":"windows","architecture":"x86_64"},"version":"1.2.3","format":"windows_msi","filename":"agent.msi","length":1,"installerSha256":vec![1;32]})).unwrap(),
            resource: "resource".into(), version: "v1".into(), variant: "default".into(), digest:[0;32], lifecycle:[0;32],
            software: serde_json::from_value(serde_json::json!({"material":{"format":"msi","installer":"package"},"source":{"id":"private","revision":"1","sha256":vec![1;32]},"package":"RSS.Agent","version":"1.2.3","artifacts":{"package":{"reference":"installer","length":1,"sha256":vec![1;32]}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":behavior,"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}})).unwrap(),
        }
    };
    let behavior = serde_json::json!({"kind":"msi","installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{12345678-1234-4234-8234-123456789abc}","version":"1.2.3"},"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}});
    let expected =
        detection_catalog(vec![release(behavior.clone())], TaskPlatform::Windows).unwrap();
    assert!(expected.complete && expected.identities.len() == 1);
    // known_in includes published and withdrawn historical material; neither has execution claims.
    let combined = detection_catalog(
        vec![release(behavior), release(serde_json::Value::Null)],
        TaskPlatform::Windows,
    )
    .unwrap();
    assert!(combined.complete);
    assert_eq!(combined.digest().unwrap(), expected.digest().unwrap());
}
