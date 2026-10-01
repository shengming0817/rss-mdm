use rss_mdm_resource::*;
use std::collections::BTreeMap;
fn spec(adapter: NativeAdapter, query: &str) -> NativeCollectionSpec {
    NativeCollectionSpec {
        adapter,
        mappings: [(
            "device.model".into(),
            NativeMapping {
                query: query.into(),
                pointer: String::new(),
                columns: BTreeMap::new(),
            },
        )]
        .into(),
        timeout_seconds: 300,
        output_bytes: 1048576,
    }
}
#[test]
fn native_templates_are_read_only_bounded_and_platform_specific() {
    let template =
        NativeCollectionDefinition::new(spec(NativeAdapter::WindowsCsp, "./DevInfo/Mod")).unwrap();
    assert!(template.validate_platform(Platform::Windows).is_ok());
    assert!(template.validate_platform(Platform::MacOS).is_err());
    assert!(
        NativeCollectionDefinition::new(spec(NativeAdapter::WindowsCsp, "https://example.test"))
            .is_err()
    );
    assert!(
        NativeCollectionDefinition::new(spec(NativeAdapter::AppleDeviceInformation, "Model"))
            .is_ok()
    );
    assert!(
        NativeCollectionDefinition::new(spec(NativeAdapter::AppleDeviceInformation, "EraseDevice"))
            .is_err()
    );
}
