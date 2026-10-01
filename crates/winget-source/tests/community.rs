use rss_mdm_winget_source::*;
use rss_request_context::TenantId;

fn query() -> Query {
    Query::new(
        TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
        "community",
        "Acme.App",
        "1.2",
        Architecture::X64,
        InstallerType::Exe,
        Scope::Machine,
    )
    .unwrap()
}
fn manifest() -> Vec<(String, Vec<u8>)> {
    vec![("Acme.App.yaml".into(),b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme Corporation\nPackageName: Acme Application\nLicense: Proprietary\nShortDescription: Controlled offline application\nInstallerType: exe\nScope: machine\nInstallerSwitches:\n  Silent: /quiet\nInstallers:\n  - Architecture: x64\n    InstallerUrl: https://cdn.example.test/app.exe\n    InstallerSha256: '1111111111111111111111111111111111111111111111111111111111111111'\nManifestType: singleton\nManifestVersion: 1.10.0\n".to_vec())]
}
#[test]
fn singleton_inheritance_retains_switches_and_precise_identity() {
    let value = CommunityManifest::parse(&query(), &manifest()).unwrap();
    assert_eq!(value.manifest().package(), "Acme.App");
    assert_eq!(value.manifest().sha256(), [0x11; 32]);
    assert_eq!(
        value.manifest().installer_metadata()["InstallerSwitches"]["Silent"],
        "/quiet"
    );
}
#[test]
fn multifile_and_singleton_have_the_same_effective_installer() {
    let single = CommunityManifest::parse(&query(), &manifest()).unwrap();
    let files=vec![
        ("Acme.App.yaml".into(),b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nDefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.10.0\n".to_vec()),
        ("Acme.App.installer.yaml".into(),b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nInstallerType: exe\nScope: machine\nInstallerSwitches:\n  Silent: /quiet\nInstallers:\n  - Architecture: x64\n    InstallerUrl: https://cdn.example.test/app.exe\n    InstallerSha256: '1111111111111111111111111111111111111111111111111111111111111111'\nManifestType: installer\nManifestVersion: 1.10.0\n".to_vec()),
        ("Acme.App.locale.en-US.yaml".into(),b"PackageIdentifier: Acme.App\nPackageVersion: '1.2'\nPackageLocale: en-US\nPublisher: Acme Corporation\nPackageName: Acme Application\nLicense: Proprietary\nShortDescription: Controlled offline application\nManifestType: defaultLocale\nManifestVersion: 1.10.0\n".to_vec()),
    ];
    let multi = CommunityManifest::parse(&query(), &files).unwrap();
    assert_eq!(
        single.manifest().installer_metadata(),
        multi.manifest().installer_metadata()
    );
}
#[test]
fn unknown_behavior_duplicate_roles_wrong_version_and_credentials_are_rejected() {
    for replacement in [
        (
            "Scope: machine",
            "Scope: machine\nElevationRequirement: elevationProhibited",
        ),
        ("Silent: /quiet", "Silent: /quiet\nInteractive: /wizard"),
        ("PackageVersion: '1.2'", "PackageVersion: 'latest'"),
        (
            "https://cdn.example.test/app.exe",
            "https://cdn.example.test/app.exe?token=secret",
        ),
    ] {
        let mut files = manifest();
        files[0].1 = String::from_utf8(files[0].1.clone())
            .unwrap()
            .replace(replacement.0, replacement.1)
            .into_bytes();
        assert!(CommunityManifest::parse(&query(), &files).is_err());
    }
    let mut duplicate = manifest();
    duplicate.push(duplicate[0].clone());
    assert!(CommunityManifest::parse(&query(), &duplicate).is_err());
}
