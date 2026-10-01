use rss_mdm_brew_source::*;
use rss_request_context::TenantId;
fn key() -> PackageKey {
    PackageKey::new(
        TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
        "acme/private",
        "app",
    )
    .unwrap()
}
fn cask() -> String {
    format!(
        "cask \"app\" do\n  version \"1.2\"\n  sha256 \"{}\"\n  url \"https://cdn.example.test/app.dmg\"\n  name \"Application\"\n  desc \"Controlled application\"\n  homepage \"https://example.test/\"\n  app \"App.app\"\nend\n",
        "11".repeat(32)
    )
}
#[test]
fn literal_cask_is_imported_without_evaluating_ruby() {
    let value = TapImport::parse(&key(), "1.2", BottleTag::Arm64Sonoma, cask().as_bytes()).unwrap();
    assert_eq!(value.version(), "1.2");
    assert!(matches!(value.payload(), TapPayload::Cask { .. }));
}
#[test]
fn every_unknown_hook_interpolation_and_source_build_is_rejected() {
    for statement in [
        "  postflight do\n    system \"bad\"\n  end\n",
        "  zap trash: \"~/Library/App\"\n",
        "  service do\n    run \"bad\"\n  end\n",
    ] {
        let input = cask().replace(
            "  app \"App.app\"",
            &(statement.to_owned() + "  app \"App.app\""),
        );
        assert!(TapImport::parse(&key(), "1.2", BottleTag::Arm64Sonoma, input.as_bytes()).is_err());
    }
    let dynamic = cask().replace(
        "https://cdn.example.test/app.dmg",
        "https://cdn.example.test/#{system('bad')}.dmg",
    );
    assert!(TapImport::parse(&key(), "1.2", BottleTag::Arm64Sonoma, dynamic.as_bytes()).is_err());
    assert!(TapImport::parse(&key(), "latest", BottleTag::Arm64Sonoma, cask().as_bytes()).is_err());
}
#[test]
fn bottle_identity_and_prebuilt_behavior_are_fixed() {
    let input = format!(
        "class App < Formula\n  version \"1.2\"\n  desc \"Controlled tool\"\n  homepage \"https://example.test/\"\n  url \"https://cdn.example.test/app-source.tar.gz\"\n  sha256 \"{}\"\n  bottle do\n    root_url \"https://cdn.example.test/bottles\"\n    sha256 cellar: :any_skip_relocation, arm64_sonoma: \"{}\"\n  end\n  def install\n    bin.install \"app\"\n  end\nend\n",
        "11".repeat(32),
        "22".repeat(32)
    );
    let value = TapImport::parse(&key(), "1.2", BottleTag::Arm64Sonoma, input.as_bytes()).unwrap();
    assert!(matches!(value.payload(), TapPayload::Bottle { .. }));
    let build = input.replace("bin.install \"app\"", "system \"make\"");
    assert!(TapImport::parse(&key(), "1.2", BottleTag::Arm64Sonoma, build.as_bytes()).is_err());
}

#[test]
fn exported_formula_has_no_source_install_fallback() {
    let formula = Formula::new(
        key(),
        "1.2",
        BottleLayout {
            revision: 0,
            rebuild: 0,
        },
        "Controlled tool",
        "https://example.test/",
        Artifact::new("https://cdn.example.test/source.tar.gz", [1; 32]).unwrap(),
        "app",
        vec![
            Bottle::new(
                BottleTag::Arm64Sonoma,
                "https://cdn.example.test/bottles",
                [2; 32],
                Cellar::AnySkipRelocation,
            )
            .unwrap(),
        ],
        vec![],
    )
    .unwrap();
    let doc = formula.render().unwrap();
    let source = std::str::from_utf8(doc.bytes()).unwrap();
    assert!(source.contains("RSS bottle-only: source installation is unsupported"));
    assert!(!source.contains("bin.install"));
}
