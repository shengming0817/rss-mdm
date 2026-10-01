use rss_mdm_software_service::catalog::SourceDefinition;
use serde_json::json;

#[test]
fn sources_are_distinct_closed_current_protocols_without_credentials() {
    for protocol in [
        json!({"kind":"private"}),
        json!({"kind":"winget_rest","location":"https://source.example.test/feed/","identifier":"enterprise-feed"}),
        json!({"kind":"winget_community","repository":"https://github.com/microsoft/winget-pkgs.git","commit":"3119f00ff5be7f34f85e16158dae2f70d1a2ee04"}),
        json!({"kind":"brew_tap","repository":"https://github.com/Homebrew/homebrew-cask.git","tap":"homebrew/cask","commit":"7cce6eac8d897b0b8440e16f33dbcb21770da7cf"}),
    ] {
        let input = json!({"id":"enterprise","revision":"1","protocol":protocol});
        let definition: SourceDefinition = serde_json::from_value(input.clone()).unwrap();
        definition.snapshot().unwrap();
        let mut old = input;
        old["location"] = json!(null);
        assert!(serde_json::from_value::<SourceDefinition>(old).is_err());
    }
}

#[test]
fn source_credentials_and_floating_commits_cannot_enter_the_snapshot() {
    for (repository, commit) in [
        ("https://github.com/Homebrew/homebrew-cask.git", "latest"),
        (
            "https://user:secret@github.com/Homebrew/homebrew-cask.git",
            "7cce6eac8d897b0b8440e16f33dbcb21770da7cf",
        ),
        (
            "https://github.com/Homebrew/homebrew-cask.git?token=secret",
            "7cce6eac8d897b0b8440e16f33dbcb21770da7cf",
        ),
    ] {
        let input = json!({"id":"enterprise","revision":"1","protocol":{"kind":"brew_tap","repository":repository,"tap":"homebrew/cask","commit":commit}});
        let definition: SourceDefinition = serde_json::from_value(input).unwrap();
        assert!(definition.snapshot().is_err());
    }
}
