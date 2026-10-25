use rss_mdm_agent_wire::runtime::{brew_documents_digest, winget_document_digest};
use serde_json::json;

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn manifest_digest_authenticates_the_native_document_without_its_http_envelope() {
    let manifest = json!({"Versions":[{"PackageVersion":"1","Installers":[{"Architecture":"arm64"}]}],"PackageIdentifier":"Acme.App"});
    let original = winget_document_digest(&manifest).unwrap();
    assert_eq!(
        hex(original),
        "c0203d7d54499842d0031e4e58eae43b430857c5d7e4bfec53a3174a51d95452"
    );
    let pretty = serde_json::to_string_pretty(&manifest).unwrap();
    assert_eq!(
        winget_document_digest(&serde_json::from_str(&pretty).unwrap()).unwrap(),
        original
    );
    let mut changed = manifest.clone();
    changed["Versions"][0]["PackageVersion"] = json!("2");
    assert_ne!(winget_document_digest(&changed).unwrap(), original);
    assert_ne!(
        winget_document_digest(&json!({"Data":manifest})).unwrap(),
        original
    );
    assert!(winget_document_digest(&json!([])).is_err());
}

#[test]
fn tap_digest_binds_the_complete_sorted_inventory_and_arbitrary_bytes() {
    let a = ("Casks/app.rb", &[0, 128, 255][..]);
    let b = ("Formula/tool.rb", "设备".as_bytes());
    let original = brew_documents_digest([a, b]).unwrap();
    assert_eq!(
        hex(original),
        "b149e25abde841e840c519a14fe8822b163be60f20ee02d8f142b47158305e1a"
    );
    assert_eq!(brew_documents_digest([b, a]).unwrap(), original);
    assert_ne!(brew_documents_digest([a]).unwrap(), original);
    assert_ne!(
        brew_documents_digest([("Casks/other.rb", a.1), b]).unwrap(),
        original
    );
    assert!(brew_documents_digest([a, a]).is_err());
    assert!(brew_documents_digest([]).is_err());
    assert!(brew_documents_digest([("", a.1)]).is_err());
    let paths = (0..257)
        .map(|n| format!("Formula/f{n}.rb"))
        .collect::<Vec<_>>();
    assert!(brew_documents_digest(paths.iter().map(|p| (p.as_str(), &b"x"[..]))).is_err());
}

#[test]
fn document_encoding_stops_at_the_shared_byte_budget() {
    let mut exact = json!({"x":"a".repeat(8 * 1024 * 1024 - 8)});
    assert!(winget_document_digest(&exact).is_ok());
    let serde_json::Value::String(text) = &mut exact["x"] else {
        unreachable!()
    };
    text.push('a');
    assert!(winget_document_digest(&exact).is_err());
    drop(exact);
    let bytes = vec![255; 2 * 1024 * 1024 + 1];
    assert!(brew_documents_digest([("Formula/large.rb", bytes.as_slice())]).is_err());
}
