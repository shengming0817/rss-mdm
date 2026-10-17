use super::*;
#[test]
fn linked_signature_shape_and_canonicalization_use_the_real_verifier() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/windows-linked-proof.json")).unwrap();
    let at = fixture["at"].as_i64().unwrap();
    let trust = crate::DeviceTrust::new(
        serde_json::from_value(fixture["trust"].clone()).unwrap(),
        rss_mdm_agent_wire::pki::Purpose::Windows,
        at,
    )
    .unwrap();
    let ca = WindowsDeviceTrust::from_trust(trust).unwrap();
    let wire = fixture["wire"].as_str().unwrap();
    let proof = ca.linked_proof(wire.as_bytes(), at).unwrap();
    let tampered = wire.replace("TEST-DEVICE", "tampered");
    assert_ne!(tampered, wire);
    assert!(ca.linked_proof(tampered.as_bytes(), at).is_err());
    assert!(ca.linked_proof(wire.as_bytes(), at + 301).is_err());
    let original = wire.to_owned();
    let reference = r#"URI="""#;
    let negative = [
        original.replace("</s:Envelope>", "<s:Body/></s:Envelope>"),
        original.replace("</o:Security>", "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></o:Security>"),
        original.replace("linked-time", "parent-cert"),
        original.replace(reference, r#"URI="https://invalid.example/reference""#),
        original.replace("URI=\"#parent-cert\"", "URI=\"#linked-time\""),
        original.replace("rsa-sha256", "rsa-sha1"),
        original.replace("enveloped-signature", "xpath"),
        original.replace("</ds:Transforms>", "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>"),
        original.replace("</ds:SignedInfo>", "<ds:Reference URI=\"\"/></ds:SignedInfo>"),
        format!("<?fixture prohibited?>{original}"),
        original.replace("<s:Envelope", "<!DOCTYPE s:Envelope [<!ENTITY malicious SYSTEM 'file:///etc/passwd'>]><s:Envelope"),
        original.replace("</s:Body>", &format!("{}{} </s:Body>", "<nested>".repeat(65), "</nested>".repeat(65))),
        original.replace("</s:Body>", &("<node/>".repeat(4097) + "</s:Body>")),
    ];
    for (index, invalid) in negative.into_iter().enumerate() {
        assert!(
            invalid != original,
            "negative fixture mutation {index} did not apply"
        );
        assert!(
            ca.linked_proof(invalid.as_bytes(), at).is_err(),
            "unsafe signature shape {index} accepted"
        );
    }
    let attributes = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing""#;
    let reordered = original.replace(attributes, r#"xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope""#);
    assert_ne!(reordered, original);
    assert_eq!(
        ca.linked_proof(reordered.as_bytes(), at)
            .unwrap()
            .fingerprint(),
        proof.fingerprint()
    );
    assert_eq!(
        ca.linked_proof(fixture["equivalent"].as_str().unwrap().as_bytes(), at)
            .unwrap()
            .fingerprint(),
        proof.fingerprint()
    );
}
