use super::*;
#[test]
fn signed_csr_requires_strong_rsa_sha256_and_exact_der() {
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509NameBuilder, X509Req},
    };
    for (bits, digest, valid) in [
        (2048, MessageDigest::sha256(), true),
        (1024, MessageDigest::sha256(), false),
        (2048, MessageDigest::sha1(), false),
    ] {
        let key = PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "device").unwrap();
        let mut request = X509Req::builder().unwrap();
        request.set_subject_name(&name.build()).unwrap();
        request.set_pubkey(&key).unwrap();
        request.sign(&key, digest).unwrap();
        let bytes = request.build().to_der().unwrap();
        assert_eq!(Csr::verify(&bytes).is_ok(), valid);
        if valid {
            let mut absent = CertReq::from_der(&bytes).unwrap();
            absent.algorithm.parameters = None;
            assert!(Csr::verify(&absent.to_der().unwrap()).is_ok());
            let mut tail = bytes.clone();
            tail.push(0);
            assert!(matches!(Csr::verify(&tail), Err(Error::CertificateRequest)));
            let mut damaged = bytes;
            *damaged.last_mut().unwrap() ^= 1;
            assert!(matches!(
                Csr::verify(&damaged),
                Err(Error::CertificateRequest)
            ));
        }
    }
}
#[test]
fn linked_signature_shape_and_canonicalization_use_the_real_verifier() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/windows-linked-proof.json")).unwrap();
    let at = fixture["at"].as_i64().unwrap();
    let trust = rss_mdm_device_trust::DeviceTrust::new(
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
