//! The fixed MS-MDE2 certificate-authenticated WSTEP signature profile.
//! ref: MS-MDE2 fdcd8fcc-4ce8-4d89-8666-26ae24e8d571;
//! KWARC/rust-libxml src/tree/{node,document}/c14n.rs.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use libxml::{parser::{Parser, ParserOptions}, tree::{Node, c14n::{CanonicalizationOptions, CanonicalizationMode}}};
use std::collections::BTreeSet;

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSSE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Private-key proof. The registration owner must resolve its fingerprint to a current parent.
pub struct LinkedProof {
    fingerprint: [u8; 32],
    replay: [u8; 32],
}
impl LinkedProof {
    pub fn fingerprint(&self) -> [u8; 32] { self.fingerprint }
    pub fn replay(&self) -> [u8; 32] { self.replay }
}
fn is(node: &Node, ns: &str, name: &str) -> bool {
    node.get_name() == name && node.get_namespace().is_some_and(|n| n.get_href() == ns)
}
fn child(node: &Node, ns: &str, name: &str) -> Result<Node, Error> {
    let mut children = node.get_child_elements().into_iter().filter(|n| is(n, ns, name));
    let found = children.next().ok_or(Error::Unauthorized)?;
    if children.next().is_some() { return Err(Error::Unauthorized); }
    Ok(found)
}
fn algorithm(node: &Node, expected: &str) -> Result<(), Error> {
    if node.get_property_no_ns("Algorithm").as_deref() != Some(expected)
        || !node.get_child_elements().is_empty()
    { return Err(Error::Unauthorized); }
    Ok(())
}
fn decode(node: &Node) -> Result<Vec<u8>, Error> {
    if !node.get_child_elements().is_empty() { return Err(Error::Unauthorized); }
    STANDARD.decode(node.get_content().split_whitespace().collect::<String>()).map_err(|_| Error::Unauthorized)
}
impl WindowsEnrollmentAuthority {
    /// Verify the original DOM, never a reconstructed SOAP fragment or a KeyInfo-selected key.
    pub fn linked_proof(&self, xml: &[u8], now: i64) -> Result<LinkedProof, Error> {
        // Preflight before libxml: forbid DTD/entity loading, alternate encodings and bound depth.
        if xml.len() > 1024 * 1024 || std::str::from_utf8(xml).is_err() { return Err(Error::Unauthorized); }
        let mut reader = quick_xml::Reader::from_reader(xml);
        let (mut depth, mut nodes) = (0u32, 0u32);
        loop {
            use quick_xml::events::Event;
            match reader.read_event().map_err(|_| Error::Unauthorized)? {
                Event::DocType(_) | Event::PI(_) => return Err(Error::Unauthorized),
                Event::Decl(d) if d.encoding().is_some_and(|e| e.map_or(true, |e| !e.eq_ignore_ascii_case("utf-8"))) => return Err(Error::Unauthorized),
                Event::Start(_) => { depth += 1; nodes += 1; },
                Event::Empty(_) => nodes += 1,
                Event::End(_) => depth = depth.checked_sub(1).ok_or(Error::Unauthorized)?,
                Event::Eof => break,
                _ => {},
            }
            if depth > 64 || nodes > 4096 { return Err(Error::Unauthorized); }
        }
        let document = Parser::default().parse_string_with_options(xml, ParserOptions {
            recover: false, no_net: true, no_def_dtd: true, ..ParserOptions::default()
        }).map_err(|_| Error::Unauthorized)?;
        let root = document.get_root_element().ok_or(Error::Unauthorized)?;
        if !is(&root, SOAP, "Envelope") || root.get_child_elements().len() != 2 { return Err(Error::Unauthorized); }
        let header = child(&root, SOAP, "Header")?;
        child(&root, SOAP, "Body")?;
        let security = child(&header, WSSE, "Security")?;
        let mut signature_node = child(&security, DS, "Signature")?;
        let token = child(&security, WSSE, "BinarySecurityToken")?;
        if token.get_property_no_ns("ValueType").as_deref() != Some("http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentUserToken")
            || token.get_property_no_ns("EncodingType").as_deref() != Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary")
        { return Err(Error::Unauthorized); }
        let timestamp = child(&security, WSU, "Timestamp")?;
        let parse_time = |n: Node| time::OffsetDateTime::parse(&n.get_content(), &time::format_description::well_known::Rfc3339).map(|v| v.unix_timestamp()).map_err(|_| Error::Unauthorized);
        let created = parse_time(child(&timestamp, WSU, "Created")?)?;
        let expires = parse_time(child(&timestamp, WSU, "Expires")?)?;
        if timestamp.get_child_elements().len() != 2 || created < now - 300 || created > now + 30 || expires <= now || expires <= created || expires - created > 300 { return Err(Error::Unauthorized); }
        let mut pending = vec![root];
        let (mut ids, mut signatures, mut tokens) = (BTreeSet::new(), 0, 0);
        while let Some(n) = pending.pop() {
            signatures += usize::from(is(&n, DS, "Signature"));
            tokens += usize::from(is(&n, WSSE, "BinarySecurityToken"));
            for ((name, _), value) in n.get_properties_ns() {
                if name.eq_ignore_ascii_case("id") && (value.is_empty() || !ids.insert(value)) { return Err(Error::Unauthorized); }
            }
            pending.extend(n.get_child_elements());
        }
        if signatures != 1 || tokens != 2 { return Err(Error::Unauthorized); }
        let key_info = child(&signature_node, DS, "KeyInfo")?;
        let token_reference = child(&key_info, WSSE, "SecurityTokenReference")?;
        let key_reference = child(&token_reference, WSSE, "Reference")?;
        let token_id = token.get_property_ns("Id", WSU).ok_or(Error::Unauthorized)?;
        if signature_node.get_child_elements().len() != 3 || key_info.get_child_elements().len() != 1 || token_reference.get_child_elements().len() != 1
            || key_reference.get_property_no_ns("URI") != Some(format!("#{token_id}"))
            || key_reference.get_property_no_ns("ValueType").as_deref() != Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509")
        { return Err(Error::Unauthorized); }
        let mut info = child(&signature_node, DS, "SignedInfo")?;
        if info.get_child_elements().len() != 3 { return Err(Error::Unauthorized); }
        algorithm(&child(&info, DS, "CanonicalizationMethod")?, C14N)?;
        algorithm(&child(&info, DS, "SignatureMethod")?, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")?;
        let reference = child(&info, DS, "Reference")?;
        if reference.get_property_no_ns("URI").as_deref() != Some("") || reference.get_child_elements().len() != 3 { return Err(Error::Unauthorized); }
        let transforms = child(&reference, DS, "Transforms")?.get_child_elements();
        if transforms.is_empty() || transforms.len() > 2 || transforms.iter().any(|n| !is(n, DS, "Transform")) { return Err(Error::Unauthorized); }
        algorithm(&transforms[0], "http://www.w3.org/2000/09/xmldsig#enveloped-signature")?;
        if transforms.len() == 2 { algorithm(&transforms[1], C14N)?; }
        algorithm(&child(&reference, DS, "DigestMethod")?, "http://www.w3.org/2001/04/xmlenc#sha256")?;
        let digest = decode(&child(&reference, DS, "DigestValue")?)?;
        let signature = decode(&child(&signature_node, DS, "SignatureValue")?)?;
        let cert_der = decode(&token)?;
        let checked = self.verify(&[CertificateDer::from(cert_der.as_slice())], now)?;
        let certificate = Certificate::from_der(&cert_der).map_err(|_| Error::Unauthorized)?;
        if !rsa_algorithm(&certificate.tbs_certificate.subject_public_key_info.algorithm, RSA) { return Err(Error::Unauthorized); }
        let signed_info = info.canonicalize(CanonicalizationOptions::default()).map_err(|_| Error::Unauthorized)?;
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,
            certificate.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes().ok_or(Error::Unauthorized)?)
            .verify(signed_info.as_bytes(), &signature).map_err(|_| Error::Unauthorized)?;
        signature_node.unlink();
        let canonical = document.canonicalize(CanonicalizationOptions { mode: if transforms.len() == 1 { CanonicalizationMode::Canonical1_0 } else { CanonicalizationMode::ExclusiveCanonical1_0 }, ..Default::default() }, None).map_err(|_| Error::Unauthorized)?;
        if digest.as_slice() != Sha256::digest(canonical.as_bytes()).as_slice() { return Err(Error::Unauthorized); }
        Ok(LinkedProof { fingerprint: checked.fingerprint(), replay: Sha256::digest(xml).into() })
    }
}
