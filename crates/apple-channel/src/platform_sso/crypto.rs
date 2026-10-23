//! Apple PSSO JOSE adapter; cryptographic operations belong to OpenSSL.
//! ref: rust-openssl openssl/src/derive.rs@openssl-v0.10.81
//! ref: Apple AuthenticationServices/creating-a-json-web-encryption-jwe-login-response
use crate::Error;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as URL},
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use rss_mdm_apple_mdm::platform_sso::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn invalid<T>(_: T) -> Error {
    Error::Malformed
}
pub fn encode(bytes: &[u8]) -> String {
    URL.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() > 87384 {
        return Err(Error::Malformed);
    }
    let bytes = URL.decode(value).map_err(invalid)?;
    if encode(&bytes) != value {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
pub fn random() -> Result<String, Error> {
    let mut b = [0; 32];
    openssl::rand::rand_bytes(&mut b).map_err(invalid)?;
    Ok(encode(&b))
}
pub fn digest(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}
pub fn public(key: &PublicKey) -> Result<PKey<Public>, Error> {
    if key.kty != "EC" || key.crv != "P-256" {
        return Err(Error::Malformed);
    }
    let x = decode(&key.x)?;
    let y = decode(&key.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Malformed);
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(invalid)?;
    let mut bytes = vec![4];
    bytes.extend(x);
    bytes.extend(y);
    let mut context = BigNumContext::new().map_err(invalid)?;
    let point = EcPoint::from_bytes(&group, &bytes, &mut context).map_err(invalid)?;
    let key = EcKey::from_public_key(&group, &point).map_err(invalid)?;
    key.check_key().map_err(invalid)?;
    PKey::from_ec_key(key).map_err(invalid)
}
pub fn coordinates<T: openssl::pkey::HasPublic>(key: &PKey<T>) -> Result<PublicKey, Error> {
    let ec = key.ec_key().map_err(invalid)?;
    if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(Error::Malformed);
    }
    let mut context = BigNumContext::new().map_err(invalid)?;
    let bytes = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(invalid)?;
    if bytes.len() != 65 {
        return Err(Error::Malformed);
    }
    Ok(PublicKey {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: encode(&bytes[1..33]),
        y: encode(&bytes[33..]),
    })
}
fn point(key: &PublicKey) -> Result<Vec<u8>, Error> {
    public(key)?;
    let mut b = vec![4];
    b.extend(decode(&key.x)?);
    b.extend(decode(&key.y)?);
    Ok(b)
}
pub fn kid(key: &PublicKey) -> Result<String, Error> {
    Ok(STANDARD.encode(Sha256::digest(point(key)?)))
}

pub struct Signer {
    key: PKey<Private>,
    public: PublicKey,
    id: String,
}
impl Signer {
    pub fn from_pem(bytes: &[u8]) -> Result<Self, Error> {
        let key = PKey::private_key_from_pem(bytes).map_err(invalid)?;
        let public = coordinates(&key)?;
        let id = kid(&public)?;
        key.ec_key()
            .map_err(invalid)?
            .check_key()
            .map_err(invalid)?;
        Ok(Self { key, public, id })
    }
    pub fn jwk(&self) -> Value {
        let mut v = serde_json::to_value(&self.public).expect("public key");
        v["kid"] = json!(self.id);
        v["alg"] = json!("ES256");
        v["use"] = json!("sig");
        v
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn sign(&self, typ: &str, claims: &Value) -> Result<String, Error> {
        let input = format!(
            "{}.{}",
            encode(
                &serde_json::to_vec(&json!({"alg":"ES256","typ":typ,"kid":self.id}))
                    .map_err(invalid)?
            ),
            encode(&serde_json::to_vec(claims).map_err(invalid)?)
        );
        let signature = EcdsaSig::sign(
            &Sha256::digest(input.as_bytes()),
            self.key.ec_key().map_err(invalid)?.as_ref(),
        )
        .map_err(invalid)?;
        let mut raw = signature.r().to_vec_padded(32).map_err(invalid)?;
        raw.extend(signature.s().to_vec_padded(32).map_err(invalid)?);
        Ok(format!("{input}.{}", encode(&raw)))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
/// Parses only bounded JSON, rejects duplicate keys at every depth before claim selection.
pub fn json_unique(bytes: &[u8]) -> Result<Value, Error> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("unique JSON")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> Result<Unique, M::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some((k, v)) = map.next_entry::<String, Unique>()? {
                        if out.insert(k, v.0).is_some() {
                            return Err(serde::de::Error::custom("duplicate field"));
                        }
                    }
                    Ok(Unique(Value::Object(out)))
                }
                fn visit_seq<S: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: S,
                ) -> Result<Unique, S::Error> {
                    let mut out = Vec::new();
                    while let Some(v) = seq.next_element::<Unique>()? {
                        out.push(v.0);
                    }
                    Ok(Unique(Value::Array(out)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                    Err(serde::de::Error::custom("non-integral claim"))
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    if bytes.len() > 65536 {
        return Err(Error::Malformed);
    }
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(invalid)
}
pub fn unverified(token: &str) -> Result<(String, Value), Error> {
    if token.len() > 65536 {
        return Err(Error::Malformed);
    }
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Error::Malformed);
    }
    let header: Header =
        serde_json::from_value(json_unique(&decode(parts[0])?)?).map_err(invalid)?;
    if header.alg != "ES256" {
        return Err(Error::Unauthorized);
    }
    Ok((header.kid, json_unique(&decode(parts[1])?)?))
}
pub fn verify(token: &str, key: &PublicKey, typ: &str) -> Result<Value, Error> {
    let (_, claims) = unverified(token)?;
    let (input, signature) = token.rsplit_once('.').ok_or(Error::Malformed)?;
    let header: Header = serde_json::from_value(json_unique(&decode(
        input.split('.').next().ok_or(Error::Malformed)?,
    )?)?)
    .map_err(invalid)?;
    if header.typ != typ || header.kid != kid(key)? {
        return Err(Error::Unauthorized);
    }
    let raw = decode(signature)?;
    if raw.len() != 64 {
        return Err(Error::Unauthorized);
    }
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(&raw[..32]).map_err(invalid)?,
        BigNum::from_slice(&raw[32..]).map_err(invalid)?,
    )
    .map_err(invalid)?;
    if !signature
        .verify(
            &Sha256::digest(input.as_bytes()),
            public(key)?.ec_key().map_err(invalid)?.as_ref(),
        )
        .map_err(invalid)?
    {
        return Err(Error::Unauthorized);
    }
    Ok(claims)
}
pub fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, Error> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or(Error::Unauthorized)
}
pub fn times(v: &Value, now: i64) -> Result<(), Error> {
    let iat = v
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(Error::Unauthorized)?;
    let exp = v
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Error::Unauthorized)?;
    if iat > now
        || iat < now.saturating_sub(300)
        || exp <= now
        || exp <= iat
        || exp.saturating_sub(iat) > 300
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn part(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.extend(u32::try_from(bytes.len()).map_err(invalid)?.to_be_bytes());
    out.extend(bytes);
    Ok(())
}
fn party(prefix: &[u8], key: &PublicKey, nonce: Option<&str>) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    part(&mut b, prefix)?;
    part(&mut b, &point(key)?)?;
    if let Some(nonce) = nonce {
        part(&mut b, nonce.as_bytes())?;
    }
    Ok(b)
}
fn kdf(z: &[u8], apu: &[u8], apv: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut input = zeroize::Zeroizing::new(Vec::new());
    input.extend(1u32.to_be_bytes());
    input.extend(z);
    part(&mut input, b"A256GCM")?;
    part(&mut input, apu)?;
    part(&mut input, apv)?;
    input.extend(256u32.to_be_bytes());
    Ok(zeroize::Zeroizing::new(Sha256::digest(&*input).to_vec()))
}
pub fn encrypt<T: Serialize>(
    key: &PublicKey,
    nonce: &str,
    apv: &str,
    value: &T,
) -> Result<String, Error> {
    let apv = decode(apv)?;
    if apv != party(b"Apple", key, Some(nonce))? {
        return Err(Error::Unauthorized);
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(invalid)?;
    let ephemeral =
        PKey::from_ec_key(EcKey::generate(&group).map_err(invalid)?).map_err(invalid)?;
    let epk = coordinates(&ephemeral)?;
    let apu = party(b"APPLE", &epk, None)?;
    let peer = public(key)?;
    let mut deriver = openssl::derive::Deriver::new(&ephemeral).map_err(invalid)?;
    deriver.set_peer(&peer).map_err(invalid)?;
    let z = zeroize::Zeroizing::new(deriver.derive_to_vec().map_err(invalid)?);
    let cek = kdf(&z, &apu, &apv)?;
    let header=encode(&serde_json::to_vec(&json!({"typ":"platformsso-login-response+jwt","alg":"ECDH-ES","enc":"A256GCM","epk":epk,"apu":encode(&apu),"apv":encode(&apv)})).map_err(invalid)?);
    let mut iv = [0; 12];
    openssl::rand::rand_bytes(&mut iv).map_err(invalid)?;
    let mut tag = [0; 16];
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(invalid)?);
    let ciphertext = openssl::symm::encrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        header.as_bytes(),
        &plaintext,
        &mut tag,
    )
    .map_err(invalid)?;
    Ok(format!(
        "{header}..{}.{}.{}",
        encode(&iv),
        encode(&ciphertext),
        encode(&tag)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn signer() -> Signer {
        let g = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let k = PKey::from_ec_key(EcKey::generate(&g).unwrap()).unwrap();
        Signer::from_pem(&k.private_key_to_pem_pkcs8().unwrap()).unwrap()
    }
    #[test]
    fn signatures_bind_key_type_and_exact_bytes() {
        let a = signer();
        let b = signer();
        let token = a.sign("proof", &json!({"nonce":"123"})).unwrap();
        assert_eq!(verify(&token, &a.public, "proof").unwrap()["nonce"], "123");
        assert!(verify(&token, &b.public, "proof").is_err());
        assert!(verify(&token, &a.public, "login").is_err());
        assert!(json_unique(br#"{"a":{"x":1,"x":2}}"#).is_err());
    }
    #[test]
    fn encrypted_response_binds_recipient_and_nonce() {
        let s = signer();
        let apv = encode(&party(b"Apple", &s.public, Some("nonce")).unwrap());
        let token = encrypt(&s.public, "nonce", &apv, &json!({"id_token":"signed"})).unwrap();
        assert!(encrypt(&s.public, "other", &apv, &json!({})).is_err());
        let p = token.split('.').collect::<Vec<_>>();
        assert_eq!(p.len(), 5);
        let h: Value = serde_json::from_slice(&decode(p[0]).unwrap()).unwrap();
        let epk: PublicKey = serde_json::from_value(h["epk"].clone()).unwrap();
        let peer = public(&epk).unwrap();
        let mut d = openssl::derive::Deriver::new(&s.key).unwrap();
        d.set_peer(&peer).unwrap();
        let key = kdf(
            &d.derive_to_vec().unwrap(),
            &decode(h["apu"].as_str().unwrap()).unwrap(),
            &decode(&apv).unwrap(),
        )
        .unwrap();
        let plain = openssl::symm::decrypt_aead(
            openssl::symm::Cipher::aes_256_gcm(),
            &key,
            Some(&decode(p[2]).unwrap()),
            p[0].as_bytes(),
            &decode(p[3]).unwrap(),
            &decode(p[4]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&plain).unwrap()["id_token"],
            "signed"
        );
    }
}
