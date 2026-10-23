//! Apple's two signatures bind a server nonce, subject and encrypted response parameters.
use super::{Runtime, crypto, store::Source};
use crate::Error;
use rss_mdm_apple_mdm::platform_sso::*;
use serde_json::{Value, json};
pub(super) const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub(super) fn verify(
    runtime: &Runtime,
    device: &PublicKey,
    user: &PublicKey,
    user_id: uuid::Uuid,
    request: &str,
    server_nonce: &str,
    now: i64,
) -> Result<(String, String), Error> {
    let outer = crypto::verify(request, device, LOGIN_TYPE)?;
    let inner = crypto::verify(crypto::text(&outer, "assertion")?, user, ASSERTION_TYPE)?;
    for claims in [&outer, &inner] {
        crypto::times(claims, now)?;
        if crypto::text(claims, "request_nonce")? != server_nonce
            || crypto::text(claims, "scope")? != SCOPE
            || crypto::text(claims, "sub")? != user_id.to_string()
        {
            return Err(Error::Unauthorized);
        }
    }
    let client = runtime.configuration.client_id.to_string();
    if crypto::text(&outer, "iss")? != client
        || crypto::text(&outer, "client_id")? != client
        || crypto::text(&outer, "aud")? != runtime.endpoints.token
        || crypto::text(&outer, "username")? != user_id.to_string()
        || crypto::text(&outer, "grant_type")? != GRANT
        || crypto::text(&inner, "iss")? != user_id.to_string()
        || crypto::text(&inner, "aud")? != runtime.endpoints.issuer
    {
        return Err(Error::Unauthorized);
    }
    let nonce = crypto::text(&outer, "nonce")?;
    if nonce.len() < 16 || nonce.len() > 256 || crypto::text(&inner, "nonce")? != nonce {
        return Err(Error::Unauthorized);
    }
    let jwe = outer.get("jwe_crypto").ok_or(Error::Malformed)?;
    if crypto::text(jwe, "alg")? != "ECDH-ES" || crypto::text(jwe, "enc")? != "A256GCM" {
        return Err(Error::Malformed);
    }
    Ok((nonce.into(), crypto::text(jwe, "apv")?.into()))
}
pub(super) fn response(
    runtime: &Runtime,
    user: &Source,
    nonce: &str,
    apv: &str,
    now: i64,
    access: &str,
    refresh: &str,
) -> Result<Value, Error> {
    let subject = user.subject.as_ref().ok_or(Error::Unauthorized)?;
    let id=runtime.signer().sign("JWT",&json!({"iss":runtime.endpoints.issuer,"aud":runtime.configuration.client_id,"sub":subject.account.principal.as_uuid(),"iat":now,"exp":now+TOKEN_SECONDS,"nonce":nonce}))?;
    let payload = json!({"access_token":access,"token_type":"Bearer","expires_in":TOKEN_SECONDS,"refresh_token":refresh,"refresh_token_expires_in":SSO_SECONDS,"id_token":id,"scope":SCOPE});
    // Native refresh is another fresh SE login. An opaque refresh value carries no MFA state.
    Ok(Value::String(crypto::encrypt(
        &user.encryption,
        nonce,
        apv,
        &payload,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };
    fn key() -> (crypto::Signer, PublicKey) {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        (
            crypto::Signer::from_pem(&key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
            crypto::coordinates(&key).unwrap(),
        )
    }
    #[test]
    fn native_request_binds_both_keys_subject_audiences_and_freshness() {
        let (server, _) = key();
        let (device, device_key) = key();
        let (user, user_key) = key();
        let rt = Runtime::new(
            Configuration {
                team_id: "ABCDEFGHIJ".into(),
                extension_id: "com.rss.extension".into(),
                application_id: "com.rss.app".into(),
                application_version: "1.0".into(),
                client_id: uuid::Uuid::new_v4(),
            },
            "https://mdm.example.test",
            uuid::Uuid::new_v4(),
            "active".into(),
            [("active".into(), server)].into(),
        )
        .unwrap();
        let id = uuid::Uuid::new_v4();
        let inner = json!({"iss":id,"sub":id,"aud":rt.endpoints.issuer,"iat":1000,"exp":1300,"scope":SCOPE,"nonce":"client-nonce-123456","request_nonce":"server-nonce"});
        let mut outer = json!({"iss":rt.configuration.client_id,"client_id":rt.configuration.client_id,"aud":rt.endpoints.token,"sub":id,"username":id,"grant_type":GRANT,"iat":1000,"exp":1300,"scope":SCOPE,"nonce":"client-nonce-123456","request_nonce":"server-nonce","jwe_crypto":{"alg":"ECDH-ES","enc":"A256GCM","apv":"checked-at-encryption"}});
        outer["assertion"] = json!(user.sign(ASSERTION_TYPE, &inner).unwrap());
        let request = device.sign(LOGIN_TYPE, &outer).unwrap();
        assert!(
            verify(
                &rt,
                &device_key,
                &user_key,
                id,
                &request,
                "server-nonce",
                1000
            )
            .is_ok()
        );
        assert!(
            verify(
                &rt,
                &user_key,
                &device_key,
                id,
                &request,
                "server-nonce",
                1000
            )
            .is_err()
        );
        assert!(
            verify(
                &rt,
                &device_key,
                &user_key,
                id,
                &request,
                "other-nonce",
                1000
            )
            .is_err()
        );
        assert!(
            verify(
                &rt,
                &device_key,
                &user_key,
                id,
                &request,
                "server-nonce",
                1300
            )
            .is_err()
        );
        for (field, value) in [
            ("aud", json!(rt.endpoints.issuer)),
            ("sub", json!(uuid::Uuid::new_v4())),
            ("client_id", json!(uuid::Uuid::new_v4())),
            ("scope", json!("openid")),
            ("grant_type", json!("refresh_token")),
        ] {
            let mut bad = outer.clone();
            bad[field] = value;
            assert!(
                verify(
                    &rt,
                    &device_key,
                    &user_key,
                    id,
                    &device.sign(LOGIN_TYPE, &bad).unwrap(),
                    "server-nonce",
                    1000
                )
                .is_err(),
                "outer {field}"
            );
        }
        for (field, value) in [
            ("aud", json!(rt.endpoints.token)),
            ("iss", json!(uuid::Uuid::new_v4())),
            ("nonce", json!("different-nonce-123")),
            ("request_nonce", json!("different-server")),
            ("exp", json!(1301)),
        ] {
            let mut bad = inner.clone();
            bad[field] = value;
            let mut envelope = outer.clone();
            envelope["assertion"] = json!(user.sign(ASSERTION_TYPE, &bad).unwrap());
            assert!(
                verify(
                    &rt,
                    &device_key,
                    &user_key,
                    id,
                    &device.sign(LOGIN_TYPE, &envelope).unwrap(),
                    "server-nonce",
                    1000
                )
                .is_err(),
                "inner {field}"
            );
        }
        let mut wrong_type = outer;
        wrong_type["assertion"] = json!(user.sign(BRIDGE_TYPE, &inner).unwrap());
        assert!(
            verify(
                &rt,
                &device_key,
                &user_key,
                id,
                &device.sign(LOGIN_TYPE, &wrong_type).unwrap(),
                "server-nonce",
                1000
            )
            .is_err()
        );
    }
}
