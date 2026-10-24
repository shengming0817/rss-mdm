//! Native Password protocol against a real native Keycloak password account.
use super::*;
const PASSWORD: &str = "Native-platform-password-2026!";
pub(super) struct Fixture {
    directory: tempfile::TempDir,
    provider: Uuid,
    issuer: String,
    subject: String,
    ca: std::path::PathBuf,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let issuer = std::env::var("MDM_TEST_SSO_ISSUER")?;
        let ca = std::path::PathBuf::from(std::env::var("MDM_TEST_SSO_CA")?);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(&ca)?)?)
            .build()?;
        let origin = issuer.trim_end_matches("/realms/mdm");
        let token: Value = client
            .post(format!(
                "{origin}/realms/master/protocol/openid-connect/token"
            ))
            .form(&[
                ("client_id", "admin-cli"),
                ("grant_type", "password"),
                ("username", "fixture-operator"),
                ("password", "fixture-operator-password"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let token = zeroize::Zeroizing::new(
            token["access_token"]
                .as_str()
                .context("admin token")?
                .to_owned(),
        );
        let base = format!("{origin}/admin/realms/mdm");
        client.post(format!("{base}/clients")).bearer_auth(token.as_str()).json(&json!({"clientId":"mdm-password","enabled":true,"protocol":"openid-connect","publicClient":false,"secret":"fixture-password-client","directAccessGrantsEnabled":true,"standardFlowEnabled":false,"protocolMappers":[{"name":"password-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"mdm-password","access.token.claim":"true","id.token.claim":"false"}}]})).send().await?.error_for_status()?;
        client.post(format!("{base}/users")).bearer_auth(token.as_str()).json(&json!({"username":"native-password","enabled":true,"firstName":"Native","lastName":"Password","email":"native@example.test","emailVerified":true,"credentials":[{"type":"password","value":PASSWORD,"temporary":false}]})).send().await?.error_for_status()?;
        let users: Value = client
            .get(format!("{base}/users?username=native-password&exact=true"))
            .bearer_auth(token.as_str())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let subject = users[0]["id"]
            .as_str()
            .context("stable native subject")?
            .to_owned();
        let directory = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(directory.path().join("secret"), "fixture-password-client")?;
        std::fs::set_permissions(
            directory.path().join("secret"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        Ok(Self {
            directory,
            provider: Uuid::new_v4(),
            issuer,
            subject,
            ca,
        })
    }
    pub(super) fn configuration(&self) -> Result<config::PlatformSso> {
        let mut configuration = super::configuration(self.directory.path())?;
        let url = url::Url::parse(&self.issuer)?;
        configuration
            .password_providers
            .push(config::PasswordProvider {
                configuration:
                    rss_mdm_apple_channel::platform_sso::password_provider::Configuration {
                        id: self.provider,
                        revision: 1,
                        issuer: self.issuer.clone(),
                        client_id: "mdm-password".into(),
                        addresses: vec![
                            format!("127.0.0.1:{}", url.port_or_known_default().context("port")?)
                                .parse()?,
                        ],
                    },
                client_secret_file: self.directory.path().join("secret"),
                private_ca_file: Some(self.ca.clone()),
            });
        Ok(configuration)
    }
    pub(super) fn login(&self) -> rss_mdm_agent_wire::platform_sso::LoginConfiguration {
        rss_mdm_agent_wire::platform_sso::LoginConfiguration {
            authentication: rss_mdm_agent_wire::platform_sso::AuthenticationMode::Password,
            password_provider: Some(self.provider),
            ..Default::default()
        }
    }
    pub(super) async fn mapping(&self, binding: Uuid) -> Result<()> {
        // Stable pre-provisioned mapping. Enterprise management CAS/step-up is covered by its HTTP test.
        let mut c =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let mut tx = c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(case_tenant())
            .execute(&mut *tx)
            .await?;
        let person:Value=sqlx::query_scalar("SELECT document->'person' FROM mdm_access.device_access_bindings WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(binding).fetch_one(&mut *tx).await?;
        let document = json!({"provider":self.provider,"person":person,"revision":1,"enabled":true,"subject":self.subject,"username":"native-password"});
        let principal: Uuid = serde_json::from_value(person["principal"].clone())?;
        sqlx::query("INSERT INTO mdm_enterprise.subjects(tenant_id,provider,principal,revision,document) VALUES($1::uuid,$2,$3,1,$4)").bind(case_tenant()).bind(self.provider).bind(principal).bind(&document).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_enterprise.subject_versions(tenant_id,provider,principal,revision,document) VALUES($1::uuid,$2,$3,1,$4)").bind(case_tenant()).bind(self.provider).bind(principal).bind(document).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_enterprise.subject_owners(tenant_id,provider,principal,subject) VALUES($1::uuid,$2,$3,$4)").bind(case_tenant()).bind(self.provider).bind(principal).bind(&self.subject).execute(&mut *tx).await?;
        tx.commit().await?;
        c.close().await?;
        Ok(())
    }
}
pub(super) fn copy_key(key: &Key) -> Result<Key> {
    let pem = zeroize::Zeroizing::new(key.private.private_key_to_pem_pkcs8()?);
    Ok(Key {
        private: PKey::private_key_from_pem(&pem)?,
        signer: crypto::Signer::from_pem(&pem)?,
        public: key.public.clone(),
    })
}
pub(super) async fn register_user(
    f: &super::Fixture,
    binding: Option<Uuid>,
    registration: Uuid,
    signing: &Key,
    encryption: &Key,
    password: bool,
) -> Result<Value> {
    if !password {
        return register_key(f, "user", binding, registration, signing, encryption).await;
    }
    let (status,challenge)=agent(f,"bootstrap",json!({"operationId":Uuid::new_v4(),"kind":"user","bindingId":binding,"bindingGeneration":1})).await?;
    ensure!(
        status == StatusCode::OK,
        "Password registration challenge {status}: {challenge}"
    );
    let now = f.app.clock.unix_seconds()?;
    let proof=signing.signer.sign("rss-mdm-platform-sso-registration+jwt",&json!({"iss":registration,"aud":format!("{}/register",challenge["endpoints"]["base"].as_str().context("base")?),"challengeId":challenge["id"],"sourceId":challenge["sourceId"],"sourceVersion":challenge["sourceVersion"],"nonce":challenge["nonce"],"encryptionKeyId":crypto::kid(&encryption.public)?,"iat":now,"exp":now+120}))?;
    let input = json!({"operationId":Uuid::new_v4(),"challengeId":challenge["id"],"signingKey":null,"encryptionKey":encryption.public,"proof":proof});
    let reply = agent(f, "register", input.clone()).await?;
    ensure!(reply.0 == StatusCode::OK, "Password register {reply:?}");
    ensure!(!agent(f, "register", input).await?.0.is_success());
    Ok(reply.1)
}
async fn request(
    f: &super::Fixture,
    device: &Key,
    encryption: &Key,
    id: &Value,
    password: &str,
) -> Result<String> {
    use rss_mdm_agent_wire::platform_sso::{LOGIN_TYPE, SCOPE};
    let rt = f.ade.platform_sso.as_ref().context("PSSO")?;
    let (status, nonce) = call(
        f,
        &format!("/api/v1/apple/platform-sso/{}/nonce", case_tenant()),
        json!({}),
    )
    .await?;
    ensure!(status == StatusCode::OK);
    let now = f.app.clock.unix_seconds()?;
    let client_nonce = Uuid::new_v4().to_string();
    device.signer.sign(LOGIN_TYPE,&json!({"iss":rt.configuration.client_id,"client_id":rt.configuration.client_id,"aud":rt.endpoints.token,"sub":id,"username":id,"grant_type":"password","password":password,"iat":now,"exp":now+120,"scope":SCOPE,"nonce":client_nonce,"request_nonce":nonce["nonce"],"jwe_crypto":{"alg":"ECDH-ES","enc":"A256GCM","apv":apv(&encryption.public,&client_nonce)?}})).map_err(Into::into)
}
pub(super) async fn login(
    f: &super::Fixture,
    password: bool,
    device: &Key,
    user: &Key,
    encryption: &Key,
    id: &Value,
) -> Result<String> {
    if password {
        request(f, device, encryption, id, PASSWORD).await
    } else {
        login_request(f, device, user, encryption, id).await
    }
}
pub(super) async fn negative(
    f: &super::Fixture,
    device: &Key,
    encryption: &Key,
    id: &Value,
) -> Result<()> {
    let assertion = request(f, device, encryption, id, "wrong-native-password").await?;
    ensure!(
        token(f, &assertion).await?.0 == StatusCode::BAD_REQUEST,
        "IdP rejection must not issue a native token"
    );
    ensure!(
        token(f, &assertion).await?.0 == StatusCode::BAD_REQUEST,
        "failed Password request nonce is not replayable"
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=apple.platform_sso: independent Password/JWE consumer with real Keycloak native account"]
async fn native_password_registration_exchange_and_recovery() -> Result<()> {
    native_registration_scenario(Some(Fixture::new().await?)).await
}
