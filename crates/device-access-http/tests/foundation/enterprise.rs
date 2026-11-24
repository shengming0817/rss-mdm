//! Standalone browser writes and recovery of a fixed enterprise application receipt.
use super::*;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use reqwest::{Client, RequestBuilder, StatusCode};
use rss_identity_core::session::BearerSecret;
use serde_json::{Value, json};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

const APP: &str = "expense-reports";

pub(super) fn deployment(c: &Context, m: &material::Material) -> Result<Value> {
    let signing = m.directory.join("enterprise-signing.pem");
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    host::private(
        &signing,
        &PKey::from_ec_key(EcKey::generate(&group)?)?.private_key_to_pem_pkcs8()?,
    )?;
    let client = m.directory.join("enterprise-client.secret");
    let backend = m.directory.join("enterprise-backend.secret");
    host::private(&client, Uuid::new_v4().to_string().as_bytes())?;
    host::private(
        &backend,
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()).as_bytes(),
    )?;
    Ok(json!({
        "key_id":"test-rp", "signing_key_file":signing, "administrators":[],
        "clients":[{"tenant":c.tenant.to_string(),"target":{"id":APP,"issuer":"https://rp.example.test/assertion",
        "token_endpoint":"https://id.example.test/token","client_id":"expense-client","scopes":["openid"]},
        "provider":Uuid::new_v4(),"issuer":"https://id.example.test","client_secret_file":client,
        "private_cidrs":[],"backend_key_id":"backend","backend_secret_file":backend}]
    }))
}

struct Browser<'a> {
    client: &'a Client,
    origin: &'a str,
    identity: String,
    configurations: String,
    cookie: String,
    csrf: String,
    key: WebauthnAuthenticator<SoftPasskey>,
}
impl Browser<'_> {
    fn post(&self, url: &str, grant: Option<&str>) -> RequestBuilder {
        let cookie = match grant {
            Some(grant) => format!("{}; {grant}", self.cookie),
            None => self.cookie.clone(),
        };
        self.client
            .post(url)
            .header("cookie", cookie)
            .header("x-csrf-token", &self.csrf)
            .header("x-identity-request", "1")
            .header("origin", self.origin)
    }

    async fn register(&mut self) -> Result<()> {
        let begin = format!("{}/webauthn/register/begin", self.identity);
        let challenge: Value = material::success(
            self.post(&begin, None)
                .json(&json!({"label":"Enterprise configuration test","recover":false}))
                .send()
                .await?,
        )
        .await?;
        let response = self.key.do_registration(
            self.origin.parse()?,
            serde_json::from_value(challenge["options"].clone())?,
        )?;
        let finish = format!("{}/webauthn/register/finish", self.identity);
        self.post(&finish, None)
            .json(&json!({"id":challenge["id"],"response":response}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn grant(&mut self, change: &Value) -> Result<String> {
        let challenge: Value = material::success(
            self.post(&format!("{}/step-up", self.configurations), None)
                .json(change)
                .send()
                .await?,
        )
        .await?;
        let response = self.key.do_authentication(
            self.origin.parse()?,
            serde_json::from_value(challenge["options"].clone())?,
        )?;
        let finish = format!("{}/webauthn/authenticate/finish", self.identity);
        let response = self
            .post(&finish, None)
            .json(&json!({"id":challenge["id"],"response":response}))
            .send()
            .await?
            .error_for_status()?;
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.split(';').next())
            .find(|v| v.starts_with("__Host-identity-operation="))
            .map(str::to_owned)
            .context("missing purpose-bound grant")
    }

    async fn submit(&mut self, change: &Value) -> Result<reqwest::Response> {
        let grant = self.grant(change).await?;
        Ok(self
            .post(&self.configurations, Some(&grant))
            .json(change)
            .send()
            .await?)
    }
}
fn change(operation: Uuid, revision: i64, enabled: bool) -> Value {
    json!({"operationId":operation, "expectedRevision":revision,
        "configuration":{"kind":"relying_party","id":APP,"enabled":enabled,
        "callback":"https://rp.example.test/callback","capabilities":["native_key"]}})
}
async fn missing(response: reqwest::Response) -> Result<()> {
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.json::<Value>().await?,
        json!({"code":"operation_not_found"})
    );
    Ok(())
}

pub(super) async fn verify(
    c: &Context,
    client: &Client,
    other_cookie: &str,
    management: Uuid,
    management_cookie: &str,
) -> Result<()> {
    let token = material::administrator(c).await?;
    let principal = c
        .authority
        .inspect_bearer(
            c.execution(),
            BearerSecret::parse(token)?,
            platform::deadline(),
        )
        .await?
        .account()
        .principal
        .as_uuid();
    let grant = rss_mdm_authorization_service::Grant {
        operation: rss_mdm_authorization_service::Permission::EnterpriseApplicationsWrite,
        scope: rss_mdm_authorization_service::Scope::Tenant,
    };
    let rule: Uuid = sqlx::query_scalar("UPDATE rss_da.authorization_rules SET document=jsonb_set(document,'{grants}',(document->'grants') || jsonb_build_array($3::jsonb)), revision=revision+1 WHERE tenant_id=$1::uuid AND document #>> '{subject,user,principalId}'=$2 RETURNING id")
        .bind(c.tenant.to_string()).bind(principal.to_string()).bind(serde_json::to_value(grant)?).fetch_one(&c.operator).await?;
    let (cookie, csrf) = credentials::login(c, client, principal).await?;
    let root = format!(
        "{}/api/v1/tenants/{}/device-access/enterprise/configuration",
        c.browser_origin, c.tenant
    );
    let mut browser = Browser {
        client,
        origin: &c.browser_origin,
        identity: format!("{}/api/v1/identity/tenants/{}", c.browser_origin, c.tenant),
        configurations: root.clone(),
        cookie,
        csrf,
        key: WebauthnAuthenticator::new(SoftPasskey::new(true)),
    };
    browser.register().await?;
    let first = Uuid::new_v4();
    let create = change(first, 0, true);
    for (field, value) in [
        ("id", "unconfigured"),
        ("callback", "http://rp.example.test/callback"),
    ] {
        let mut invalid = create.clone();
        invalid["configuration"][field] = json!(value);
        assert_eq!(
            browser
                .post(&format!("{root}/step-up"), None)
                .json(&invalid)
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let other_grant = browser.grant(&change(Uuid::new_v4(), 0, true)).await?;
    assert_eq!(
        browser
            .post(&root, Some(&other_grant))
            .json(&create)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let before = business::counts(c).await?;
    // Simulate the lost response by discarding the committed write body.
    drop(browser.submit(&create).await?.error_for_status()?);
    let original = format!("{root}/operations/{first}");
    let read = |url: &str, cookie: &str| client.get(url).header("cookie", cookie);
    let expected = json!({"operationId":first,"applicationId":APP,"revision":1,"enabled":true});
    assert_eq!(
        material::success::<Value>(read(&original, &browser.cookie).send().await?).await?,
        expected
    );
    let mut edit = change(Uuid::new_v4(), 1, true);
    edit["configuration"]["capabilities"] = json!(["password"]);
    let updated: Value = material::success(browser.submit(&edit).await?).await?;
    assert_eq!(updated["value"]["revision"], 2);
    assert_eq!(
        browser
            .submit(&change(Uuid::new_v4(), 1, false))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let disabled: Value =
        material::success(browser.submit(&change(Uuid::new_v4(), 2, false)).await?).await?;
    assert_eq!(disabled["value"]["enabled"], false);
    let after = business::counts(c).await?;
    assert_eq!((after.1 - before.1, after.2 - before.2), (3, 3));
    assert_eq!(
        material::success::<Value>(
            read(&original, &browser.cookie)
                .query(&[("applicationId", APP)])
                .send()
                .await?
        )
        .await?,
        expected
    );
    let detail: Value = material::success(
        read(&format!("{root}/rp:{APP}"), other_cookie)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(detail["value"]["revision"], 3);
    assert_eq!(detail["value"]["enabled"], false);
    missing(
        read(&original, &browser.cookie)
            .query(&[("applicationId", "another-app")])
            .send()
            .await?,
    )
    .await?;
    missing(
        read(
            &format!("{root}/operations/{}", Uuid::new_v4()),
            &browser.cookie,
        )
        .send()
        .await?,
    )
    .await?;
    missing(read(&original, other_cookie).send().await?).await?;
    let management_lookup = format!(
        "{}/api/v1/tenants/{management}/device-access/enterprise/configuration/operations/{first}",
        c.browser_origin
    );
    assert_eq!(
        read(&management_lookup, management_cookie)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(business::counts(c).await?, after);

    // Seed another DA owner's receipt and a damaged, positively identified RP receipt.
    for (result, expected_status) in [
        ("22", StatusCode::NOT_FOUND),
        (
            r#"{"kind":"relying_party","value":{}}"#,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO rss_da.operations(tenant_id,instance,actor,operation_id,digest,result) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)")
            .bind(c.tenant.to_string()).bind(&c.inputs.installation.instance_id).bind(principal).bind(id).bind("a".repeat(64)).bind(result)
            .execute(&c.operator).await?;
        let response = read(&format!("{root}/operations/{id}"), &browser.cookie)
            .send()
            .await?;
        if expected_status == StatusCode::NOT_FOUND {
            missing(response).await?;
        } else {
            assert_eq!(response.status(), expected_status);
        }
    }
    let old_session = browser.cookie.clone();
    browser
        .post(&format!("{}/session/logout", browser.identity), None)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        read(&original, &old_session).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let (fresh, _) = credentials::login(c, client, principal).await?;
    assert_eq!(
        material::success::<Value>(read(&original, &fresh).send().await?).await?,
        expected
    );
    assert_eq!(
        sqlx::query(
            "UPDATE rss_da.authorization_rules
             SET revision=revision+1, document=jsonb_set(document, '{grants}',
                 (SELECT jsonb_agg(g) FROM jsonb_array_elements(document->'grants') g
                  WHERE g->>'operation' <> 'enterprise_applications_read'))
             WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(rule)
        .execute(&c.operator)
        .await?
        .rows_affected(),
        1
    );
    assert_eq!(
        read(&original, &fresh).send().await?.status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
