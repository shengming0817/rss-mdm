//! Persisted enrollment intent and certificate state; protocol signing remains with Windows.
pub(crate) async fn intent(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT enrollment_type,csr,tbs,issuer,configuration,registration::text,credential::text,epoch::text,secrets FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(tenant).bind(request).fetch_optional(c).await
}
pub(crate) struct NewIntent<'a> {
    pub request: String,
    pub csr: &'a [u8],
    pub tbs: &'a [u8],
    pub issuer: &'a [u8],
    pub configuration: &'a str,
    pub registration: String,
    pub credential: String,
    pub epoch: String,
    pub secrets: &'a [u8],
    pub enrollment_type: &'a str,
}
pub(crate) async fn insert_intent(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    intent: NewIntent<'_>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let NewIntent {
        request,
        csr,
        tbs,
        issuer,
        configuration,
        registration,
        credential,
        epoch,
        secrets,
        enrollment_type,
    } = intent;
    sqlx::query("INSERT INTO mdm_access.enrollment_intents(tenant_id,request_id,csr,tbs,issuer,configuration,registration,credential,epoch,secrets,enrollment_type) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7::uuid,$8::uuid,$9::uuid,$10,$11)")
            .bind(tenant).bind(request).bind(csr).bind(tbs).bind(issuer).bind(configuration).bind(registration).bind(credential).bind(epoch).bind(secrets).bind(enrollment_type)
            .execute(c).await
}
pub(crate) async fn certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(tenant).bind(request).fetch_optional(c).await
}
pub(crate) async fn required_certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
                .bind(tenant).bind(request).fetch_one(c).await
}
pub(crate) async fn insert_certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
    certificate: &[u8],
    nonce: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query("INSERT INTO mdm_access.enrollment_certificates(tenant_id,request_id,certificate,server_nonce) VALUES($1::uuid,$2::uuid,$3,$4)")
            .bind(tenant).bind(request).bind(certificate).bind(nonce).execute(c).await
}
pub(crate) async fn registration(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
) -> Result<sqlx::postgres::PgRow, sqlx::Error> {
    sqlx::query("SELECT i.request_id::text,i.secrets,c.server_nonce FROM mdm_access.enrollment_intents i JOIN mdm_access.enrollment_certificates c ON (c.tenant_id,c.request_id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid AND i.registration=$2::uuid FOR UPDATE OF c")
            .bind(tenant).bind(registration).fetch_one(c).await
}
pub(crate) async fn update_nonce(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
    nonce: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query("UPDATE mdm_access.enrollment_certificates SET server_nonce=$3 WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
                .bind(tenant).bind(request).bind(nonce).execute(c).await
}
