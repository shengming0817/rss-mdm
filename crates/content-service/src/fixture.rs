//! Concrete ready artifact state for downstream integration prerequisites.
use super::*;

/// Store one small, unprotected artifact without an upload, binding, receipt or audit event.
/// Consumers that test upload or installer inspection must use the real upload API.
pub async fn artifact(
    store: &Store,
    artifact: &Artifact,
    bytes: Vec<u8>,
    expires: i64,
) -> Result<(), Error> {
    ready(store, artifact, bytes, expires, StorageClass::Artifact).await
}

/// Store a sealed native configuration using the owner's current protection and manifest codecs.
pub async fn native_configuration(
    store: &Store,
    artifact: &Artifact,
    bytes: Vec<u8>,
    expires: i64,
) -> Result<(), Error> {
    ready(
        store,
        artifact,
        bytes,
        expires,
        StorageClass::NativeConfiguration,
    )
    .await
}

async fn ready(
    store: &Store,
    artifact: &Artifact,
    bytes: Vec<u8>,
    expires: i64,
    class: StorageClass,
) -> Result<(), Error> {
    if bytes.is_empty()
        || bytes.len() as u64 > journal::CHUNK
        || bytes.len() as u64 != artifact.length()
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != artifact.digest().bytes()
    {
        return Err(Error::Malformed);
    }
    let bytes = if class.protected() {
        protected::seal(&store.protection, store.tenant, &bytes, artifact, class)?
    } else {
        bytes
    };
    let id = uuid::Uuid::new_v4();
    let content = rss_mdm_content_s3::Content {
        length: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
    };
    let intent = store.backend.intent(id, content)?;
    let coordinate = store
        .backend
        .write(
            &intent,
            content,
            bytes,
            store.upload_budget()?.operation,
            (),
        )
        .await
        .map_err(|error| match error {
            backend::WriteFailure::Unresolved(e) | backend::WriteFailure::NotWritten(e) => e,
        })?;
    let manifest = journal::Manifest {
        pieces: vec![journal::Piece {
            id,
            offset: 0,
            length: artifact.length(),
            content,
            coordinate: coordinate.clone(),
        }],
        inspections: Default::default(),
    };
    let mut tx = store.tx().await?;
    sqlx::query("INSERT INTO mdm_content.objects(tenant_id,id,owner,content,intent,coordinate,expires,state) VALUES($1::uuid,$2,$2,$3,$4,$5,$6,'ready')")
        .bind(store.tenant.to_string()).bind(id).bind(journal::encode(&content)?).bind(journal::encode(&intent)?).bind(journal::encode(&coordinate)?).bind(expires).execute(&mut *tx).await.map_err(|_| storage())?;
    sqlx::query("INSERT INTO mdm_content.manifests(tenant_id,class,sha256,length,document,expires,state) VALUES($1::uuid,$6,$2,$3,$4,$5,'ready') ON CONFLICT(tenant_id,class,sha256,length) DO NOTHING")
        .bind(store.tenant.to_string()).bind(artifact.digest().bytes().as_slice()).bind(artifact.length() as i64).bind(store.sign(&store.manifest_key(class, artifact), &manifest)?).bind(expires).bind(journal::class(class)).execute(&mut *tx).await.map_err(|_| storage())?;
    journal::commit(tx).await
}
