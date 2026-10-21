//! Uploaded files enter the same Resource/Catalog transaction as source imports.
use super::*;
use crate::management::content::InstallerFacts;
impl Catalog {
    #[allow(
        clippy::too_many_arguments,
        reason = "one borrowed transaction binds file, definition and original operation"
    )]
    pub(crate) async fn save_installer_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resources: &rss_mdm_resource_postgres::ResourceStore,
        audit: &RequestAudit,
        operation: uuid::Uuid,
        hash: &[u8],
        id: &str,
        artifact: &r::SoftwareArtifact,
        filename: &str,
        facts: &InstallerFacts,
        version: &str,
        platform: r::Platform,
        architecture: r::Architecture,
        now: i64,
    ) -> Result<Value> {
        use rss_mdm_resource_postgres::{Command, Request};
        let key = format!("resource/{id}/v1");
        tx.prepare_outbox_partitions(&[
            event::partition(self.tenant, &key)?,
            event::partition(self.tenant, "source/private-upload/1")?,
            resources.partition(id)?,
        ])
        .await?;
        self.audit.lock_in(tx).await?;
        storage::lock(tx).await?;
        if let Some(value) = storage::replay(tx, operation, hash).await? {
            self.record(tx, audit, (&key, operation, hash), &value, true)
                .await?;
            return Ok(value);
        }
        let source = match storage::source(tx, "private-upload", "1").await? {
            Some((definition, _)) => definition,
            None => {
                let definition = SourceDefinition {
                    id: "private-upload".into(),
                    revision: "1".into(),
                    protocol: SourceProtocol::Private,
                };
                let mut bytes =
                    Sha256::digest([operation.as_bytes().as_slice(), b"source"].concat());
                bytes[6] = (bytes[6] & 15) | 64;
                bytes[8] = (bytes[8] & 63) | 128;
                self.source_prepared_in(
                    tx,
                    audit,
                    "private-upload",
                    "1",
                    &Operation {
                        operation_id: uuid::Uuid::from_slice(&bytes[..16])
                            .map_err(|_| Error::Input)?,
                        expected_revision: 0,
                        input: SourceChange::Register {
                            definition: definition.clone(),
                        },
                    },
                )
                .await?;
                definition
            }
        };
        if !matches!(source.protocol, SourceProtocol::Private) {
            return Err(Error::Conflict);
        }
        let definition = r::SoftwareDefinition::new(r::SoftwareSpec {
            source: source.snapshot()?,
            package: id.into(),
            version: version.into(),
            provenance: r::SoftwareProvenance::Private,
            artifacts: std::collections::BTreeMap::from([("package".into(), artifact.clone())]),
            material: r::SoftwareMaterial {
                format: facts.format,
                installer: "package".into(),
                bundle_id: facts.bundle_id.clone(),
            },
            behavior: None,
            signatures: vec![],
            reboot: r::SoftwareReboot::Report,
            downgrade: r::SoftwareDowngrade::Deny,
            dependencies: vec![],
            export: r::SoftwareExport::Disabled,
        })
        .map_err(|_| Error::Input)?;
        let resource = r::Id::new(id).map_err(|_| Error::Input)?;
        let frozen = r::Version::new(
            self.tenant,
            resource.clone(),
            r::Id::new("v1").map_err(|_| Error::Input)?,
            r::Kind::Software,
            vec![r::Variant::new(
                platform,
                architecture,
                r::Id::new("default").map_err(|_| Error::Input)?,
                r::Declaration::Software { definition },
            )],
        )
        .map_err(|_| Error::Input)?;
        let at = rss_contract::Timepoint::try_from(now).map_err(|_| Error::Input)?;
        let commands = [
            Command::Create(r::Kind::Software),
            Command::Present(serde_json::Map::from_iter([(
                "name".into(),
                json!(filename),
            )])),
            Command::Insert(frozen.clone()),
            Command::Activate(r::Id::new("v1").map_err(|_| Error::Input)?),
        ];
        for (revision, command) in commands.into_iter().enumerate() {
            resources
                .execute_in(
                    tx,
                    &Request {
                        id: r::Id::new(format!("{operation}.{revision}"))
                            .map_err(|_| Error::Input)?,
                        resource: resource.clone(),
                        expected_storage_revision: revision as u64,
                        as_of: at,
                        command,
                    },
                )
                .await?
                .map_err(|_| Error::Conflict)?;
        }
        let value = json!({"packageId":id,"resource":id,"version":"v1","variant":"default","productVersion":version,"material":facts,"sha256":artifact.sha256,"length":artifact.length,"filename":filename,"href":format!("/api/v1/software/resources/{id}/versions/v1"),"storageRevision":4});
        self.record(tx, audit, (&key, operation, hash), &value, false)
            .await?;
        Ok(value)
    }
}

impl Reader {
    pub(crate) async fn operation_receipt_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: uuid::Uuid,
        hash: &[u8],
    ) -> Result<Option<Value>> {
        self.tenant(tx)?;
        storage::replay(tx, operation, hash).await
    }
    pub(crate) async fn save_operation_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: uuid::Uuid,
        hash: &[u8],
        value: &Value,
    ) -> Result<()> {
        self.tenant(tx)?;
        storage::receipt(tx, operation, hash, value).await
    }
}
