//! Source conversion joins the existing Resource, admission, audit and receipt transaction.
use super::*;
use crate::imports::{ImportRequest, PreparedImport, SourceDocuments};
use rss_contract::Timepoint;
use rss_mdm_resource_postgres::{Command, Request, ResourceStore};
impl Catalog {
    fn import_hash(&self, audit: &RequestAudit, op: &Operation<ImportRequest>) -> Result<Vec<u8>> {
        check_operation(op.operation_id, op.expected_revision)?;
        fingerprint(&(
            "software-import-v1",
            self.tenant.to_string(),
            actor(audit)?,
            op,
        ))
    }
    pub async fn has_import_receipt_in(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        op: &Operation<ImportRequest>,
    ) -> Result<bool> {
        self.tenant(tx)?;
        Ok(
            storage::replay(tx, op.operation_id, &self.import_hash(audit, op)?)
                .await?
                .is_some(),
        )
    }
    pub async fn import_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &r::SoftwareSource,
    ) -> Result<SourceDefinition> {
        self.source_admitted_in(tx, source).await?;
        storage::source(tx, &source.id, &source.revision)
            .await?
            .map(|(s, _)| s)
            .ok_or(Error::NotAdmitted)
    }
    /// Replay before consulting current source state or fetching metadata. Both Resource
    /// commands and the operation receipt settle in the caller's one transaction.
    pub async fn import_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resources: &ResourceStore,
        audit: &RequestAudit,
        op: &Operation<ImportRequest>,
        prepared: Option<&PreparedImport>,
    ) -> Result<Value> {
        self.tenant(tx)?;
        let hash = self.import_hash(audit, op)?;
        let key = format!(
            "resource/{}/{}",
            op.input.resource, op.input.resource_version
        );
        tx.prepare_outbox_partitions(&[
            event::partition(self.tenant, &key)?,
            resources.partition(&op.input.resource)?,
        ])
        .await?;
        self.audit.lock_in(tx).await?;
        storage::lock(tx).await?;
        if let Some(value) = storage::replay(tx, op.operation_id, &hash).await? {
            self.record(tx, audit, (&key, op.operation_id, &hash), &value, true)
                .await?;
            return Ok(value);
        }
        let source = self.import_source_in(tx, &op.input.source).await?;
        let prepared = prepared.ok_or(Error::Input)?;
        let documents: SourceDocuments = match &prepared.version.variants()[0].declaration() {
            r::Declaration::Software { definition } => match &definition.spec().provenance {
                r::SoftwareProvenance::Imported { files, .. } => files
                    .iter()
                    .map(|f| {
                        let bytes = prepared
                            .originals
                            .iter()
                            .find(|(a, _)| a == &f.content)
                            .ok_or(Error::Input)?
                            .1
                            .clone();
                        Ok((f.path.clone(), bytes))
                    })
                    .collect::<Result<_>>()?,
                _ => return Err(Error::Input),
            },
            _ => return Err(Error::Input),
        };
        let checked = crate::imports::prepare(self.tenant, &source, &op.input, &documents)?;
        if checked.version.digest() != prepared.version.digest() {
            return Err(Error::Input);
        }
        self.dependencies(tx, &checked.version).await?;
        for dep in &op.input.dependencies {
            let child = self.version_in(tx, &dep.resource, &dep.version).await?;
            let selected = child
                .variants()
                .iter()
                .find(|v| {
                    v.platform() == op.input.platform && v.architecture() == op.input.architecture
                })
                .ok_or(Error::Dependency)?;
            let r::Declaration::Software { definition } = selected.declaration() else {
                return Err(Error::Dependency);
            };
            if definition.spec().version != dep.package_version {
                return Err(Error::Dependency);
            }
            let child_source = self.import_source_in(tx, &definition.spec().source).await?;
            let package = match child_source.protocol {
                SourceProtocol::BrewTap { tap, .. } => {
                    format!("{}/{}", tap, definition.spec().package)
                }
                _ => definition.spec().package.clone(),
            };
            if package != dep.package {
                return Err(Error::Dependency);
            }
        }
        let at = Timepoint::try_from(op.input.as_of_unix_seconds).map_err(|_| Error::Input)?;
        let rid = r::Id::new(&op.input.resource).map_err(|_| Error::Input)?;
        let mut revision = op.expected_revision;
        if revision == 0 {
            resources
                .execute_in(
                    tx,
                    &Request {
                        id: r::Id::new(format!("{}.create", op.operation_id))
                            .map_err(|_| Error::Input)?,
                        resource: rid.clone(),
                        expected_storage_revision: 0,
                        as_of: at,
                        command: Command::Create(r::Kind::Software),
                    },
                )
                .await?
                .map_err(|_| Error::Conflict)?;
            revision = 1;
        }
        let receipt = resources
            .execute_in(
                tx,
                &Request {
                    id: r::Id::new(format!("{}.insert", op.operation_id))
                        .map_err(|_| Error::Input)?,
                    resource: rid,
                    expected_storage_revision: revision,
                    as_of: at,
                    command: Command::Insert(checked.version.clone()),
                },
            )
            .await?
            .map_err(|_| Error::Conflict)?;
        let value = json!({"resource":op.input.resource,"version":op.input.resource_version,"resourceDigest":checked.version.digest().bytes(),"storageRevision":receipt.storage_revision});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
    }
}
