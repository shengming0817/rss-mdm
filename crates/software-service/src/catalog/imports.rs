//! Source conversion joins the existing Resource, lifecycle, audit and receipt transaction.
use super::*;
use crate::imports::{ImportRequest, PreparedImport, SourceDocuments};
use crate::management::resource::ResourceWriter;
use rss_contract::Timepoint;
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
        self.reader().tenant(tx)?;
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
        self.reader().source_admitted_in(tx, source).await?;
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
        resources: &dyn ResourceWriter,
        audit: &RequestAudit,
        op: &Operation<ImportRequest>,
        prepared: Option<&PreparedImport>,
    ) -> Result<Value> {
        self.reader().tenant(tx)?;
        let hash = self.import_hash(audit, op)?;
        let key = format!(
            "resource/{}/{}",
            op.input.resource, op.input.resource_version
        );
        storage::lock(tx).await?;
        self.audit
            .prepare_in(
                tx,
                audit,
                &[
                    event::partition(self.tenant, &key)?,
                    resources.partition(&op.input.resource)?,
                ],
            )
            .await?;
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
        self.reader().dependencies(tx, &checked.version).await?;
        for dep in &op.input.dependencies {
            let child = self
                .reader()
                .version_in(tx, &dep.resource, &dep.version)
                .await?;
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
        let revision = resources
            .import_in(
                tx,
                op.operation_id,
                op.expected_revision,
                &checked.version,
                at,
            )
            .await?;
        let value = json!({"resource":op.input.resource,"version":op.input.resource_version,"resourceDigest":checked.version.digest().bytes(),"storageRevision":revision});
        self.record(tx, audit, (&key, op.operation_id, &hash), &value, false)
            .await?;
        Ok(value)
    }
}
