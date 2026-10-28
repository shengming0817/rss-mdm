//! Resource participation in an already authorized Software transaction.
use crate::{Error, transaction::*};
use rss_contract::Timepoint;
use rss_mdm_resource as r;
use rss_mdm_resource_postgres::{Command, Request, ResourceStore};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub struct SoftwareWriter {
    store: Arc<ResourceStore>,
}
impl SoftwareWriter {
    pub fn new(store: Arc<ResourceStore>) -> Self {
        Self { store }
    }
    pub fn partition(
        &self,
        resource: &str,
    ) -> Result<rss_transactional_messaging::message::PartitionIdentity> {
        Ok(self.store.partition(resource)?)
    }
    pub async fn import_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: uuid::Uuid,
        expected: u64,
        version: &r::Version,
        at: Timepoint,
    ) -> Result<u64> {
        checked(self.store.validate_transaction(tx)?)?;
        if version.kind() != r::Kind::Software || version.tenant() != tx.tenant_id() {
            return Err(Error::Malformed.into());
        }
        let mut revision = expected;
        if revision == 0 {
            checked(
                self.store
                    .execute_in(
                        tx,
                        &Request {
                            id: checked_input(r::Id::new(format!("{operation}.create")))?,
                            resource: version.resource().clone(),
                            expected_storage_revision: 0,
                            as_of: at,
                            command: Command::Create(r::Kind::Software),
                        },
                    )
                    .await?,
            )?;
            revision = 1;
        }
        let receipt = checked(
            self.store
                .execute_in(
                    tx,
                    &Request {
                        id: checked_input(r::Id::new(format!("{operation}.insert")))?,
                        resource: version.resource().clone(),
                        expected_storage_revision: revision,
                        as_of: at,
                        command: Command::Insert(version.clone()),
                    },
                )
                .await?,
        )?;
        Ok(receipt.storage_revision)
    }
    pub async fn installer_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: uuid::Uuid,
        version: &r::Version,
        filename: &str,
        at: Timepoint,
    ) -> Result<u64> {
        checked(self.store.validate_transaction(tx)?)?;
        if version.kind() != r::Kind::Software || version.tenant() != tx.tenant_id() {
            return Err(Error::Malformed.into());
        }
        let commands = [
            Command::Create(r::Kind::Software),
            Command::Present(serde_json::Map::from_iter([(
                "name".into(),
                serde_json::json!(filename),
            )])),
            Command::Insert(version.clone()),
            Command::Activate(version.label().clone()),
        ];
        let mut revision = 0;
        for (step, command) in commands.into_iter().enumerate() {
            revision = checked(
                self.store
                    .execute_in(
                        tx,
                        &Request {
                            id: checked_input(r::Id::new(format!("{operation}.{step}")))?,
                            resource: version.resource().clone(),
                            expected_storage_revision: revision,
                            as_of: at,
                            command,
                        },
                    )
                    .await?,
            )?
            .storage_revision;
        }
        Ok(revision)
    }
}
