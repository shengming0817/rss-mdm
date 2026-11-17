//! Bounded scan of existing publication attempts and withdrawal intents. No second task authority.
use super::{service::PublicationOperation, storage as db, *};
use rss_mdm_software_release as rel;
use rss_request_context::Deadline;
/// Existing intent selected for periodic recovery under its original identity.
pub struct PublicationWork {
    /// Opaque scan position in the existing record set.
    pub cursor: String,
    /// Original immutable publication identity.
    pub publication: rel::PublicationId,
    /// Original attempt; recovery never creates another attempt.
    pub attempt: u64,
    /// Whether this record is a withdrawal intent.
    pub withdrawal: bool,
}
impl PublicationOperation<'_> {
    /// Recheck the original call selected by the owner's bounded metadata discovery.
    pub async fn reconciliation_work(
        &self,
        key: &str,
        cutoff: Deadline,
    ) -> Result<Option<PublicationWork>> {
        let key = key.to_owned();
        settle(
            self.runtime
                .local_tx_with_context(self.binding, budget(cutoff), (self, key), |(s, key), tx| {
                    Box::pin(async move {
                        let withdrawal = key.starts_with("w:");
                        let table = if withdrawal {
                            db::Table::Withdraw
                        } else {
                            db::Table::Publish
                        };
                        let call = db::call(tx, table, key).await?.ok_or_else(db::fault)?;
                        if call.expected_epoch != s.binding.epoch().get() {
                            return Ok(Err(Error::Conflict));
                        }
                        if s.sources.binding.identity != call.target.binding {
                            return Ok(Ok(None));
                        }
                        let record = input!(
                            rel::PublicationKey::new(s.tenant(), &call.target.record)
                                .map_err(|_| Error::Identity)
                        );
                        let record = input!(
                            s.releases
                                .get_in(tx, &record)
                                .await?
                                .map_err(|_| Error::Content)
                        )
                        .ok_or_else(db::fault)?;
                        let publication = match db::core_publication(&record, &call.target) {
                            Ok(value) => value,
                            Err(Error::Conflict) => return Ok(Ok(None)),
                            Err(error) => return Ok(Err(error)),
                        };
                        if !withdrawal
                            && (db::call(tx, db::Table::Withdraw, &call.target.withdrawal_key())
                                .await?
                                .is_some()
                                || record.snapshot().withdrawn
                                || matches!(
                                    publication.outcome,
                                    rel::PublicationOutcome::Reported(
                                        rel::PublicationResult::NotApplied(_)
                                    )
                                ))
                        {
                            return Ok(Ok(None));
                        }
                        Ok(Ok(Some(PublicationWork {
                            cursor: key.clone(),
                            publication: call.target.publication_id(),
                            attempt: call.target.attempt,
                            withdrawal,
                        })))
                    })
                })
                .await,
        )
    }
}
