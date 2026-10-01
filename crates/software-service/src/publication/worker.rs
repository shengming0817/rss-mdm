//! Bounded scan of existing publication attempts and withdrawal intents. No second task authority.
use super::{service::PublicationService, storage as db, *};
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
/// A bounded scan position, including records skipped because they belong to another source.
pub struct PublicationWorkPage {
    /// Last inspected existing record. None restarts the finite scan.
    pub next: Option<String>,
    /// Only current unfinished work owned by this source binding.
    pub work: Vec<PublicationWork>,
}
impl PublicationService {
    /// Scan at most 32 existing records and restore owner state before choosing recovery.
    pub async fn reconciliation_page(
        &self,
        after: &str,
        limit: usize,
        cutoff: Deadline,
    ) -> Result<PublicationWorkPage> {
        if limit == 0 || limit > 32 || after.len() > 128 || after.contains(['\0', '\r', '\n']) {
            return Err(Error::Input);
        }
        let after = after.to_owned();
        settle(self.runtime.local_tx_with_context(self.tenant(),budget(cutoff),(self,after),|(s,after),tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();let after=after.clone();
            let keys:Vec<String>=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar("SELECT id FROM (SELECT t.id FROM mdm_software_composition.targets t WHERE t.tenant_id=$1::uuid AND left(t.id,2)='p:' AND NOT EXISTS(SELECT 1 FROM mdm_software_composition.projections p WHERE p.tenant_id=t.tenant_id AND encode(p.publication,'hex')=substring(t.id,3,64)) UNION ALL SELECT id FROM mdm_software_composition.withdrawals WHERE tenant_id=$1::uuid AND NOT complete) pending WHERE id COLLATE \"C\">$2 ORDER BY id COLLATE \"C\" LIMIT $3").bind(tenant).bind(after).bind(limit as i64).fetch_all(c).await
            })).await?;
            let next=if keys.len()==limit{keys.last().cloned()}else{None};let mut work=Vec::new();
            for key in keys {
                let withdrawal=key.starts_with("w:");let table=if withdrawal{db::Table::Withdraw}else{db::Table::Publish};
                let call=db::call(tx,table,&key).await?.ok_or_else(db::fault)?;
                if !s.sources.bindings.iter().any(|b|b.identity==call.target.binding){continue;}
                let candidate=input!(rel::CandidateId::new(s.tenant(),&call.target.candidate).map_err(|_|Error::Identity));
                let candidate=input!(s.releases.get_in(tx,&candidate).await?.map_err(|_|Error::Content)).ok_or_else(db::fault)?;
                let publication=match db::core_publication(&candidate,&call.target) {Ok(value)=>value,Err(Error::Conflict)=>continue,Err(error)=>return Ok(Err(error))};
                if !withdrawal&&(candidate.snapshot().disposition!=rel::Disposition::Active||matches!(publication.outcome,rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_)))){continue;}
                work.push(PublicationWork{cursor:key,publication:call.target.publication_id(),attempt:call.target.attempt,withdrawal});
            }
            Ok(Ok(PublicationWorkPage{next,work}))
        })).await)
    }
}
