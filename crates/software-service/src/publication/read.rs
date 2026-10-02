//! Read projections from the existing publication, Resource and admission authorities.
use super::{
    config::{Driver, index},
    service::PublicationService,
    storage as db, *,
};
use rss_mdm_software_release as rel;
use rss_request_context::Deadline;
use sqlx::Row;
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedSoftware {
    pub publication: [u8; 32],
    pub resource: String,
    pub version: String,
    pub resource_digest: [u8; 32],
    pub document: ExportDocument,
    pub dependencies: Vec<ExportDocument>,
    pub artifacts: Vec<PublicArtifact>,
    pub snapshot: Option<String>,
}
impl PublicationService {
    pub fn public_base(&self, ring: rel::Ring) -> &str {
        match &self.sources.binding(ring).driver {
            Driver::Winget { base, .. } | Driver::Brew { base, .. } => base,
        }
    }
    pub fn native_identifier(&self, ring: rel::Ring, publication: Option<[u8; 32]>) -> String {
        match publication {
            Some(id) => format!("rss.{}", hex(&id)),
            None => format!("rss.{}.{}", hex(&self.sources.digest), index(ring)),
        }
    }
    pub fn native_read_allowed(&self, ring: rel::Ring, token: Option<&str>) -> bool {
        match &self.sources.binding(ring).driver {
            Driver::Winget { .. } => true,
            Driver::Brew { access, .. } => token
                .is_some_and(|token| access.permits(self.tenant(), &self.sources.logical, token)),
        }
    }
    pub fn native_winget(&self, ring: rel::Ring) -> bool {
        matches!(self.sources.binding(ring).driver, Driver::Winget { .. })
    }

    /// A frozen read does not adopt a newer source approval, target or release identity.
    pub async fn published(
        &self,
        ring: rel::Ring,
        publication: [u8; 32],
        cutoff: Deadline,
    ) -> Result<PublishedSoftware> {
        let (version, subject, target) = settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, ring, publication),
                    |(s, ring, id), tx| {
                        Box::pin(async move { s.exports().published_in(tx, *ring, *id).await })
                    },
                )
                .await,
        )?;
        let dependencies = self.export_dependencies(&version, cutoff).await?;
        let prepared = spec::prepare(&self.sources.exports(), &version, &dependencies)?;
        if serde_json::to_vec(&prepared.document).map_err(|_| Error::Content)?
            != serde_json::to_vec(&subject.document).map_err(|_| Error::Content)?
        {
            return Err(Error::Content);
        }
        // Final current-state check includes the period spent reconstructing the immutable view.
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, ring, publication),
                    |(s, ring, id), tx| {
                        Box::pin(async move {
                            s.exports()
                                .published_in(tx, *ring, *id)
                                .await
                                .map(|v| v.map(|_| ()))
                        })
                    },
                )
                .await,
        )?;
        Ok(PublishedSoftware {
            publication,
            resource: subject.resource,
            version: subject.version,
            resource_digest: subject.resource_digest,
            dependencies: derive::dependency_documents(
                &version,
                &dependencies,
                match &self.sources.binding(ring).driver {
                    Driver::Winget { artifacts_base, .. } | Driver::Brew { artifacts_base, .. } => {
                        artifacts_base
                    }
                },
            )?,
            document: prepared.document,
            artifacts: derive::exported_materials(
                &version,
                &dependencies,
                match &self.sources.binding(ring).driver {
                    Driver::Winget { artifacts_base, .. } | Driver::Brew { artifacts_base, .. } => {
                        artifacts_base
                    }
                },
            )?,
            snapshot: target.snapshot,
        })
    }
    /// Bounded page through already-published projections, never raw candidates.
    pub async fn published_page(
        &self,
        ring: rel::Ring,
        after: &str,
        limit: usize,
        cutoff: Deadline,
    ) -> Result<Vec<(String, [u8; 32])>> {
        if limit == 0 || limit > 100 || after.len() > 512 || after.contains(['\r', '\n', '\0']) {
            return Err(Error::Input);
        }
        let binding = self.sources.binding(ring).identity.clone();
        let after = after.to_owned();
        settle(self.runtime.local_tx_with_context(self.tenant(),budget(cutoff),(binding,after),|(binding,after),tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();let binding=binding.clone();let after=after.clone();
            let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT coordinate,publication FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate COLLATE \"C\">$3 ORDER BY coordinate COLLATE \"C\" LIMIT $4").bind(tenant).bind(binding).bind(after).bind(limit as i64).fetch_all(c).await})).await?;
            let mut values=Vec::new();for row in rows {let id:Vec<u8>=row.try_get("publication")?;values.push((row.try_get("coordinate")?,id.try_into().map_err(|_|db::fault())?));}Ok(Ok(values))
        })).await)
    }
    /// Exact coordinate and Resource reads use existing indexed projections; page size
    /// does not cap source membership or make later publications unreachable.
    pub async fn published_coordinate(
        &self,
        ring: rel::Ring,
        coordinate: &str,
        cutoff: Deadline,
    ) -> Result<PublishedSoftware> {
        if coordinate.len() > 512 {
            return Err(Error::Input);
        }
        let binding = self.sources.binding(ring).identity.clone();
        let coordinate = coordinate.to_owned();
        let id=settle(self.runtime.local_tx_with_context(self.tenant(),budget(cutoff),(binding,coordinate),|(binding,coordinate),tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();let binding=binding.clone();let coordinate=coordinate.clone();
            let bytes:Option<Vec<u8>>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT publication FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND binding=$2 AND coordinate=$3").bind(tenant).bind(binding).bind(coordinate).fetch_optional(c).await})).await?;
            Ok(bytes.map(|b|b.try_into().map_err(|_|Error::Content)).transpose().map(|v|v.ok_or(Error::CandidateNotFound)).and_then(|v|v))
        })).await)?;
        self.published(ring, id, cutoff).await
    }
    pub async fn published_resource(
        &self,
        ring: rel::Ring,
        resource: &str,
        version: &str,
        cutoff: Deadline,
    ) -> Result<Vec<PublishedSoftware>> {
        let binding = self.sources.binding(ring).identity.clone();
        let resource = resource.to_owned();
        let version = version.to_owned();
        let ids=settle(self.runtime.local_tx_with_context(self.tenant(),budget(cutoff),(binding,resource,version),|(binding,resource,version),tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();let binding=binding.clone();let resource=resource.clone();let version=version.clone();
            let bytes:Vec<Vec<u8>>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT DISTINCT p.publication FROM mdm_software_composition.projections p JOIN mdm_software_composition.targets t ON t.tenant_id=p.tenant_id AND t.id LIKE ('p:'||encode(p.publication,'hex')||':%') JOIN mdm_software_composition.subjects s ON s.tenant_id=t.tenant_id AND s.candidate=t.candidate WHERE p.tenant_id=$1::uuid AND p.binding=$2 AND s.resource=$3 AND s.version=$4 LIMIT 4").bind(tenant).bind(binding).bind(resource).bind(version).fetch_all(c).await})).await?;
            let ids=bytes.into_iter().map(|b|b.try_into().map_err(|_|Error::Content)).collect::<Result<Vec<[u8;32]>>>();Ok(ids)
        })).await)?;
        let mut values = Vec::new();
        for id in ids {
            match self.published(ring, id, cutoff).await {
                Ok(v) => values.push(v),
                Err(Error::CandidateNotFound | Error::Content) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(values)
    }
    /// Execute upload-pack while current publication and approval locks remain held.
    pub async fn upload_pack(
        &self,
        ring: rel::Ring,
        publication: [u8; 32],
        advertise: bool,
        v2: bool,
        input: &[u8],
        cutoff: Deadline,
    ) -> Result<Vec<u8>> {
        let Driver::Brew { repo, .. } = &self.sources.binding(ring).driver else {
            return Err(Error::Unsupported);
        };
        settle(
            self.runtime
                .local_tx_with_context(
                    self.tenant(),
                    budget(cutoff),
                    (self, ring, publication, repo, input),
                    |(s, ring, id, repo, input), tx| {
                        Box::pin(async move {
                            let (_, _, target) =
                                input!(s.exports().published_in(tx, *ring, *id).await?);
                            let snapshot = input!(
                                rss_mdm_brew_source::CommitId::parse(
                                    target.snapshot.as_deref().ok_or_else(db::fault)?
                                )
                                .map_err(|_| Error::Content)
                            );
                            Ok(repo
                                .upload_pack(&snapshot, advertise, v2, input)
                                .await
                                .map_err(|cause| Error::Source.context("read::upload_pack", cause)))
                        })
                    },
                )
                .await,
        )
    }
}

pub(super) fn current_published(
    candidate: &rel::Candidate,
    ring: rel::Ring,
    target: &db::Target,
) -> bool {
    let rel::RingState::Publication(current) = candidate.snapshot().ring_state(ring) else {
        return false;
    };
    current.id().digest().bytes() == target.publication
        && current.attempt == target.attempt
        && candidate.snapshot().disposition == rel::Disposition::Active
        && matches!(
            current.outcome,
            rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))
        )
}
