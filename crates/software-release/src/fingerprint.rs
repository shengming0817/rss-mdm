//! Canonical original request identity.
use crate::identity::Encoding;
use crate::model::{encode_evidence, encode_time};
use crate::*;
pub(crate) fn request(publication: &PublicationKey, request: &Request) -> Digest {
    let mut e = Encoding::new(b"rss-mdm-software-release/request/v1");
    e.object(publication.tenant(), publication.value());
    e.object(request.id.tenant(), request.id.value());
    e.object(request.actor.tenant(), request.actor.value());
    e.number(request.expected_revision);
    encode_time(&mut e, request.as_of);
    match &request.operation {
        Operation::Retry {
            publication,
            attempt,
        } => {
            e.number(0);
            e.digest(publication.digest());
            e.number(*attempt);
        }
        Operation::Record {
            publication,
            attempt,
            outcome,
        } => {
            e.number(1);
            e.digest(publication.digest());
            e.number(*attempt);
            e.number(match outcome {
                PublicationResult::Unknown(_) => 0,
                PublicationResult::NotApplied(_) => 1,
                PublicationResult::Applied(_) => 2,
            });
            encode_evidence(&mut e, outcome.evidence());
        }
        Operation::Withdraw => e.number(2),
    }
    e.finish()
}
