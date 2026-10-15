//! One canonical encoding for request identity; timestamps belong to the original request.
use crate::identity::Encoding;
use crate::model::{encode_evidence, encode_time, encode_validation};
use crate::*;
pub(crate) fn request(candidate: &CandidateId, request: &Request) -> Digest {
    let mut e = Encoding::new(b"rss-mdm-software-release/request/v3");
    e.object(candidate.tenant(), candidate.value());
    e.object(request.id.tenant(), request.id.value());
    e.object(request.actor.tenant(), request.actor.value());
    e.number(request.expected_revision);
    encode_time(&mut e, request.as_of);
    match &request.operation {
        Operation::Replace(content) => {
            e.number(0);
            e.digest(content.digest());
        }
        Operation::Publish {
            validation,
            lifecycle,
        } => {
            e.number(1);
            encode_validation(&mut e, validation);
            e.digest(*lifecycle);
        }
        Operation::Retry {
            ring,
            publication,
            attempt,
        } => {
            e.number(4);
            e.number(ring.index() as u64);
            e.digest(publication.digest());
            e.number(*attempt);
        }
        Operation::Record {
            ring,
            publication,
            attempt,
            outcome,
        } => {
            e.number(5);
            e.number(ring.index() as u64);
            e.digest(publication.digest());
            e.number(*attempt);
            match outcome {
                PublicationResult::Unknown(v) => {
                    e.number(1);
                    encode_evidence(&mut e, v);
                }
                PublicationResult::NotApplied(v) => {
                    e.number(2);
                    encode_evidence(&mut e, v);
                }
                PublicationResult::Applied(v) => {
                    e.number(3);
                    encode_evidence(&mut e, v);
                }
            }
        }
        Operation::Quarantine => e.number(6),
        Operation::Deprecate => e.number(7),
    }
    e.finish()
}
