//! Authenticated physical locations. Logical manifests only name immutable pieces.
use crate::{
    Error,
    backend::{Coordinate, Intent},
    journal,
};
use rss_mdm_content_s3::Content;
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Location {
    pub generation: Uuid,
    pub piece: Uuid,
    pub content: Content,
    pub intent: Intent,
    pub coordinate: Option<Coordinate>,
}

impl Location {
    fn key(generation: Uuid, piece: Uuid) -> String {
        format!("location:{generation}:{piece}")
    }

    pub(crate) fn seal(
        &self,
        protector: &Protector,
        tenant: TenantId,
    ) -> Result<serde_json::Value, Error> {
        journal::sign_document(
            protector,
            tenant,
            &Self::key(self.generation, self.piece),
            self,
        )
    }

    pub(crate) fn open(
        protector: &Protector,
        tenant: TenantId,
        generation: Uuid,
        piece: Uuid,
        content: Content,
        document: serde_json::Value,
    ) -> Result<Self, Error> {
        let value: Self =
            journal::verify_document(protector, tenant, &Self::key(generation, piece), document)?;
        if value.generation != generation || value.piece != piece || value.content != content {
            return Err(Error::Invariant);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_authentication_binds_tenant_generation_piece_and_content() {
        let protector = Protector::new(&[39; 32]).unwrap();
        let tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
        let other_tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
        let generation = Uuid::new_v4();
        let piece = Uuid::new_v4();
        let content = Content {
            length: 3,
            sha256: [7; 32],
        };
        let value = Location {
            generation,
            piece,
            content,
            intent: Intent::Volume {
                scope: [1; 32],
                id: piece,
            },
            coordinate: Some(Coordinate::Volume {
                scope: [1; 32],
                id: piece,
            }),
        };
        let sealed = value.seal(&protector, tenant).unwrap();
        assert!(
            Location::open(
                &protector,
                tenant,
                generation,
                piece,
                content,
                sealed.clone()
            )
            .is_ok()
        );
        for (t, g, p, c) in [
            (other_tenant, generation, piece, content),
            (tenant, Uuid::new_v4(), piece, content),
            (tenant, generation, Uuid::new_v4(), content),
            (
                tenant,
                generation,
                piece,
                Content {
                    length: 4,
                    ..content
                },
            ),
        ] {
            assert!(Location::open(&protector, t, g, p, c, sealed.clone()).is_err());
        }
        let mut altered = sealed;
        altered["value"]["coordinate"]["id"] = serde_json::json!(Uuid::new_v4());
        assert!(Location::open(&protector, tenant, generation, piece, content, altered).is_err());
    }
}

#[cfg(test)]
mod logical_format_tests {
    use super::*;

    #[test]
    fn logical_piece_rejects_embedded_physical_coordinates() {
        let piece = serde_json::json!({
            "id": Uuid::new_v4(), "offset": 0, "length": 3,
            "content": {"length": 3, "sha256": vec![7u8; 32]},
        });
        assert!(serde_json::from_value::<crate::journal::Piece>(piece.clone()).is_ok());
        let mut old = piece;
        old["coordinate"] =
            serde_json::json!({"kind":"volume","scope":vec![1u8;32],"id":Uuid::new_v4()});
        assert!(serde_json::from_value::<crate::journal::Piece>(old).is_err());
    }
}
