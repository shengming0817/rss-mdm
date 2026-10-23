//! A query certificate is qualified by the real verifier for one exact trust snapshot.
//! ref: rustls 0.23.45 src/webpki/client_verifier.rs::verify_client_cert.
use super::*;

/// Bump whenever the live verifier's qualification semantics change.
pub const VERSION: i32 = 1;

/// An interval certified by the live verifier, never a device authentication proof.
pub struct CertificateWindow {
    start: i64,
    end: i64,
}
impl CertificateWindow {
    pub fn start(&self) -> i64 {
        self.start
    }
    pub fn end(&self) -> i64 {
        self.end
    }
}
impl DeviceTrust {
    /// All time predicates are constant inside this interval. Revocation, CRL authority,
    /// issuer ordering, purpose and path validation are delegated to the original verifier.
    /// The PKI owner must bind the result to exact DER and trust bytes, and independently
    /// exclude queued revocations at query time. Trust replacement invalidates the result.
    pub fn certificate_window(&self, der: &[u8]) -> Result<Option<CertificateWindow>, Error> {
        if der.is_empty() || der.len() > 32768 {
            return Err(Error::Malformed);
        }
        let leaf = Certificate::from_der(der).map_err(invalid)?;
        let snapshot = self.inner.read().map_err(invalid)?;
        // Match exactly verify()'s first signature-matching generation. Never skip a
        // revoked, expired or otherwise ineligible match in favor of a later issuer.
        let selected = snapshot.generations.iter().find(|generation| {
            leaf.tbs_certificate.issuer == generation.certificate.tbs_certificate.subject
                && leaf.tbs_certificate.to_der().ok().is_some_and(|bytes| {
                    leaf.signature.as_bytes().is_some_and(|signature| {
                        signed(
                            &generation.certificate,
                            &leaf.signature_algorithm,
                            &bytes,
                            signature,
                        )
                        .is_ok()
                    })
                })
        });
        let Some(selected) = selected else {
            return Ok(None);
        };
        let time = |v: x509_cert::time::Time| {
            i64::try_from(v.to_unix_duration().as_secs()).map_err(invalid)
        };
        let mut start = time(leaf.tbs_certificate.validity.not_before)?.max(1);
        // webpki includes the leaf's notAfter second; our CA and CRL bounds are exclusive.
        let mut end = time(leaf.tbs_certificate.validity.not_after)?
            .checked_add(1)
            .ok_or(Error::Malformed)?;
        for generation in &snapshot.generations {
            start = start
                .max(generation.crl.this_update)
                .max(generation.root_crl.this_update);
            end = end
                .min(generation.crl.next_update)
                .min(generation.root_crl.next_update);
            if generation.public.mode != Mode::VerifyOnly || std::ptr::eq(generation, selected) {
                for cert in [&generation.certificate, &generation.root] {
                    start = start.max(time(cert.tbs_certificate.validity.not_before)?);
                    end = end.min(time(cert.tbs_certificate.validity.not_after)?);
                }
            }
        }
        if start >= end {
            return Ok(None);
        }
        // snapshot() already checked signatures, shape and CRL authority. Its only
        // additional new()/restore() difference is CA time, covered by these bounds.
        if Self::verify_snapshot(&snapshot, &[CertificateDer::from(der)], start).is_err() {
            return Ok(None);
        }
        Ok(Some(CertificateWindow { start, end }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Trust, Vec<u8>, i64) {
        let fixture: serde_json::Value =
            serde_json::from_slice(include_bytes!("../fixtures/windows-linked-proof.json"))
                .unwrap();
        let wire = fixture["wire"].as_str().unwrap();
        let token = wire
            .split("<o:BinarySecurityToken ")
            .nth(1)
            .unwrap()
            .split_once('>')
            .unwrap()
            .1
            .split("</o:BinarySecurityToken>")
            .next()
            .unwrap();
        (
            serde_json::from_value(fixture["trust"].clone()).unwrap(),
            STANDARD.decode(token).unwrap(),
            fixture["at"].as_i64().unwrap(),
        )
    }
    #[test]
    fn qualification_interval_matches_live_verification_at_all_boundaries() {
        let (public, der, now) = fixture();
        let trust = DeviceTrust::new(public.clone(), Purpose::Windows, now).unwrap();
        let window = trust.certificate_window(&der).unwrap().unwrap();
        for at in [
            window.start - 1,
            window.start,
            now,
            window.end - 1,
            window.end,
        ] {
            let live = DeviceTrust::new(public.clone(), Purpose::Windows, at)
                .and_then(|t| t.verify(&[CertificateDer::from(der.as_slice())], at))
                .is_ok();
            assert_eq!(live, at >= window.start && at < window.end, "at {at}");
        }
    }
    #[test]
    fn qualification_keeps_the_first_matching_issuers_revocation_decision() {
        let (public, der, now) = fixture();
        let trust = DeviceTrust::new(public, Purpose::Windows, now).unwrap();
        let leaf = Certificate::from_der(&der).unwrap();
        {
            let mut snapshot = trust.inner.write().unwrap();
            // A later matching generation must not bypass the first one's denial.
            let later = snapshot.generations[0].clone();
            snapshot.generations[0]
                .crl
                .revoked
                .push(serial(leaf.tbs_certificate.serial_number.as_bytes()));
            snapshot.generations.push(later);
        }
        assert!(
            trust
                .verify(&[CertificateDer::from(der.as_slice())], now)
                .is_err()
        );
        assert!(trust.certificate_window(&der).unwrap().is_none());
    }
    #[test]
    fn qualification_cannot_turn_an_invalid_leaf_into_a_query_identity() {
        let (public, mut der, now) = fixture();
        let trust = DeviceTrust::new(public, Purpose::Windows, now).unwrap();
        let last = der.len() - 1;
        der[last] ^= 1;
        assert!(
            trust
                .verify(&[CertificateDer::from(der.as_slice())], now)
                .is_err()
        );
        assert!(trust.certificate_window(&der).unwrap().is_none());
    }
}
