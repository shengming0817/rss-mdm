//! Decisions over native evidence; storage and current authority are adapter inputs.

pub(crate) struct Eligibility {
    pub latest: bool,
    pub within_deadline: bool,
    pub active: bool,
    pub authority_valid: bool,
}
impl Eligibility {
    pub fn allows(&self) -> bool {
        self.latest && self.within_deadline && self.active && self.authority_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_live_authority_guard_is_required() {
        for missing in 0..4 {
            let e = Eligibility {
                latest: missing != 0,
                within_deadline: missing != 1,
                active: missing != 2,
                authority_valid: missing != 3,
            };
            assert!(!e.allows());
        }
    }
}
