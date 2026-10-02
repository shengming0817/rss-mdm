//! Validate bounded native XML against pinned XSDs without a filesystem or network resolver.
//! ref: xsd-schema 0.2.0 pipeline.rs and validation/quick_xml_driver.rs.
use super::Error;
use std::{cell::RefCell, collections::BTreeMap};
use xsd_schema::validation::{
    SchemaValidator, SchemaValidity, ValidationError, ValidationFlags, ValidationSink,
    ValidationWarning, drive_quick_xml,
};
use xsd_schema::{SchemaSet, parse_schema_only, process_loaded_schemas};

thread_local! {
    // Keys can only come from generated native definitions, never a request-supplied schema.
    static SCHEMAS: RefCell<BTreeMap<&'static str, Result<SchemaSet, Error>>> = const { RefCell::new(BTreeMap::new()) };
}
struct Rejection<'a>(&'a mut bool);
impl ValidationSink for Rejection<'_> {
    fn on_error(&mut self, _: ValidationError) {
        *self.0 = true;
    }
    fn on_warning(&mut self, _: ValidationWarning) {
        *self.0 = true;
    }
}

fn compile(source: &str) -> Result<SchemaSet, Error> {
    let mut schema = SchemaSet::new();
    // Two-phase loading deliberately never follows schemaLocation or instance hints.
    parse_schema_only(source.as_bytes(), "native.xsd", &mut schema)
        .map_err(|_| Error::UnresolvedConstraint)?;
    if source.contains("schemaLocation=\"EapHostConfig.xsd\"") {
        for (name, source) in [
            (
                "EapHostConfig.xsd",
                include_str!("../../schema/upstream/xsd/EapHostConfig.xsd"),
            ),
            (
                "EapCommon.xsd",
                include_str!("../../schema/upstream/xsd/EapCommon.xsd"),
            ),
            (
                "BaseEapMethodConfig.xsd",
                include_str!("../../schema/upstream/xsd/BaseEapMethodConfig.xsd"),
            ),
        ] {
            parse_schema_only(source.as_bytes(), name, &mut schema)
                .map_err(|_| Error::UnresolvedConstraint)?;
        }
    }
    process_loaded_schemas(&mut schema).map_err(|_| Error::UnresolvedConstraint)?;
    Ok(schema)
}

pub(super) fn validate(source: &'static str, xml: &str) -> Result<(), Error> {
    let limits = crate::CodecLimits::default();
    crate::xml::document(xml.as_bytes(), limits.field_bytes, &limits).map_err(|e| {
        if e == crate::CodecError::LimitExceeded {
            Error::Limit
        } else {
            Error::Value
        }
    })?;
    SCHEMAS.with(|schemas| {
        let mut schemas = schemas.borrow_mut();
        let schema = schemas
            .entry(source)
            .or_insert_with(|| compile(source))
            .as_ref()
            .map_err(|e| *e)?;
        let flags = ValidationFlags::PROCESS_IDENTITY_CONSTRAINTS
            | ValidationFlags::REPORT_WARNINGS
            | ValidationFlags::STRICT_MODE;
        let validator = SchemaValidator::new(schema, flags);
        let mut failed = false;
        let result = {
            let mut runtime = validator.start_run(Rejection(&mut failed));
            runtime.set_unparsed_entities(Default::default());
            drive_quick_xml(xml.as_bytes(), &mut runtime, schema).map_err(|_| Error::Value)?
        };
        if failed || result.root_validity != Some(SchemaValidity::Valid) {
            Err(Error::Value)
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fixed_ddf_xsd_compiles_with_only_its_pinned_dependencies() {
        let schemas = super::super::generated::NODES
            .iter()
            .flat_map(|n| n.constraints)
            .filter(|c| c.kind == "XSD")
            .flat_map(|c| c.values)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!schemas.is_empty());
        for source in schemas {
            assert!(compile(source).is_ok());
        }
    }
}
