use serde_json::Value;
/// Publication sources differ from already complete immediate-call values.
#[derive(Clone, Copy)]
pub enum Parameters<'a> {
    Sources(&'a rss_mdm_policy::ParameterSources),
    Values(&'a Value),
}
impl Parameters<'_> {
    pub fn checked(
        self,
        definition: &rss_mdm_resource::ScriptDefinition,
    ) -> crate::transaction::Result<rss_mdm_policy::ParameterSources> {
        use rss_mdm_policy::{ParameterSource, ParameterSources};
        let sources = match self {
            Self::Sources(sources) => sources.clone(),
            Self::Values(values) => {
                definition
                    .validate_parameters(values)
                    .map_err(|_| crate::Error::Malformed)?;
                ParameterSources(
                    values
                        .as_object()
                        .ok_or(crate::Error::Malformed)?
                        .iter()
                        .map(|(k, v)| (k.clone(), ParameterSource::Fixed { value: v.clone() }))
                        .collect(),
                )
            }
        };
        sources.validate()?;
        let properties = definition
            .spec()
            .parameters
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(crate::Error::Malformed)?;
        if sources.0.len() != properties.len()
            || sources.0.keys().any(|k| !properties.contains_key(k))
        {
            return Err(crate::Error::Malformed.into());
        }
        definition
            .validate_fixed_parameters(&sources.fixed_values())
            .map_err(|_| crate::Error::Malformed)?;
        Ok(sources)
    }
}
