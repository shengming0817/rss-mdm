pub(crate) use rss_mdm_agent_channel::*;
#[cfg(test)]
#[path = "../agent/mod.rs"]
pub(crate) mod t2;
impl From<crate::Error> for AgentError {
    fn from(e: crate::Error) -> Self {
        Self::from(rss_mdm_flow_service::Error::from(e))
    }
}
