//! Authenticated Agent capability facts.
pub type Pending<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::Error>> + Send + 'a>>;
#[derive(Clone)]
pub struct Binding {
    pub execution_context: rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<rss_mdm_agent_wire::runtime::Capability>,
}
impl Binding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1)
    }
    pub fn script(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::TaskExecuteV1)
    }
    pub fn software(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.is_software())
    }
    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::MdmEnrollmentV1)
    }
    pub fn native_collection(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryNativeV1)
    }
    pub fn task(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceUnmanageV1)
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceAccessV1)
            || self.script()
            || self.software()
            || self.enrollment()
            || self.native_collection()
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::CredentialsWindowsV1)
    }
}
