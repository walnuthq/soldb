#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapServerConfig {
    pub adapter_id: String,
}

impl Default for DapServerConfig {
    fn default() -> Self {
        Self {
            adapter_id: "soldb".to_owned(),
        }
    }
}
