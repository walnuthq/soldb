use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub message_type: String,
    pub payload: serde_json::Value,
}
