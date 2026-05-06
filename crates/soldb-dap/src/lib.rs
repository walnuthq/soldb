use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod server;

pub use server::{run_stdio_server, DapServer};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DapFrameError {
    MissingHeaderEnd,
    MissingContentLength,
    InvalidContentLength,
    IncompleteBody { expected: usize, actual: usize },
    InvalidJson(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DapMessage {
    pub seq: u64,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl DapMessage {
    pub fn request(seq: u64, command: impl Into<String>, arguments: Option<Value>) -> Self {
        Self {
            seq,
            message_type: "request".to_owned(),
            command: Some(command.into()),
            event: None,
            request_seq: None,
            success: None,
            message: None,
            arguments,
            body: None,
        }
    }

    pub fn response(
        seq: u64,
        request: &DapMessage,
        success: bool,
        body: Option<Value>,
        message: Option<String>,
    ) -> Self {
        Self {
            seq,
            message_type: "response".to_owned(),
            command: request.command.clone(),
            event: None,
            request_seq: Some(request.seq),
            success: Some(success),
            message,
            arguments: None,
            body,
        }
    }

    pub fn event(seq: u64, event: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            seq,
            message_type: "event".to_owned(),
            command: None,
            event: Some(event.into()),
            request_seq: None,
            success: None,
            message: None,
            arguments: None,
            body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    pub id: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    pub id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    pub line: u64,
    pub column: u64,
}

pub fn initialize_body(adapter_id: &str) -> Value {
    json!({
        "adapterID": adapter_id,
        "supportsConfigurationDoneRequest": true,
        "supportsEvaluateForHovers": true,
        "supportsStepBack": false,
        "supportsSetVariable": false,
        "supportsRestartRequest": false,
    })
}

pub fn threads_body(thread_id: u64, name: &str) -> Value {
    json!({
        "threads": [
            Thread {
                id: thread_id,
                name: name.to_owned(),
            }
        ]
    })
}

pub fn stack_trace_body(frames: Vec<StackFrame>) -> Value {
    json!({
        "stackFrames": frames,
        "totalFrames": frames.len(),
    })
}

pub fn encode_dap_frame(message: &DapMessage) -> serde_json::Result<Vec<u8>> {
    let body = serde_json::to_vec(message)?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let mut frame = Vec::with_capacity(header.len() + body.len());
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_dap_frame(input: &[u8]) -> Result<(DapMessage, usize), DapFrameError> {
    let header_end = find_header_end(input).ok_or(DapFrameError::MissingHeaderEnd)?;
    let headers = std::str::from_utf8(&input[..header_end])
        .map_err(|error| DapFrameError::InvalidJson(error.to_string()))?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim())
            })
        })
        .ok_or(DapFrameError::MissingContentLength)?
        .parse::<usize>()
        .map_err(|_| DapFrameError::InvalidContentLength)?;

    let body_start = header_end + 4;
    let actual = input.len().saturating_sub(body_start);
    if actual < content_length {
        return Err(DapFrameError::IncompleteBody {
            expected: content_length,
            actual,
        });
    }

    let body_end = body_start + content_length;
    let message = serde_json::from_slice::<DapMessage>(&input[body_start..body_end])
        .map_err(|error| DapFrameError::InvalidJson(error.to_string()))?;
    Ok((message, body_end))
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        decode_dap_frame, encode_dap_frame, initialize_body, stack_trace_body, threads_body,
        DapFrameError, DapMessage, DapServerConfig, Source, StackFrame,
    };

    #[test]
    fn default_config_uses_soldb_adapter_id() {
        assert_eq!(DapServerConfig::default().adapter_id, "soldb");
    }

    #[test]
    fn request_response_and_event_shapes_match_dap() {
        let request = DapMessage::request(1, "initialize", Some(json!({"clientID": "test"})));
        let response =
            DapMessage::response(2, &request, true, Some(initialize_body("soldb")), None);
        let event = DapMessage::event(3, "initialized", None);

        assert_eq!(request.message_type, "request");
        assert_eq!(response.request_seq, Some(1));
        assert_eq!(response.command.as_deref(), Some("initialize"));
        assert_eq!(response.success, Some(true));
        assert_eq!(response.body.as_ref().expect("body")["adapterID"], "soldb");
        assert_eq!(event.message_type, "event");
        assert_eq!(event.event.as_deref(), Some("initialized"));
    }

    #[test]
    fn encodes_and_decodes_content_length_frames() {
        let request = DapMessage::request(7, "threads", None);
        let frame = encode_dap_frame(&request).expect("encode frame");
        let (decoded, consumed) = decode_dap_frame(&frame).expect("decode frame");

        assert!(frame.starts_with(b"Content-Length: "));
        assert_eq!(decoded, request);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decodes_one_frame_from_buffer_with_trailing_data() {
        let first = encode_dap_frame(&DapMessage::request(1, "threads", None)).expect("first");
        let second = encode_dap_frame(&DapMessage::request(2, "stackTrace", None)).expect("second");
        let mut buffer = first.clone();
        buffer.extend_from_slice(&second);

        let (decoded, consumed) = decode_dap_frame(&buffer).expect("decode first");

        assert_eq!(decoded.seq, 1);
        assert_eq!(consumed, first.len());
        assert!(buffer[consumed..].starts_with(b"Content-Length: "));
    }

    #[test]
    fn reports_incomplete_or_invalid_frames() {
        assert_eq!(
            decode_dap_frame(b"Content-Length: 10\r\n\r\n{}"),
            Err(DapFrameError::IncompleteBody {
                expected: 10,
                actual: 2
            })
        );
        assert_eq!(
            decode_dap_frame(b"Content-Length: nope\r\n\r\n{}"),
            Err(DapFrameError::InvalidContentLength)
        );
        assert_eq!(
            decode_dap_frame(b"Header: value\r\n\r\n{}"),
            Err(DapFrameError::MissingContentLength)
        );
        assert_eq!(
            decode_dap_frame(b"Content-Length: 2\r\n{}"),
            Err(DapFrameError::MissingHeaderEnd)
        );
    }

    #[test]
    fn builds_common_response_bodies() {
        let threads = threads_body(1, "main");
        assert_eq!(threads["threads"][0]["name"], "main");

        let frames = vec![StackFrame {
            id: 1,
            name: "increment".to_owned(),
            source: Some(Source {
                name: "TestContract.sol".to_owned(),
                path: "/tmp/TestContract.sol".to_owned(),
            }),
            line: 10,
            column: 1,
        }];
        let body = stack_trace_body(frames);

        assert_eq!(body["totalFrames"], 1);
        assert_eq!(body["stackFrames"][0]["name"], "increment");
        assert_eq!(body["stackFrames"][0]["source"]["name"], "TestContract.sol");
    }
}
