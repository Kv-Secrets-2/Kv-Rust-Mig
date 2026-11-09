//! The hook's one-line JSON reply, serialized the way Python's `json.dumps` does.

use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Python `_allow`: `{}`.
    Allow,
    /// Python `_deny(reason)`.
    Deny(String),
}

impl Reply {
    pub fn is_deny(&self) -> bool {
        matches!(self, Reply::Deny(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Reply::Allow => None,
            Reply::Deny(reason) => Some(reason),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Reply::Allow => json!({}),
            Reply::Deny(reason) => json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }),
        }
    }

    /// `json.dumps(reply)` followed by a newline (Python's `print`).
    pub fn to_line(&self) -> Vec<u8> {
        let mut bytes = kv_store::pyjson::to_vec_python(&self.to_json(), false)
            .unwrap_or_else(|_| b"{}".to_vec());
        bytes.push(b'\n');
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::Reply;

    #[test]
    fn python_json_dumps_shape() {
        assert_eq!(Reply::Allow.to_line(), b"{}\n");
        let line = Reply::Deny("[kv-secrets] blocked: é".into()).to_line();
        assert_eq!(
            String::from_utf8(line).unwrap(),
            "{\"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \
             \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \
             \"[kv-secrets] blocked: \\u00e9\"}}\n"
        );
    }
}
