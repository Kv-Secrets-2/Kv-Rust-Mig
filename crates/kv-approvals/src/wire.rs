use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::{ApprovalError, canonical::canonical_json};

pub const FRAME_LEN: usize = 8;
pub const NONCE_LEN: usize = 32;
pub const MAC_LEN: usize = 32;
pub const MAX_FIELD_BYTES: usize = 256 * 1024;
pub const MAX_LIST_ITEMS: usize = 1000;

const NONCE: FieldType = FieldType::Nonce;
const BYTES: FieldType = FieldType::Bytes;
const TEXT: FieldType = FieldType::Text;
const BOOL: FieldType = FieldType::Bool;
const PROTECTED_MODE: &[&str] = &["protected", "unprotected"];
const REGISTERED_STATUS: &[&str] = &["registered", "already-registered", "job-ended"];
const PERMIT_STATUS: &[&str] = &["registered", "already-registered"];
const PAUSE_STATUS: &[&str] = &["extended", "refused"];
const TARGET_KIND: &[&str] = &["request", "grant"];
const REVOKE_RESULT: &[&str] = &["revoked"];
const RETIRE_RESULT: &[&str] = &["retired"];
const END_JOB_RESULT: &[&str] = &["ended", "started", "unknown"];
const END_JOB_RECORD: &[&str] = &["removed", "not-saved", "kept"];
const TEXT_TEXT: &[FieldType] = &[TEXT, TEXT];
const TEXT_NONCE_TEXT_TEXT_TEXT: &[FieldType] = &[TEXT, NONCE, TEXT, TEXT, TEXT];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    ChannelV1,
    RequestRecordV1,
    GrantRegisterAckV1,
    PermitRequestV1,
    PermitRegisterAckV1,
    PauseRequestV1,
    PauseAnswerAckV1,
    HttpRuleV1,
    RevokeAckV1,
    RetireAckV1,
    ErrorV1,
    EndJobV1,
    EndJobAckV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Nonce,
    Bytes,
    Text,
    Bool,
    Enum(&'static [&'static str]),
    List(&'static [FieldType]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: &'static str,
    pub field_type: FieldType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    Nonce(Vec<u8>),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Enum(String),
    List(Vec<Vec<FieldValue>>),
}

pub type MessageFields = BTreeMap<String, FieldValue>;

const CHANNEL_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "mode",
        field_type: FieldType::Enum(PROTECTED_MODE),
    },
    FieldSchema {
        name: "owner_key_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "local_approval_id",
        field_type: BYTES,
    },
    FieldSchema {
        name: "location",
        field_type: BYTES,
    },
    FieldSchema {
        name: "daemon_version",
        field_type: TEXT,
    },
    FieldSchema {
        name: "providers",
        field_type: FieldType::List(TEXT_TEXT),
    },
];
const REQUEST_RECORD_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "content_digest",
        field_type: TEXT,
    },
    FieldSchema {
        name: "environment",
        field_type: TEXT,
    },
    FieldSchema {
        name: "network",
        field_type: BOOL,
    },
    FieldSchema {
        name: "network_reason",
        field_type: TEXT,
    },
];
const GRANT_REGISTER_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "grant_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "payload_digest",
        field_type: TEXT,
    },
    FieldSchema {
        name: "status",
        field_type: FieldType::Enum(REGISTERED_STATUS),
    },
];
const PERMIT_REQUEST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "facts_json",
        field_type: TEXT,
    },
    FieldSchema {
        name: "body_text",
        field_type: TEXT,
    },
    FieldSchema {
        name: "caller_headers_json",
        field_type: TEXT,
    },
    FieldSchema {
        name: "requester_json",
        field_type: TEXT,
    },
];
const PERMIT_REGISTER_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "permit_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "payload_digest",
        field_type: TEXT,
    },
    FieldSchema {
        name: "status",
        field_type: FieldType::Enum(PERMIT_STATUS),
    },
];
const PAUSE_REQUEST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "facts_json",
        field_type: TEXT,
    },
];
const PAUSE_ANSWER_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "request_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "payload_digest",
        field_type: TEXT,
    },
    FieldSchema {
        name: "status",
        field_type: FieldType::Enum(PAUSE_STATUS),
    },
];
const HTTP_RULE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "provider",
        field_type: TEXT,
    },
    FieldSchema {
        name: "rule_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "provider_json",
        field_type: TEXT,
    },
    FieldSchema {
        name: "rule_json",
        field_type: TEXT,
    },
];
const REVOKE_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "mode",
        field_type: FieldType::Enum(PROTECTED_MODE),
    },
    FieldSchema {
        name: "target_kind",
        field_type: FieldType::Enum(TARGET_KIND),
    },
    FieldSchema {
        name: "target_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "revoke_mode",
        field_type: TEXT,
    },
    FieldSchema {
        name: "hits",
        field_type: FieldType::List(TEXT_NONCE_TEXT_TEXT_TEXT),
    },
    FieldSchema {
        name: "result",
        field_type: FieldType::Enum(REVOKE_RESULT),
    },
];
const RETIRE_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "result",
        field_type: FieldType::Enum(RETIRE_RESULT),
    },
];
const ERROR_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "code",
        field_type: TEXT,
    },
];
const END_JOB_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "job_id",
        field_type: TEXT,
    },
];
const END_JOB_ACK_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "challenge",
        field_type: NONCE,
    },
    FieldSchema {
        name: "session_nonce",
        field_type: NONCE,
    },
    FieldSchema {
        name: "job_id",
        field_type: TEXT,
    },
    FieldSchema {
        name: "result",
        field_type: FieldType::Enum(END_JOB_RESULT),
    },
    FieldSchema {
        name: "record",
        field_type: FieldType::Enum(END_JOB_RECORD),
    },
];

impl MessageKind {
    pub const ALL: [Self; 13] = [
        Self::ChannelV1,
        Self::RequestRecordV1,
        Self::GrantRegisterAckV1,
        Self::PermitRequestV1,
        Self::PermitRegisterAckV1,
        Self::PauseRequestV1,
        Self::PauseAnswerAckV1,
        Self::HttpRuleV1,
        Self::RevokeAckV1,
        Self::RetireAckV1,
        Self::ErrorV1,
        Self::EndJobV1,
        Self::EndJobAckV1,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::ChannelV1 => "channel-v1",
            Self::RequestRecordV1 => "request-record-v1",
            Self::GrantRegisterAckV1 => "grant-register-ack-v1",
            Self::PermitRequestV1 => "permit-request-v1",
            Self::PermitRegisterAckV1 => "permit-register-ack-v1",
            Self::PauseRequestV1 => "pause-request-v1",
            Self::PauseAnswerAckV1 => "pause-answer-ack-v1",
            Self::HttpRuleV1 => "http-rule-v1",
            Self::RevokeAckV1 => "revoke-ack-v1",
            Self::RetireAckV1 => "retire-ack-v1",
            Self::ErrorV1 => "error-v1",
            Self::EndJobV1 => "end-job-v1",
            Self::EndJobAckV1 => "end-job-ack-v1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    pub fn fields(self) -> &'static [FieldSchema] {
        match self {
            Self::ChannelV1 => CHANNEL_FIELDS,
            Self::RequestRecordV1 => REQUEST_RECORD_FIELDS,
            Self::GrantRegisterAckV1 => GRANT_REGISTER_ACK_FIELDS,
            Self::PermitRequestV1 => PERMIT_REQUEST_FIELDS,
            Self::PermitRegisterAckV1 => PERMIT_REGISTER_ACK_FIELDS,
            Self::PauseRequestV1 => PAUSE_REQUEST_FIELDS,
            Self::PauseAnswerAckV1 => PAUSE_ANSWER_ACK_FIELDS,
            Self::HttpRuleV1 => HTTP_RULE_FIELDS,
            Self::RevokeAckV1 => REVOKE_ACK_FIELDS,
            Self::RetireAckV1 => RETIRE_ACK_FIELDS,
            Self::ErrorV1 => ERROR_FIELDS,
            Self::EndJobV1 => END_JOB_FIELDS,
            Self::EndJobAckV1 => END_JOB_ACK_FIELDS,
        }
    }
}

pub fn schema_json(kind: MessageKind) -> Value {
    Value::Array(
        kind.fields()
            .iter()
            .map(|field| {
                Value::Array(vec![
                    Value::String(field.name.to_owned()),
                    field_type_json(field.field_type),
                ])
            })
            .collect(),
    )
}

fn field_type_json(field_type: FieldType) -> Value {
    match field_type {
        FieldType::Nonce => Value::String("nonce".to_owned()),
        FieldType::Bytes => Value::String("bytes".to_owned()),
        FieldType::Text => Value::String("text".to_owned()),
        FieldType::Bool => Value::String("bool".to_owned()),
        FieldType::Enum(options) => Value::Array(
            std::iter::once(Value::String("enum".to_owned()))
                .chain(
                    options
                        .iter()
                        .map(|option| Value::String((*option).to_owned())),
                )
                .collect(),
        ),
        FieldType::List(parts) => Value::Array(vec![
            Value::String("list".to_owned()),
            Value::Array(parts.iter().copied().map(field_type_json).collect()),
        ]),
    }
}

pub fn frame(item: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(FRAME_LEN + item.len());
    output.extend_from_slice(&(item.len() as u64).to_be_bytes());
    output.extend_from_slice(item);
    output
}

pub fn encode(kind: MessageKind, fields: &MessageFields) -> Result<Vec<u8>, ApprovalError> {
    let expected: Vec<&str> = kind.fields().iter().map(|field| field.name).collect();
    if fields.len() != expected.len() || expected.iter().any(|key| !fields.contains_key(*key)) {
        let display = expected
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("{}: fields must be exactly [{display}]", kind.name()).into());
    }

    let mut output = frame(kind.name().as_bytes());
    for schema in kind.fields() {
        let value = fields.get(schema.name).expect("validated field set");
        match schema.field_type {
            FieldType::List(parts) => {
                let FieldValue::List(items) = value else {
                    return Err(format!(
                        "{}: must be a list of at most {MAX_LIST_ITEMS} items",
                        schema.name
                    )
                    .into());
                };
                if items.len() > MAX_LIST_ITEMS {
                    return Err(format!(
                        "{}: must be a list of at most {MAX_LIST_ITEMS} items",
                        schema.name
                    )
                    .into());
                }
                output.extend_from_slice(&frame(items.len().to_string().as_bytes()));
                for (index, item) in items.iter().enumerate() {
                    if item.len() != parts.len() {
                        return Err(format!(
                            "{}[{index}]: must have {} parts",
                            schema.name,
                            parts.len()
                        )
                        .into());
                    }
                    for (part_type, part) in parts.iter().copied().zip(item) {
                        let bytes =
                            field_bytes(part_type, part, &format!("{}[{index}]", schema.name))?;
                        output.extend_from_slice(&frame(&bytes));
                    }
                }
            }
            field_type => {
                let bytes = field_bytes(field_type, value, schema.name)?;
                output.extend_from_slice(&frame(&bytes));
            }
        }
    }
    Ok(output)
}

fn field_bytes(
    field_type: FieldType,
    value: &FieldValue,
    name: &str,
) -> Result<Vec<u8>, ApprovalError> {
    let bytes = match (field_type, value) {
        (FieldType::Nonce, FieldValue::Nonce(bytes)) => {
            if bytes.len() != NONCE_LEN {
                return Err(format!("{name}: must be {NONCE_LEN} bytes").into());
            }
            return Ok(bytes.clone());
        }
        (FieldType::Bytes, FieldValue::Bytes(bytes)) => bytes.clone(),
        (FieldType::Text, FieldValue::Text(text)) => text.as_bytes().to_vec(),
        (FieldType::Bool, FieldValue::Bool(value)) => {
            return Ok(if *value { &b"true"[..] } else { &b"false"[..] }.to_vec());
        }
        (FieldType::Enum(options), FieldValue::Enum(value)) => {
            if !options.contains(&value.as_str()) {
                return Err(format!("{name}: must be one of {}", options.join(", ")).into());
            }
            if !value.is_ascii() {
                return Err(format!("{name}: must be one of {}", options.join(", ")).into());
            }
            value.as_bytes().to_vec()
        }
        (FieldType::Enum(options), _) => {
            return Err(format!("{name}: must be one of {}", options.join(", ")).into());
        }
        (FieldType::Nonce, _) => {
            return Err(format!("{name}: must be {NONCE_LEN} bytes").into());
        }
        (FieldType::Bytes, _) => return Err(format!("{name}: must be bytes").into()),
        (FieldType::Text, _) => return Err(format!("{name}: must be text").into()),
        (FieldType::Bool, _) => return Err(format!("{name}: must be a Boolean").into()),
        (FieldType::List(_), _) => unreachable!("list fields are encoded by the caller"),
    };
    if bytes.len() > MAX_FIELD_BYTES {
        return Err(format!("{name}: too long").into());
    }
    Ok(bytes)
}

pub fn mac(
    key: &[u8],
    kind: MessageKind,
    fields: &MessageFields,
) -> Result<[u8; 32], ApprovalError> {
    if key.len() != MAC_LEN {
        return Err("the daemon-auth key must be 32 bytes".into());
    }
    let encoded = encode(kind, fields)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify(key: &[u8], kind: MessageKind, fields: &MessageFields, tag: &[u8]) -> bool {
    if key.len() != MAC_LEN || tag.len() != MAC_LEN {
        return false;
    }
    let Ok(encoded) = encode(kind, fields) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(&encoded);
    mac.verify_slice(tag).is_ok()
}

pub fn to_json(
    kind: MessageKind,
    fields: &MessageFields,
    tag: &[u8],
) -> Result<Value, ApprovalError> {
    encode(kind, fields)?;
    let mut json_fields = Map::new();
    for schema in kind.fields() {
        let value = fields.get(schema.name).expect("validated field set");
        let json_value = match schema.field_type {
            FieldType::List(parts) => {
                let FieldValue::List(items) = value else {
                    return Err(format!(
                        "{}: must be a list of at most {MAX_LIST_ITEMS} items",
                        schema.name
                    )
                    .into());
                };
                Value::Array(
                    items
                        .iter()
                        .map(|item| {
                            Value::Array(
                                parts
                                    .iter()
                                    .copied()
                                    .zip(item)
                                    .map(|(part_type, part)| field_json(part_type, part))
                                    .collect(),
                            )
                        })
                        .collect(),
                )
            }
            field_type => field_json(field_type, value),
        };
        json_fields.insert(schema.name.to_owned(), json_value);
    }
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String(kind.name().to_owned()));
    object.insert("fields".to_owned(), Value::Object(json_fields));
    object.insert("mac".to_owned(), Value::String(hex::encode(tag)));
    Ok(Value::Object(object))
}

fn field_json(field_type: FieldType, value: &FieldValue) -> Value {
    match (field_type, value) {
        (
            FieldType::Nonce | FieldType::Bytes,
            FieldValue::Nonce(bytes) | FieldValue::Bytes(bytes),
        ) => Value::String(hex::encode(bytes)),
        (FieldType::Text, FieldValue::Text(value))
        | (FieldType::Enum(_), FieldValue::Enum(value)) => Value::String(value.clone()),
        (FieldType::Bool, FieldValue::Bool(value)) => Value::Bool(*value),
        _ => Value::Null,
    }
}

pub fn from_json(value: &Value) -> Result<(MessageKind, MessageFields, Vec<u8>), ApprovalError> {
    let Value::Object(object) = value else {
        return Err("not a MACed message".into());
    };
    if object.len() != 3
        || !object.contains_key("type")
        || !object.contains_key("fields")
        || !object.contains_key("mac")
    {
        return Err("not a MACed message".into());
    }
    let Some(type_name) = object.get("type").and_then(Value::as_str) else {
        return Err("unknown message type".into());
    };
    let Some(kind) = MessageKind::from_name(type_name) else {
        return Err("unknown message type".into());
    };
    let Value::Object(raw_fields) = &object["fields"] else {
        return Err(format!("{type_name}: wrong fields").into());
    };
    if raw_fields.len() != kind.fields().len()
        || kind
            .fields()
            .iter()
            .any(|field| !raw_fields.contains_key(field.name))
    {
        return Err(format!("{type_name}: wrong fields").into());
    }
    let Some(tag_hex) = object.get("mac").and_then(Value::as_str) else {
        return Err("bad MAC field".into());
    };
    if tag_hex.len() != 2 * MAC_LEN {
        return Err("bad MAC field".into());
    }
    let tag = decode_hex(tag_hex).ok_or_else(|| ApprovalError::from("bad MAC field"))?;

    let mut fields = MessageFields::new();
    for schema in kind.fields() {
        let raw = &raw_fields[schema.name];
        let field = match schema.field_type {
            FieldType::List(parts) => {
                let Some(items) = raw.as_array() else {
                    return Err(format!("{}: must be a list", schema.name).into());
                };
                if items.len() > MAX_LIST_ITEMS {
                    return Err(format!("{}: must be a list", schema.name).into());
                }
                let mut decoded = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let Some(parts_json) = item.as_array() else {
                        return Err(format!("{}[{index}]: wrong parts", schema.name).into());
                    };
                    if parts_json.len() != parts.len() {
                        return Err(format!("{}[{index}]: wrong parts", schema.name).into());
                    }
                    let mut decoded_item = Vec::with_capacity(parts.len());
                    for (part_type, part_value) in parts.iter().copied().zip(parts_json) {
                        decoded_item.push(part_from_json(
                            part_type,
                            part_value,
                            &format!("{}[{index}]", schema.name),
                        )?);
                    }
                    decoded.push(decoded_item);
                }
                FieldValue::List(decoded)
            }
            field_type => part_from_json(field_type, raw, schema.name)?,
        };
        fields.insert(schema.name.to_owned(), field);
    }
    encode(kind, &fields)?;
    Ok((kind, fields, tag))
}

fn part_from_json(
    field_type: FieldType,
    value: &Value,
    name: &str,
) -> Result<FieldValue, ApprovalError> {
    match field_type {
        FieldType::Nonce | FieldType::Bytes => {
            let Some(hex_text) = value.as_str() else {
                return Err(format!("{name}: must be hex text").into());
            };
            let bytes = decode_hex(hex_text)
                .ok_or_else(|| ApprovalError::Message(format!("{name}: not hex")))?;
            Ok(if field_type == FieldType::Nonce {
                FieldValue::Nonce(bytes)
            } else {
                FieldValue::Bytes(bytes)
            })
        }
        FieldType::Text => Ok(value
            .as_str()
            .map(|text| FieldValue::Text(text.to_owned()))
            .unwrap_or_else(|| FieldValue::Bool(false))),
        FieldType::Enum(_) => Ok(value
            .as_str()
            .map(|text| FieldValue::Enum(text.to_owned()))
            .unwrap_or_else(|| FieldValue::Bool(false))),
        FieldType::Bool => Ok(value
            .as_bool()
            .map(FieldValue::Bool)
            .unwrap_or_else(|| FieldValue::Text(String::new()))),
        FieldType::List(_) => unreachable!("list field parts are not supported"),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(compact).ok()
}

pub fn request_content_digest(request: &Value) -> Result<String, ApprovalError> {
    let Value::Object(object) = request else {
        return Err("a request must be an object".into());
    };
    const KEYS: &[&str] = &[
        "request_id",
        "argv",
        "cwd",
        "command_fingerprint",
        "script_kind",
        "script_sha256",
        "script_ref_hash",
        "secret_names",
        "capability_names",
        "max_calls",
        "actor",
        "reason",
        "source",
        "risk_level",
        "risk_card",
        "environment",
        "network",
        "network_reason",
        "created_at_epoch",
        "expires_at_epoch",
    ];
    let has_v2 = object
        .get("calls_per_service")
        .is_some_and(|value| !value.is_null());
    let has_v3 = object
        .get("recommended_ttl_seconds")
        .is_some_and(|value| !value.is_null());
    let mut projection = Map::new();
    for key in KEYS {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            projection.insert((*key).to_owned(), value.clone());
        }
    }
    if (has_v2 || has_v3)
        && let Some(value) = object
            .get("calls_per_service")
            .filter(|value| !value.is_null())
    {
        projection.insert("calls_per_service".to_owned(), value.clone());
    }
    if has_v3
        && let Some(value) = object
            .get("recommended_ttl_seconds")
            .filter(|value| !value.is_null())
    {
        projection.insert("recommended_ttl_seconds".to_owned(), value.clone());
    }
    let label: &[u8] = if has_v3 {
        b"kv-request-content-v3"
    } else if has_v2 {
        b"kv-request-content-v2"
    } else {
        b"kv-request-content-v1"
    };
    digest_framed(
        label,
        canonical_json(&Value::Object(projection))?.as_bytes(),
    )
}

pub fn provider_digest(definition: &Value) -> Result<String, ApprovalError> {
    if !definition.is_object() {
        return Err("a provider definition must be an object".into());
    }
    digest_framed(
        b"kv-provider-def-v1",
        canonical_json(definition)?.as_bytes(),
    )
}

fn digest_framed(label: &[u8], payload: &[u8]) -> Result<String, ApprovalError> {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(frame(label));
    digest.update(frame(payload));
    Ok(hex::encode(digest.finalize()))
}
