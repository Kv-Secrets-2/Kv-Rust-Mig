use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
};

use kv_approvals::{
    artifacts,
    canonical::{artifact_canonical_json, canonical_json},
    owner::{self, OwnerGrantFields, OwnerSeed},
    pause::{self, PauseContext},
    permit,
    wire::{self, FieldType, FieldValue, MessageFields, MessageKind},
};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("../../../fixtures/v0.4.0/approvals.json")).unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn field_value(field_type: FieldType, value: &Value) -> FieldValue {
    match field_type {
        FieldType::Nonce | FieldType::Bytes => {
            let raw = value
                .as_object()
                .and_then(|object| object.get("hex"))
                .and_then(Value::as_str)
                .map(|value| hex::decode(value).unwrap())
                .or_else(|| value.as_str().map(|value| hex::decode(value).unwrap()))
                .unwrap();
            if field_type == FieldType::Nonce {
                FieldValue::Nonce(raw)
            } else {
                FieldValue::Bytes(raw)
            }
        }
        FieldType::Text => FieldValue::Text(value.as_str().unwrap().to_owned()),
        FieldType::Bool => FieldValue::Bool(value.as_bool().unwrap()),
        FieldType::Enum(_) => FieldValue::Enum(value.as_str().unwrap().to_owned()),
        FieldType::List(parts) => FieldValue::List(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    item.as_array()
                        .unwrap()
                        .iter()
                        .zip(parts)
                        .map(|(part, field_type)| field_value(*field_type, part))
                        .collect()
                })
                .collect(),
        ),
    }
}

fn message_fields(kind: MessageKind, raw: &Value) -> MessageFields {
    let mut fields = BTreeMap::new();
    for schema in kind.fields() {
        fields.insert(
            schema.name.to_owned(),
            field_value(schema.field_type, &raw[schema.name]),
        );
    }
    fields
}

fn owner_seed(root: &Value) -> OwnerSeed {
    OwnerSeed::from_slice(&hex_bytes(&root["inputs"]["seed"])).unwrap()
}

struct OwnerFieldsOwned {
    request_id: String,
    request_digest: String,
    request_expires_at_epoch: Value,
    local_approval_id: Vec<u8>,
    location: Vec<u8>,
    owner_key_id: String,
    environment: String,
    network: Value,
    network_reason: Value,
    max_runs: Value,
    calls_per_run: Value,
    provider_digests: Value,
    session_nonce: Vec<u8>,
}

impl OwnerFieldsOwned {
    fn from_payload(payload: &Value) -> Self {
        Self {
            request_id: payload["request_id"].as_str().unwrap().to_owned(),
            request_digest: payload["request_digest"].as_str().unwrap().to_owned(),
            request_expires_at_epoch: payload["request_expires_at_epoch"].clone(),
            local_approval_id: hex_bytes(&payload["local_approval_id"]),
            location: hex_bytes(&payload["location"]),
            owner_key_id: payload["owner_key_id"].as_str().unwrap().to_owned(),
            environment: payload["environment"].as_str().unwrap().to_owned(),
            network: payload["network"].clone(),
            network_reason: payload["network_reason"].clone(),
            max_runs: payload["max_runs"].clone(),
            calls_per_run: payload["calls_per_run"].clone(),
            provider_digests: payload["provider_digests"].clone(),
            session_nonce: hex_bytes(&payload["session_nonce"]),
        }
    }

    fn borrow(&self) -> OwnerGrantFields<'_> {
        OwnerGrantFields {
            request_id: &self.request_id,
            request_digest: &self.request_digest,
            request_expires_at_epoch: self.request_expires_at_epoch.clone(),
            local_approval_id: &self.local_approval_id,
            location: &self.location,
            owner_key_id: &self.owner_key_id,
            environment: &self.environment,
            network: self.network.clone(),
            network_reason: self.network_reason.clone(),
            max_runs: self.max_runs.clone(),
            calls_per_run: self.calls_per_run.clone(),
            provider_digests: &self.provider_digests,
            session_nonce: &self.session_nonce,
        }
    }
}

#[test]
fn canonical_json_matches_python_vectors() {
    let root = fixture();
    for vector in root["canonical_json"].as_array().unwrap() {
        if let Some(expected) = vector.get("ok").and_then(Value::as_str) {
            assert_eq!(canonical_json(&vector["input"]).unwrap(), expected);
        }
    }
    let float = json!({"x": [1, 2.0]});
    assert_eq!(
        canonical_json(&float).unwrap_err().to_string(),
        "$.x[1]: float is not allowed in canonical JSON"
    );
    assert_eq!(
        artifact_canonical_json(&json!({"é": 1.0})).unwrap(),
        r#"{"\u00e9":1.0}"#
    );
}

#[test]
fn frame_and_all_wire_message_vectors_match_python() {
    let root = fixture();
    for vector in root["frame"].as_array().unwrap() {
        let input = hex_bytes(&vector["in"]);
        assert_eq!(hex::encode(wire::frame(&input)), vector["out"]);
    }
    assert_eq!(
        MessageKind::ALL.len(),
        root["wire_messages"].as_array().unwrap().len()
    );
    for vector in root["wire_messages"].as_array().unwrap() {
        let kind = MessageKind::from_name(vector["type"].as_str().unwrap()).unwrap();
        assert_eq!(wire::schema_json(kind), vector["schema"]);
        let fields = message_fields(kind, &vector["fields"]);
        let encoded = wire::encode(kind, &fields).unwrap();
        assert_eq!(hex::encode(&encoded), vector["encoding"]);
        let key = hex_bytes(&root["inputs"]["daemon_key"]);
        let tag = wire::mac(&key, kind, &fields).unwrap();
        assert_eq!(hex::encode(tag), vector["mac"]);
        assert!(wire::verify(&key, kind, &fields, &tag));
        assert_eq!(
            wire::to_json(kind, &fields, &tag).unwrap(),
            vector["to_json"]
        );
        let (decoded_kind, decoded_fields, decoded_tag) =
            wire::from_json(&vector["to_json"]).unwrap();
        assert_eq!(decoded_kind, kind);
        assert_eq!(decoded_fields, fields);
        assert_eq!(decoded_tag, tag);
        assert!(wire::verify(
            &key,
            decoded_kind,
            &decoded_fields,
            &decoded_tag
        ));
    }
}

#[test]
fn wire_malformed_inputs_return_errors_without_panicking() {
    let kind = MessageKind::RetireAckV1;
    let fields = MessageFields::from([
        ("challenge".to_owned(), FieldValue::Nonce(vec![0; 32])),
        ("session_nonce".to_owned(), FieldValue::Nonce(vec![1; 32])),
        ("result".to_owned(), FieldValue::Enum("retired".to_owned())),
    ]);
    let tag = wire::mac(&[7; 32], kind, &fields).unwrap();
    assert!(wire::mac(&[7; 31], kind, &fields).is_err());
    assert!(!wire::verify(&[7; 31], kind, &fields, &tag));
    assert!(!wire::verify(&[7; 32], kind, &fields, &tag[..31]));
    assert!(!wire::verify(&[7; 32], kind, &fields, &[0; 32]));
    let mut missing = fields.clone();
    missing.remove("result");
    assert_eq!(
        wire::encode(kind, &missing).unwrap_err().to_string(),
        "retire-ack-v1: fields must be exactly ['challenge', 'session_nonce', 'result']"
    );
    let mut extra = fields.clone();
    extra.insert("unexpected".to_owned(), FieldValue::Text(String::new()));
    assert!(wire::encode(kind, &extra).is_err());
    let unknown = json!({"type": "unknown-v1", "fields": {}, "mac": "00".repeat(32)});
    assert!(wire::from_json(&unknown).is_err());

    let channel = MessageKind::ChannelV1;
    let channel_fixture = fixture();
    let original = message_fields(channel, &channel_fixture["wire_messages"][0]["fields"]);
    let mut oversized = original.clone();
    oversized.insert(
        "daemon_version".to_owned(),
        FieldValue::Text("a".repeat(wire::MAX_FIELD_BYTES + 1)),
    );
    assert_eq!(
        wire::encode(channel, &oversized).unwrap_err().to_string(),
        "daemon_version: too long"
    );
    let mut channel_fields = original;
    channel_fields.insert(
        "providers".to_owned(),
        FieldValue::List(vec![
            vec![
                FieldValue::Text("provider".into()),
                FieldValue::Text("secret".into()),
            ];
            wire::MAX_LIST_ITEMS + 1
        ]),
    );
    assert!(wire::encode(channel, &channel_fields).is_err());

    for operation in [
        std::panic::catch_unwind(|| wire::verify(&[], kind, &fields, &[])).unwrap(),
        std::panic::catch_unwind(|| wire::from_json(&json!({"type": [], "fields": {}, "mac": ""})))
            .unwrap()
            .is_ok(),
    ] {
        assert!(!operation);
    }
}

#[test]
fn owner_grant_payload_signature_and_verification_vectors_match() {
    let root = fixture();
    let seed = owner_seed(&root);
    let public_key = owner::owner_public_key(&seed);
    assert_eq!(hex::encode(public_key), root["owner_public_key"]);
    let payload = &root["owner_grant"]["payload"];
    let fields = OwnerFieldsOwned::from_payload(payload);
    let fields_ref = fields.borrow();
    let grant = &root["owner_grant"]["grant"];
    let built =
        owner::owner_grant_payload(grant, payload["artifact_id"].as_str().unwrap(), &fields_ref)
            .unwrap();
    assert_eq!(built, *payload);
    let message = owner::owner_grant_message(&built).unwrap();
    assert_eq!(hex::encode(message), root["owner_grant"]["message"]);
    let signature = owner::sign_payload(&seed, &built).unwrap();
    assert_eq!(
        hex::encode(signature),
        root["owner_grant"]["signed_grant"]["owner_approval"]["signature"]
    );
    assert_eq!(
        owner::owner_key_id(&public_key, &fields.local_approval_id),
        root["owner_key_id"]
    );

    for vector in root["owner_grant_verify"].as_array().unwrap() {
        let key = match vector["key"].as_str().unwrap() {
            "owner" => hex_bytes(&root["owner_public_key"]),
            "other" => hex_bytes(&root["other_owner_public_key"]),
            raw => hex::decode(raw).unwrap(),
        };
        let actual = owner::verified_owner_payload(&key, &vector["grant"]);
        if vector["expected"].is_null() {
            assert!(actual.is_none(), "{}", vector["name"]);
        } else {
            assert_eq!(
                actual,
                Some(vector["expected"].clone()),
                "{}",
                vector["name"]
            );
        }
    }

    for vector in root["owner_grant_payload_errors"].as_array().unwrap() {
        let mut changed = OwnerFieldsOwned::from_payload(payload);
        let override_object = vector["override"].as_object().unwrap();
        if let Some(value) = override_object.get("network") {
            changed.network = value.clone();
        }
        if let Some(value) = override_object.get("max_runs") {
            changed.max_runs = value.clone();
        }
        if let Some(value) = override_object.get("calls_per_run") {
            changed.calls_per_run = value.clone();
        }
        let error = owner::owner_grant_payload(
            grant,
            payload["artifact_id"].as_str().unwrap(),
            &changed.borrow(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), vector["error"]);
    }

    let attached = owner::attach_owner_approval(grant, &seed, &fields_ref).unwrap();
    let artifact_id = attached["owner_approval"]["payload"]["artifact_id"]
        .as_str()
        .unwrap();
    assert_eq!(artifact_id.len(), "owner_approval_".len() + 24);
    assert!(owner::verified_owner_payload(&public_key, &attached).is_some());
}

#[test]
fn permit_and_pause_vectors_match_python() {
    let root = fixture();
    let seed = owner_seed(&root);
    let public_key = owner::owner_public_key(&seed);

    let permit_facts = &root["permit"]["facts"];
    let permit_message = permit::permit_message(permit_facts).unwrap();
    assert_eq!(hex::encode(permit_message), root["permit"]["message"]);
    let artifact = permit::attach_permit_approval(permit_facts, &seed).unwrap();
    assert_eq!(artifact, root["permit"]["artifact"]);
    assert_eq!(
        permit::verified_permit_payload(true, &public_key, &artifact),
        Some(permit_facts.clone())
    );
    for vector in root["permit_verify"].as_array().unwrap() {
        let key = match vector["key"].as_str().unwrap() {
            "owner" => hex_bytes(&root["owner_public_key"]),
            "other" => hex_bytes(&root["other_owner_public_key"]),
            raw => hex::decode(raw).unwrap(),
        };
        let actual = permit::verified_permit_payload(
            vector["protected"].as_bool().unwrap_or(false),
            &key,
            &vector["artifact"],
        );
        if vector["expected"].is_null() {
            assert!(actual.is_none(), "{}", vector["name"]);
        } else {
            assert_eq!(
                actual,
                Some(vector["expected"].clone()),
                "{}",
                vector["name"]
            );
        }
    }

    let context = PauseContext {
        protected: true,
        owner_public_key: &public_key,
    };
    let answer = &root["pause_answer"];
    let expected_answer = &answer["artifact"];
    let answer_payload = &expected_answer["payload"];
    let attached_answer = pause::attach_pause_answer(
        &answer["facts"],
        &seed,
        answer_payload["decision"].as_str().unwrap(),
        answer_payload["add_calls"].as_i64().unwrap(),
        answer_payload["add_seconds"].as_i64().unwrap(),
        Some(answer_payload["ends_at_epoch"].as_i64().unwrap()),
    )
    .unwrap();
    assert_eq!(attached_answer, *expected_answer);
    assert_eq!(
        pause::verified_pause_answer(&context, expected_answer),
        Some(answer_payload.clone())
    );
    for vector in root["pause_answer_verify"].as_array().unwrap() {
        let actual = pause::verified_pause_answer(
            &PauseContext {
                protected: vector["protected"].as_bool().unwrap_or(false),
                owner_public_key: &public_key,
            },
            &vector["artifact"],
        );
        if vector["expected"].is_null() {
            assert!(actual.is_none(), "{}", vector["name"]);
        } else {
            assert_eq!(
                actual,
                Some(vector["expected"].clone()),
                "{}",
                vector["name"]
            );
        }
    }

    let right = &root["pause_right"]["artifact"];
    assert_eq!(
        pause::attach_pause_right(&right["payload"], &seed).unwrap(),
        *right
    );
    assert_eq!(
        pause::verified_pause_right(&context, right),
        Some(right["payload"].clone())
    );
    for vector in root["pause_right_verify"].as_array().unwrap() {
        let actual = pause::verified_pause_right(
            &PauseContext {
                protected: vector["protected"].as_bool().unwrap_or(false),
                owner_public_key: &public_key,
            },
            &vector["artifact"],
        );
        if vector["expected"].is_null() {
            assert!(actual.is_none(), "{}", vector["name"]);
        } else {
            assert_eq!(
                actual,
                Some(vector["expected"].clone()),
                "{}",
                vector["name"]
            );
        }
    }

    for case in answer["end_cases"].as_array().unwrap() {
        let facts = json!({"pass_expires_at_epoch": case["pass_expires_at_epoch"]});
        assert_eq!(
            pause::pause_answer_end(
                &facts,
                case["add_seconds"].as_i64().unwrap(),
                case["now"].as_i64().unwrap(),
            ),
            case["end"].as_i64()
        );
    }
    let job = &root["pause_job_message"];
    assert_eq!(
        hex::encode(pause::pause_job_message(&job["fields"]).unwrap()),
        job["message"]
    );
    let proof = &root["pause_proof"];
    let answer_key = hex_bytes(&root["inputs"]["answer_key"]);
    assert_eq!(
        pause::pause_answer_proof(
            &answer_key,
            proof["kind"].as_str().unwrap(),
            &proof["fields"]
        )
        .unwrap(),
        proof["proof"]
    );
    assert!(pause::pause_answer_proven(
        &answer_key,
        proof["kind"].as_str().unwrap(),
        &proof["fields"],
        proof["proof"].as_str().unwrap()
    ));
    assert!(!pause::pause_answer_proven(
        &[1; 31],
        proof["kind"].as_str().unwrap(),
        &proof["fields"],
        proof["proof"].as_str().unwrap()
    ));
    assert_eq!(
        pause::snapshot_proof_fields(
            proof["snapshot_fields"]["nonce"].as_str().unwrap(),
            &proof["snapshot_reply"]
        )
        .unwrap(),
        proof["snapshot_fields"]
    );

    let seal = &root["pause_seal"];
    let daemon_key = hex_bytes(&root["inputs"]["daemon_key"]);
    let answer_key = hex_bytes(&root["inputs"]["answer_key"]);
    let right_public_key = seal["right_public_key"].as_str().unwrap();
    let session_nonce = seal["session_nonce"].as_str().unwrap();
    let opened = pause::open_pause_answer_key(
        &daemon_key,
        seal["sealed"].as_str().unwrap(),
        right_public_key,
        session_nonce,
    )
    .unwrap();
    assert_eq!(hex::encode(&*opened), seal["opens"]);
    assert!(
        pause::open_pause_answer_key(
            &daemon_key,
            seal["sealed"].as_str().unwrap(),
            right_public_key,
            "wrong-session"
        )
        .is_none()
    );
    let newly_sealed =
        pause::seal_pause_answer_key(&daemon_key, &answer_key, right_public_key, session_nonce)
            .unwrap();
    assert_eq!(newly_sealed.len(), seal["sealed"].as_str().unwrap().len());
    assert_eq!(
        hex::encode(
            &*pause::open_pause_answer_key(
                &daemon_key,
                &newly_sealed,
                right_public_key,
                session_nonce
            )
            .unwrap()
        ),
        seal["opens"]
    );
}

#[test]
fn hmac_artifact_digest_and_signing_key_vectors_match() {
    let root = fixture();
    let key = hex_bytes(&root["inputs"]["hmac_key"]);
    let artifact = &root["hmac_grant_artifact"];
    let artifact_id = "approval_cdcdcdcdcdcdcdcdcdcdcdcd";
    let payload = artifacts::grant_payload(&artifact["grant"], artifact_id).unwrap();
    assert_eq!(payload, artifact["payload"]);
    assert_eq!(
        hex::encode(artifact_canonical_json(&payload).unwrap()),
        artifact["payload_bytes"]
    );
    let mut signed_grant = artifact["grant"].as_object().unwrap().clone();
    signed_grant.insert(
        "approval_artifact".to_owned(),
        json!({
            "version": 1,
            "artifact_id": artifact_id,
            "signer": artifacts::SIGNER,
            "payload_sha256": artifact["payload_sha256"],
            "signature": artifact["signature"],
        }),
    );
    let signed_grant = Value::Object(signed_grant);
    assert!(artifacts::verify_grant_approval_artifact(
        &key,
        &signed_grant
    ));
    let attached_grant =
        artifacts::attach_grant_approval_artifact(&artifact["grant"], &key).unwrap();
    assert!(artifacts::verify_grant_approval_artifact(
        &key,
        &attached_grant
    ));

    let state = &root["grant_state"];
    assert_eq!(
        artifacts::grant_state_payload(&state["grant"]).unwrap(),
        state["payload"]
    );
    assert_eq!(
        hex::encode(artifact_canonical_json(&state["payload"]).unwrap()),
        state["payload_bytes"]
    );
    let signed_state = artifacts::attach_grant_state_integrity(&state["grant"], &key).unwrap();
    assert_eq!(signed_state["state_integrity"], state["integrity"]);
    assert!(artifacts::verify_grant_state_integrity(&key, &signed_state));
    let (id, digest) = artifacts::grant_approval_ref(&state["grant"]);
    assert_eq!(
        id.as_deref(),
        Some("owner_approval_abababababababababababab")
    );
    assert_eq!(
        digest.as_deref(),
        Some("c9b97932118702bcbf77a2be2abfb30b5d5397ffce1c13d37b23b247287a6cae")
    );

    let token = &root["token_integrity"];
    let token_payload = json!({"type": "admitted_capability_v1", "record": token["record"]});
    assert_eq!(
        hex::encode(artifact_canonical_json(&token_payload).unwrap()),
        token["bytes"]
    );
    let signed_token = artifacts::attach_token_integrity(&token["record"], &key).unwrap();
    assert_eq!(signed_token["token_integrity"], token["integrity"]);
    assert!(artifacts::verify_token_integrity(&signed_token, &key));

    let request = &root["request_integrity_payload"];
    assert_eq!(
        artifacts::approval_request_payload(&request["request"]).unwrap(),
        request["payload"]
    );
    assert_eq!(
        hex::encode(artifact_canonical_json(&request["payload"]).unwrap()),
        request["payload_bytes"]
    );
    let signed_request =
        artifacts::attach_approval_request_integrity(&request["request"], &key).unwrap();
    assert!(artifacts::verify_approval_request_integrity(
        &signed_request,
        &key
    ));
    let parsed = artifacts::parse_signing_key(
        root["signing_key_file"]["valid"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(hex::encode(*parsed), root["signing_key_file"]["parsed"]);
    let valid_signing_key = root["signing_key_file"]["valid"].as_str().unwrap();
    assert_eq!(
        hex::encode(
            *artifacts::parse_signing_key(
                format!("{} \n", valid_signing_key.replace('=', "%=")).as_bytes()
            )
            .unwrap()
        ),
        root["signing_key_file"]["parsed"]
    );
    assert!(artifacts::parse_signing_key(b"not a signing key").is_err());

    for vector in root["request_digests"].as_array().unwrap() {
        assert_eq!(
            wire::request_content_digest(&vector["request"]).unwrap(),
            vector["digest"]
        );
    }
    let provider = &root["provider_digest"];
    assert_eq!(
        wire::provider_digest(&provider["definition"]).unwrap(),
        provider["digest"]
    );
}

#[test]
fn rust_signed_owner_grant_and_permit_verify_in_python_when_configured() {
    let Some(python) = kv_test_support::python_reference() else {
        eprintln!("SKIP Python approval cross-check: KV_PY_REF is unset");
        return;
    };
    let root = fixture();
    let seed = owner_seed(&root);
    let public_key = owner::owner_public_key(&seed);
    let payload = &root["owner_grant"]["payload"];
    let fields = OwnerFieldsOwned::from_payload(payload);
    let grant =
        owner::attach_owner_approval(&root["owner_grant"]["grant"], &seed, &fields.borrow())
            .unwrap();
    let permit = permit::attach_permit_approval(&root["permit"]["facts"], &seed).unwrap();
    let input = json!({
        "public_key": hex::encode(public_key),
        "grant": grant,
        "permit": permit,
    });
    let script = format!(
        "{}/../../fixtures/gen/check_approvals_cross.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = Command::new(python)
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Python cross-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("PASS Rust owner grant"));
}
