//! `kv/vault_registry.py`'s `register_vault`: the list of vaults in `~/.kv/vaults.json`.

use std::path::Path;

use serde_json::{Map, Value, json};

fn now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Registers `root` as a `kind` vault; any failure is the caller's warning.
pub fn register_vault(root: &Path, kind: &str) -> Result<(), String> {
    let folder = kv_store::vault_origin::state_dir().map_err(|e| e.to_string())?;
    if !folder.exists() {
        crate::fsutil::mkdir_private(&folder).map_err(|e| e.to_string())?;
    }
    let real = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    let real_text = real
        .to_str()
        .ok_or("the vault path is not text")?
        .to_owned();
    let file = folder.join("vaults.json");
    let mut entries: Vec<Value> = match std::fs::symlink_metadata(&file) {
        Ok(meta) if meta.is_file() => {
            let raw = std::fs::read(&file).map_err(|e| e.to_string())?;
            serde_json::from_slice::<Value>(&raw)
                .ok()
                .and_then(|v| v.get("vaults")?.as_array().cloned())
                .unwrap_or_default()
        }
        Ok(_) => return Err("~/.kv/vaults.json is not a plain file".into()),
        Err(_) => Vec::new(),
    };
    entries.retain(|e| e.get("path").and_then(Value::as_str) != Some(real_text.as_str()));
    let stamp = now();
    let name = if kind == "global" {
        "global".to_owned()
    } else {
        real.file_name()
            .and_then(|n| n.to_str())
            .map_or_else(|| real_text.clone(), str::to_owned)
    };
    entries.push(json!({
        "path": real_text,
        "kind": kind,
        "name": name,
        "created_at": stamp,
        "last_seen_at": stamp,
        "last_backup_at": Value::Null,
        "missing": false,
    }));
    for entry in &mut entries {
        if entry.get("missing").and_then(Value::as_bool) == Some(false)
            && let Some(obj) = entry.as_object_mut()
        {
            obj.insert("last_seen_at".into(), Value::String(stamp.clone()));
        }
    }
    let mut doc = Map::new();
    doc.insert("version".into(), json!(1));
    doc.insert("vaults".into(), Value::Array(entries));
    let payload = kv_store::pyjson::to_vec_indent2_ascii(&sort_keys(Value::Object(doc)))
        .map_err(|e| e.to_string())?;
    crate::fsutil::write_private_atomic(&file, &payload).map_err(|e| e.to_string())?;
    let mut fields = Map::new();
    fields.insert("path".into(), Value::String(real_text));
    fields.insert("kind".into(), Value::String(kind.to_owned()));
    let _ = kv_audit::Audit::new(folder).emit("vault_registered", fields);
    Ok(())
}

/// `json.dumps(sort_keys=True)`: every object's keys in code point order.
fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(String, Value)> = map.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(sorted.into_iter().map(|(k, v)| (k, sort_keys(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// `backup.last_backup_at(root)`: the vault's recorded last backup stamp, if well formed.
pub fn last_backup_at(root: &Path) -> Option<String> {
    let config = kv_store::config::load_config(root).ok()?.value;
    let stamp = config.get("backup")?.get("last_backup_at")?.as_str()?;
    let b = stamp.as_bytes();
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    let ok = b.len() == 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[19] == b'Z';
    ok.then(|| stamp.to_owned())
}
