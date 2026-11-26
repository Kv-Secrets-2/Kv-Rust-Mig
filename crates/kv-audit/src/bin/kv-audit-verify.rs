#[cfg(unix)]
mod implementation {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use kv_audit::{
        ChainHead, ChainKey, ChainPosition, ChainTrust, ChainVerification, VaultIdentity,
        verify_directory,
    };
    use rustix::fs::{Mode, OFlags};
    use serde_json::{Value, json};

    const MAX_TRUST_FILE_BYTES: u64 = 16 * 1024;
    const EXIT_TRUNCATED: i32 = 10;
    const EXIT_CORRUPTED: i32 = 11;
    const EXIT_CONTINUITY_LOSS: i32 = 12;
    const EXIT_MISSING_TRUST: i32 = 13;
    const EXIT_UNREADABLE: i32 = 14;
    const EXIT_USAGE: i32 = 64;

    fn usage() -> &'static str {
        "usage: kv-audit-verify --directory DIR [--trust-file PATH]\n\
     trust file JSON: {\"v\":1,\"key\":\"<64 lowercase hex>\",\"identity\":\"<lowercase hex>\",\"head\":\"<64 lowercase hex>\",\"count\":0}\n\
     use --trust-file - to read the trust JSON from stdin"
    }

    fn hex_decode_lower(text: &str) -> Result<Vec<u8>, String> {
        if !text.len().is_multiple_of(2) {
            return Err("hex value has an odd length".into());
        }
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        }
        let mut output = Vec::with_capacity(text.len() / 2);
        for pair in text.as_bytes().chunks_exact(2) {
            let high = nibble(pair[0]).ok_or_else(|| "hex value is not lowercase".to_owned())?;
            let low = nibble(pair[1]).ok_or_else(|| "hex value is not lowercase".to_owned())?;
            output.push((high << 4) | low);
        }
        Ok(output)
    }

    #[cfg(target_os = "macos")]
    fn trust_file_has_acl(file: &fs::File) -> Result<bool, String> {
        kv_audit::darwin_file_has_acl(file).map_err(|_| "trust file ACL is unreadable".to_owned())
    }

    #[cfg(not(target_os = "macos"))]
    fn trust_file_has_acl(_file: &fs::File) -> Result<bool, String> {
        Ok(false)
    }

    fn read_trust_bytes(path: &str) -> Result<Vec<u8>, String> {
        if path == "-" {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_TRUST_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "could not read trust JSON from stdin".to_owned())?;
            if bytes.len() as u64 > MAX_TRUST_FILE_BYTES {
                return Err("trust JSON exceeds its bound".into());
            }
            return Ok(bytes);
        }
        let descriptor = rustix::fs::open(
            Path::new(path),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "trust file is unreadable".to_owned())?;
        let file = fs::File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| "trust file is unreadable".to_owned())?;
        if !metadata.file_type().is_file() {
            return Err("trust file must be a regular file".into());
        }
        if metadata.len() > MAX_TRUST_FILE_BYTES {
            return Err("trust JSON exceeds its bound".into());
        }
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || trust_file_has_acl(&file)?
        {
            return Err(
                "trust file must be owned by this account and have no group/other access".into(),
            );
        }
        let mut bytes = Vec::new();
        file.take(MAX_TRUST_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "trust file is unreadable".to_owned())?;
        if bytes.len() as u64 > MAX_TRUST_FILE_BYTES {
            return Err("trust JSON exceeds its bound".into());
        }
        Ok(bytes)
    }

    fn trust_from_file(path: &str) -> Result<ChainTrust, String> {
        let bytes = read_trust_bytes(path)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "trust JSON is malformed".to_owned())?;
        let object = value
            .as_object()
            .ok_or_else(|| "trust JSON must be an object".to_owned())?;
        if object.len() != 5 || object.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("trust JSON has an unsupported shape".into());
        }
        let key_text = object
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| "trust key is missing".to_owned())?;
        let key_bytes = hex_decode_lower(key_text)?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "trust key must be 32 bytes".to_owned())?;
        let identity_text = object
            .get("identity")
            .and_then(Value::as_str)
            .ok_or_else(|| "trust identity is missing".to_owned())?;
        let identity = VaultIdentity::new(hex_decode_lower(identity_text)?)
            .map_err(|error| error.to_string())?;
        let head = ChainHead::from_hex(
            object
                .get("head")
                .and_then(Value::as_str)
                .ok_or_else(|| "trust head is missing".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        let count = object
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| "trust count is missing".to_owned())?;
        Ok(ChainTrust::new(
            ChainKey::new(key),
            identity,
            ChainPosition { count, head },
        ))
    }

    fn position_json(position: ChainPosition) -> Value {
        json!({"count": position.count, "head": position.head.to_hex()})
    }

    fn report_json(report: ChainVerification) -> Value {
        let mut output = json!({"status": report.status().as_str()});
        match report {
            ChainVerification::MissingTrustState => {}
            ChainVerification::Valid { position } => {
                output["count"] = json!(position.count);
                output["head"] = json!(position.head.to_hex());
            }
            ChainVerification::Truncated {
                line,
                valid_entries,
            } => {
                output["line"] = json!(line);
                output["valid_entries"] = json!(valid_entries);
            }
            ChainVerification::Corrupted {
                line,
                valid_entries,
                reason,
            } => {
                output["line"] = json!(line);
                output["valid_entries"] = json!(valid_entries);
                output["reason"] = json!(reason.as_str());
            }
            ChainVerification::ContinuityLoss {
                expected,
                actual,
                valid_entries,
                mismatch,
            } => {
                output["expected"] = position_json(expected);
                output["actual"] = position_json(actual);
                output["valid_entries"] = json!(valid_entries);
                output["position_mismatch"] = json!(mismatch.as_str());
            }
            ChainVerification::Unreadable { reason } => {
                output["reason"] = json!(reason.as_str());
            }
        }
        output
    }

    fn exit_code(report: ChainVerification) -> i32 {
        match report {
            ChainVerification::Valid { .. } => 0,
            ChainVerification::Truncated { .. } => EXIT_TRUNCATED,
            ChainVerification::Corrupted { .. } => EXIT_CORRUPTED,
            ChainVerification::ContinuityLoss { .. } => EXIT_CONTINUITY_LOSS,
            ChainVerification::MissingTrustState => EXIT_MISSING_TRUST,
            ChainVerification::Unreadable { .. } => EXIT_UNREADABLE,
        }
    }

    pub(crate) fn run() {
        let mut directory = None;
        let mut trust_file = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if matches!(argument.as_str(), "--help" | "-h") {
                println!("{}", usage());
                return;
            }
            if !matches!(argument.as_str(), "--directory" | "--trust-file") {
                eprintln!("unknown argument {argument}\n{}", usage());
                std::process::exit(EXIT_USAGE);
            }
            let Some(value) = arguments.next() else {
                eprintln!("missing value for {argument}\n{}", usage());
                std::process::exit(EXIT_USAGE);
            };
            match argument.as_str() {
                "--directory" => directory = Some(value),
                "--trust-file" => trust_file = Some(value),
                _ => unreachable!("argument kind was validated"),
            }
        }
        let Some(directory) = directory else {
            eprintln!("missing --directory\n{}", usage());
            std::process::exit(EXIT_USAGE);
        };
        let trust = match trust_file {
            Some(path) => match trust_from_file(&path) {
                Ok(trust) => Some(trust),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(EXIT_USAGE);
                }
            },
            None => None,
        };
        let report = verify_directory(directory, trust.as_ref());
        println!(
            "{}",
            serde_json::to_string(&report_json(report)).expect("fixed verifier report is JSON")
        );
        std::process::exit(exit_code(report));
    }
}

fn main() {
    #[cfg(unix)]
    implementation::run();
    #[cfg(not(unix))]
    {
        eprintln!("kv-audit-verify is implemented for Unix audit storage");
        std::process::exit(64);
    }
}
