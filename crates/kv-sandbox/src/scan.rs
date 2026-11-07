//! Leak scanning and file tracking after a run (Python `kv/sandbox.py`:
//! `leak_report`, `scan_leaked_files`, `collect_new_files`,
//! `scan_specific_files`, `snapshot_files`, `collect_changed_files`,
//! `track_new_files`). Every walk skips `.secrets` at any depth, never
//! follows links, and treats a read error as "nothing here".

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::paths::{path_is_or_under, real_or_lexical};
use crate::redact::{VariantLimits, Variants, build_secret_variants};

const CHUNK: usize = 1024 * 1024;
const OVERLAP: usize = 1024;
const MAX_SCAN: usize = 500 * 1024 * 1024;

/// `(size, mtime_ns, ctime_ns)` as Python `_file_fingerprint` records it.
pub type Fingerprint = (u64, i128, i128);

#[cfg(unix)]
fn times(meta: &std::fs::Metadata) -> (f64, f64, i128, i128) {
    use std::os::unix::fs::MetadataExt;
    let mtime_ns = i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec());
    let ctime_ns = i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec());
    (
        meta.mtime() as f64 + meta.mtime_nsec() as f64 / 1e9,
        meta.ctime() as f64 + meta.ctime_nsec() as f64 / 1e9,
        mtime_ns,
        ctime_ns,
    )
}

#[cfg(not(unix))]
fn times(meta: &std::fs::Metadata) -> (f64, f64, i128, i128) {
    let secs = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or((0.0, 0), |d| (d.as_secs_f64(), d.as_nanos() as i128))
    };
    let (m, mn) = secs(meta.modified());
    let (c, cn) = secs(meta.created());
    (m, c, mn, cn)
}

fn is_dir(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

/// Python `_file_fingerprint`.
pub fn file_fingerprint(path: &str) -> Option<Fingerprint> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let (_, _, mtime_ns, ctime_ns) = times(&meta);
    Some((meta.len(), mtime_ns, ctime_ns))
}

/// Directory entries as Python's `scandir` loop sees them: `(path, name,
/// is_dir, is_file)` without following links; `.secrets` skipped.
fn entries(dirpath: &str) -> Option<Vec<(String, std::fs::Metadata)>> {
    let read = std::fs::read_dir(dirpath).ok()?;
    let mut out = Vec::new();
    for entry in read.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name == ".secrets" {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        out.push((join(dirpath, &name), meta));
    }
    Some(out)
}

/// Decode as Python `open(..., "r", errors="ignore")`: invalid bytes dropped.
fn decode_ignoring(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).expect("valid prefix"));
                let skip = e.error_len().unwrap_or(rest.len() - valid);
                rest = &rest[valid + skip..];
            }
        }
    }
}

/// Does the file contain any variant? `Some(secret_name)` for the first hit
/// in Python's order; `None` when it does not or cannot be read.
fn file_leaks(path: &str, variants: &Variants) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; CHUNK];
    let mut prev_tail = String::new();
    let mut scanned = 0usize;
    let mut carry: Vec<u8> = Vec::new();
    while scanned < MAX_SCAN {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 && carry.is_empty() {
            break;
        }
        carry.extend_from_slice(&buffer[..read]);
        // Keep an incomplete trailing sequence for the next read.
        let cut = if read == 0 {
            carry.len()
        } else {
            match std::str::from_utf8(&carry) {
                Ok(_) => carry.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => carry.len(),
            }
        };
        let chunk = decode_ignoring(&carry[..cut]);
        carry.drain(..cut);
        if read == 0 && chunk.is_empty() {
            break;
        }
        scanned += chunk.chars().count();
        let window = format!("{prev_tail}{chunk}");
        for (variant, name) in variants.iter() {
            if window.contains(variant) {
                return Some(name.to_owned());
            }
        }
        prev_tail = if chunk.chars().count() > OVERLAP {
            chunk
                .chars()
                .rev()
                .take(OVERLAP)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        } else {
            chunk
        };
        if read == 0 {
            break;
        }
    }
    None
}

fn excluded(real: &str, exclude_dirs: &[String]) -> bool {
    exclude_dirs
        .iter()
        .any(|excluded| path_is_or_under(real, excluded, false))
}

/// Python `scan_leaked_files`: `(path, secret_name)` for every file written
/// since `before_time` that holds a secret variant.
pub fn scan_leaked_files<'a, I>(
    secrets: I,
    before_time: f64,
    scan_dirs: &[String],
    exclude_dirs: &[String],
) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let variants = build_secret_variants(secrets, VariantLimits::REDACTION);
    if variants.is_empty() {
        return Vec::new();
    }
    let mut leaked = Vec::new();
    let mut seen = BTreeSet::new();
    fn scan(
        dirpath: &str,
        before_time: f64,
        variants: &Variants,
        exclude_dirs: &[String],
        seen: &mut BTreeSet<String>,
        leaked: &mut Vec<(String, String)>,
    ) {
        let real = real_or_lexical(dirpath);
        if excluded(&real, exclude_dirs) || !seen.insert(real) {
            return;
        }
        let Some(items) = entries(dirpath) else {
            return;
        };
        for (path, meta) in items {
            if meta.is_dir() {
                scan(&path, before_time, variants, exclude_dirs, seen, leaked);
            } else if meta.is_file() {
                let (mtime, ctime, _, _) = times(&meta);
                if mtime < before_time && ctime < before_time {
                    continue;
                }
                if let Some(name) = file_leaks(&path, variants) {
                    leaked.push((path, name));
                }
            }
        }
    }
    for dir in scan_dirs {
        if is_dir(dir) {
            scan(
                dir,
                before_time,
                &variants,
                exclude_dirs,
                &mut seen,
                &mut leaked,
            );
        }
    }
    leaked
}

/// Python `scan_specific_files`.
pub fn scan_specific_files<'a, I>(file_paths: &[String], secrets: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let variants = build_secret_variants(secrets, VariantLimits::REDACTION);
    if variants.is_empty() {
        return Vec::new();
    }
    file_paths
        .iter()
        .filter_map(|path| file_leaks(path, &variants).map(|name| (path.clone(), name)))
        .collect()
}

fn walk_files(
    scan_dirs: &[String],
    exclude_dirs: &[String],
    mut on_file: impl FnMut(&str, &std::fs::Metadata),
) {
    let mut seen = BTreeSet::new();
    fn walk(
        dirpath: &str,
        exclude_dirs: &[String],
        seen: &mut BTreeSet<String>,
        on_file: &mut impl FnMut(&str, &std::fs::Metadata),
    ) {
        let real = real_or_lexical(dirpath);
        if excluded(&real, exclude_dirs) || !seen.insert(real) {
            return;
        }
        let Some(items) = entries(dirpath) else {
            return;
        };
        for (path, meta) in items {
            if meta.is_dir() {
                walk(&path, exclude_dirs, seen, on_file);
            } else if meta.is_file() {
                on_file(&path, &meta);
            }
        }
    }
    for dir in scan_dirs {
        if is_dir(dir) {
            walk(dir, exclude_dirs, &mut seen, &mut on_file);
        }
    }
}

/// Python `collect_new_files`: real paths of files written since `before_time`.
pub fn collect_new_files(before_time: f64, scan_dirs: &[String]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    walk_files(scan_dirs, &[], |path, meta| {
        let (mtime, ctime, _, _) = times(meta);
        if mtime >= before_time || ctime >= before_time {
            found.insert(real_or_lexical(path));
        }
    });
    found
}

/// Python `snapshot_files`.
pub fn snapshot_files(scan_dirs: &[String]) -> BTreeMap<String, Fingerprint> {
    let mut snapshot = BTreeMap::new();
    walk_files(scan_dirs, &[], |path, _| {
        if let Some(fingerprint) = file_fingerprint(path) {
            snapshot.insert(real_or_lexical(path), fingerprint);
        }
    });
    snapshot
}

/// Python `collect_changed_files`.
pub fn collect_changed_files(
    before: &BTreeMap<String, Fingerprint>,
    scan_dirs: &[String],
) -> BTreeSet<String> {
    let mut changed = BTreeSet::new();
    walk_files(scan_dirs, &[], |path, _| {
        let real = real_or_lexical(path);
        let fingerprint = file_fingerprint(path);
        if fingerprint.is_some() && before.get(&real) != fingerprint.as_ref() {
            changed.insert(real);
        }
    });
    changed
}

/// Python `track_new_files` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tracking {
    Complete,
    /// `should_stop` answered; `unfinished` lists the folders not finished.
    Stopping {
        unfinished: Vec<String>,
    },
    TimeBound {
        unfinished: Vec<String>,
    },
}

impl Tracking {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Stopping { .. } => "stopping",
            Self::TimeBound { .. } => "time_bound",
        }
    }
}

/// Python `track_new_files`: add files written since `before_time` to
/// `tracked`, stopping at `deadline` or when `should_stop` says so.
pub fn track_new_files(
    before_time: f64,
    scan_dirs: &[String],
    tracked: &mut BTreeSet<String>,
    exclude_dirs: &[String],
    deadline: Option<Instant>,
    mut should_stop: impl FnMut() -> bool,
) -> Tracking {
    enum Cut {
        Stopping,
        TimeBound,
    }
    let mut check = |_: ()| -> Result<(), Cut> {
        if should_stop() {
            return Err(Cut::Stopping);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Cut::TimeBound);
        }
        Ok(())
    };
    let mut seen = BTreeSet::new();
    fn walk(
        dirpath: &str,
        before_time: f64,
        exclude_dirs: &[String],
        seen: &mut BTreeSet<String>,
        tracked: &mut BTreeSet<String>,
        check: &mut impl FnMut(()) -> Result<(), Cut>,
    ) -> Result<(), Cut> {
        let real = real_or_lexical(dirpath);
        if excluded(&real, exclude_dirs) || !seen.insert(real) {
            return Ok(());
        }
        let Some(items) = entries(dirpath) else {
            return Ok(());
        };
        for (path, meta) in items {
            check(())?;
            if meta.is_dir() {
                walk(&path, before_time, exclude_dirs, seen, tracked, check)?;
            } else if meta.is_file() {
                let (mtime, ctime, _, _) = times(&meta);
                if mtime >= before_time || ctime >= before_time {
                    tracked.insert(real_or_lexical(&path));
                }
            }
        }
        Ok(())
    }
    for (index, dir) in scan_dirs.iter().enumerate() {
        let result = check(()).and_then(|()| {
            if is_dir(dir) {
                walk(
                    dir,
                    before_time,
                    exclude_dirs,
                    &mut seen,
                    tracked,
                    &mut check,
                )
            } else {
                Ok(())
            }
        });
        if let Err(cut) = result {
            let unfinished = scan_dirs[index..].to_vec();
            return match cut {
                Cut::Stopping => Tracking::Stopping { unfinished },
                Cut::TimeBound => Tracking::TimeBound { unfinished },
            };
        }
    }
    Tracking::Complete
}

/// Python `leak_report`: the warning and records for leaked files, with
/// paths withheld behind an HMAC reference keyed by `key` (16 random bytes
/// the caller mints per report).
pub fn leak_report(
    leaked: &[(String, String)],
    cwd: Option<&str>,
    temp_dirs: &[String],
    key: &[u8],
) -> (String, Vec<Map<String, Value>>) {
    let mut roots: Vec<(&str, String)> = Vec::new();
    if let Some(cwd) = cwd.filter(|c| !c.is_empty()) {
        roots.push(("project", real_or_lexical(cwd)));
    }
    for temp in temp_dirs.iter().filter(|t| !t.is_empty()) {
        roots.push(("temp", real_or_lexical(temp)));
    }
    let mut records = Vec::new();
    for (path, name) in leaked {
        let real = real_or_lexical(path);
        let location = roots
            .iter()
            .find(|(_, root)| {
                real == *root || real.starts_with(&format!("{}/", root.trim_end_matches('/')))
            })
            .map_or("other", |(label, _)| *label);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(real.as_bytes());
        let digest = hex::encode(mac.finalize().into_bytes());
        let mut record = Map::new();
        record.insert("location".into(), json!(location));
        record.insert("secret_name".into(), json!(name));
        record.insert("ref".into(), json!(format!("leak_{}", &digest[..12])));
        records.push(record);
    }
    if records.is_empty() {
        return (String::new(), records);
    }
    let items = records
        .iter()
        .map(|r| {
            format!(
                "{} ({}, {})",
                r["secret_name"].as_str().unwrap_or(""),
                r["location"].as_str().unwrap_or(""),
                r["ref"].as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let warning = format!(
        "\n[SECURITY] detected and deleted {} file(s) containing secrets: {items}. Paths are \
         withheld because file names can contain secret text.",
        records.len()
    );
    (warning, records)
}

/// Python `temp_scan_dirs`: the system temp folder, `/tmp` and `extra`,
/// absolute, identical ones dropped. `std::env::temp_dir` reads `TMPDIR`
/// then falls back to `/tmp` (Python also tries `TEMP`/`TMP` and checks
/// that the folder is writable).
pub fn temp_scan_dirs(extra: &[String]) -> Vec<String> {
    let system = std::env::temp_dir().to_string_lossy().into_owned();
    let mut out: Vec<String> = Vec::new();
    for folder in std::iter::once(system.as_str())
        .chain(std::iter::once(crate::bwrap::PRIVATE_TMP))
        .chain(extra.iter().map(String::as_str))
    {
        let absolute = crate::paths::abspath(folder).unwrap_or_else(|_| folder.to_owned());
        if !out.contains(&absolute) {
            out.push(absolute);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_drops_invalid_bytes() {
        assert_eq!(decode_ignoring(b"ab\xffc\xe9"), "abc");
        assert_eq!(decode_ignoring("héllo".as_bytes()), "héllo");
    }

    #[test]
    fn leak_report_shape() {
        let leaked = vec![("/p/x.txt".to_owned(), "KEY".to_owned())];
        let (warning, records) = leak_report(&leaked, Some("/p"), &[], &[7u8; 16]);
        assert_eq!(records[0]["location"], "project");
        assert!(records[0]["ref"].as_str().unwrap().starts_with("leak_"));
        assert!(warning.starts_with("\n[SECURITY] detected and deleted 1 file(s)"));
        assert_eq!(leak_report(&[], None, &[], &[0u8; 16]).0, "");
    }
}
