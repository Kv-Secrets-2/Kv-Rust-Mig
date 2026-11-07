//! `write_private_atomic` from `kv/config.py`: a 0600 file that appears whole or not at all.

use std::io::Write;
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn write_private_atomic(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut token = [0u8; 16];
    getrandom::getrandom(&mut token).map_err(std::io::Error::other)?;
    let tmp = dir.join(format!(".kv-write-{}.tmp", hex(&token)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub fn mkdir_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}
