#![forbid(unsafe_code)]

/// Returns the crate name; smoke-tests the workspace wiring.
pub fn name() -> &'static str {
    "kv-crypto"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_kv_crypto() {
        assert_eq!(name(), "kv-crypto");
    }
}
