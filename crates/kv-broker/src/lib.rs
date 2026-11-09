mod caller;
mod policy;
mod providers;
mod redact;

pub use caller::{ApiCaller, ApiPreview, ApiRequest, UrlSafety};
pub use policy::{
    HttpPolicySnapshot, describe_http_policy_snapshot, evaluate_http_policy,
    evaluate_provider_http_request, http_headers_security_error, http_request_security_error,
    load_http_policy_snapshot, post_rules_overlap, validate_http_provider_policy,
};
pub use providers::{
    ProviderTable, api_body_security_error, build_auth, build_provider_table, build_url,
    contains_provider_secret_template, is_builtin_provider_name, load_custom_providers,
    shown_auth_url, snapshot_providers, validate_http_provider,
};
pub use redact::{Needles, hide, hide_cut, hide_value, output_needles, redact_one_secret};

pub const MAX_BROKER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const ERROR_BODY_WITHHELD: &str = "error body withheld: kv could not check it";
pub const KEY_PLACEHOLDER: &str = "<added-by-kv-not-shown>";
