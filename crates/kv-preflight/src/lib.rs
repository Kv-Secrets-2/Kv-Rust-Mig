pub mod agent_code;
mod analysis;
mod errors;
mod manifest;

pub use manifest::{
    ApiNeed, PROVIDERS, PreflightError, PreflightManifest, agent_guidance, approval_command,
    manifest_json, preflight_command, recommendation_blocked_reason, run_command,
};

pub use kv_approvals::risk_card::RunRiskCardOptions;

/// Resolve the request cwd before building the risk card; preflight failures become limited cards.
/// The static depth bound uses its own error text rather than Python's RecursionError text.
pub fn build_run_risk_card(
    argv: &[String],
    cwd: Option<&str>,
    options: &RunRiskCardOptions<'_>,
) -> Result<serde_json::Value, PreflightError> {
    let cwd = cwd.filter(|s| !s.is_empty()).unwrap_or(".");
    let cwd = kv_sandbox::paths::resolve(cwd).map_err(|error| errors::resolve_error(cwd, error))?;
    Ok(kv_approvals::risk_card::build_run_risk_card(
        argv,
        &cwd,
        options,
        |argv, cwd| {
            preflight_command(argv, Some(cwd))
                .map(|m| m.as_dict())
                .map_err(|e| e.to_string())
        },
    ))
}
