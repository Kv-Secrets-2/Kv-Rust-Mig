//! `kv run` (`cmd_run` in `kv/cli.py`): the daemon owns validation, the
//! sandbox and redaction; the terminal only relays the request and shows the
//! answer.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::project::{self, CmdResult, Exit, agent_request, is_agent_running, require_project};
use crate::ui::{self, Palette};

pub struct RunArgs {
    pub env: Option<String>,
    pub cwd: Option<String>,
    pub private_cwd: Option<bool>,
    pub quiet: bool,
    pub secret_names: Option<Vec<String>>,
    pub no_secrets: bool,
    pub capability_names: Vec<String>,
    pub cmd: Vec<String>,
}

fn dim(p: &Palette, text: &str) -> String {
    format!("{}{text}{}", p.dim, p.reset)
}

pub fn cmd_run(p: &Palette, args: RunArgs) -> CmdResult {
    let mut cmd_parts: &[String] = &args.cmd;
    if cmd_parts.first().map(String::as_str) == Some("--") {
        cmd_parts = &cmd_parts[1..];
    }
    if cmd_parts.is_empty() {
        ui::error(p, "No command provided.");
        eprintln!();
        if args.no_secrets {
            ui::info(&dim(
                p,
                "Use --no-secrets when you want kv to run a normal command without loading vault secrets.",
            ));
            ui::info(&dim(p, "Example: kv run --no-secrets -- npm test"));
        } else {
            ui::info(&dim(p, "Example: kv run --secret API_KEY -- python app.py"));
            ui::info(&dim(
                p,
                "For normal work without secrets: kv run --no-secrets -- npm test",
            ));
        }
        ui::info(&dim(
            p,
            "Usage: kv run [-e ENV] [--secret NAME | --no-secrets] -- COMMAND...",
        ));
        return Err(Exit(1));
    }
    let env = match args.env.filter(|e| !e.is_empty()) {
        Some(env) => env,
        None => {
            let root = require_project(p)?;
            kv_store::config::load_config(&root)
                .ok()
                .and_then(|snapshot| {
                    snapshot
                        .value
                        .get("default_env")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "dev".to_owned())
        }
    };
    let run_cwd = match args.cwd.filter(|c| !c.is_empty()) {
        Some(cwd) => kv_hook::paths::abspath(&cwd).unwrap_or(cwd),
        None => std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".to_owned()),
    };
    if !Path::new(&run_cwd).is_dir() {
        return Err(project::fail(
            p,
            &format!("working directory not found: {run_cwd}"),
        ));
    }
    let env_names: Option<Vec<String>> = if args.no_secrets {
        Some(Vec::new())
    } else {
        args.secret_names
    };
    for name in &args.capability_names {
        if !name.starts_with("api:") || name == "api:" {
            return Err(project::fail(
                p,
                "kv run --capability currently supports only api:<provider>",
            ));
        }
    }
    let mut fields = Map::new();
    fields.insert("argv".into(), json!(cmd_parts));
    fields.insert("env".into(), json!(env));
    fields.insert("cwd".into(), json!(run_cwd));
    if let Some(names) = &env_names {
        fields.insert("env_names".into(), json!(names));
    }
    if !args.capability_names.is_empty() {
        fields.insert("capability_names".into(), json!(args.capability_names));
    }
    if let Some(private_cwd) = args.private_cwd {
        fields.insert("private_cwd".into(), json!(private_cwd));
    }
    let root = project::find_project_root();
    let running = root.as_deref().is_some_and(is_agent_running);
    if let (true, Some(root)) = (running, root.as_deref()) {
        if !args.quiet {
            ui::header(p, &format!("running via agent ({env})"));
            ui::blank();
        }
        let Some(result) = agent_request(root, "run", fields) else {
            return Err(project::fail(p, "agent error: the agent did not answer"));
        };
        if let Some(error) = result.get("error") {
            ui::error(p, &project::py_text(error));
            return Err(Exit(exit_code(&result, 1)));
        }
        if let Some(stdout) = result.get("stdout").and_then(Value::as_str)
            && !stdout.trim().is_empty()
        {
            ui::out(stdout.trim_end());
        }
        if let Some(stderr) = result.get("stderr").and_then(Value::as_str)
            && !stderr.trim().is_empty()
        {
            eprintln!("{}", stderr.trim_end());
        }
        if let Some(warning) = result.get("warning").filter(|w| !w.is_null()) {
            ui::warn(p, &project::py_text(warning));
        }
        let injected = result
            .get("injected_secret_count")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if result.get("secret_scope").and_then(Value::as_str) == Some("all") && injected > 0 {
            let noun = if injected == 1 { "secret" } else { "secrets" };
            ui::warn(
                p,
                &format!(
                    "kv run injected all {injected} {noun} from {env}; use --secret NAME to narrow scope or --no-secrets when credentials are not needed"
                ),
            );
        }
        let code = exit_code(&result, 0);
        return if code == 0 { Ok(()) } else { Err(Exit(code)) };
    }
    ui::error(p, "kv agent is not running");
    ui::info(&format!(
        "{}the kv agent provides command validation, output redaction,",
        p.dim
    ));
    ui::info(&format!(
        "network rules, and file scanning. Start it first:{}",
        p.reset
    ));
    ui::blank();
    ui::cmd(p, "kv unlock", "Open your vault (background)");
    ui::cmd(p, "kv unlock --foreground", "Open your vault (foreground)");
    ui::blank();
    Err(Exit(1))
}

fn exit_code(result: &Value, default: i32) -> i32 {
    result
        .get("exit_code")
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(default)
}
