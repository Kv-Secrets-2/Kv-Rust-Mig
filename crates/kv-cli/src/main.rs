use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kv", version, about = "kv secrets manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the version.
    Version,
    /// Run the MCP server on stdio (what `python -I kv/mcp_launcher.py` runs).
    #[command(name = "mcp-server", disable_help_flag = true)]
    McpServer {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => println!("kv {}", env!("CARGO_PKG_VERSION")),
        Commands::McpServer { args } => std::process::exit(kv_mcp::main(&args)),
    }
}
