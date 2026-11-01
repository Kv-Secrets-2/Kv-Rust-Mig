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
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => println!("kv {}", env!("CARGO_PKG_VERSION")),
    }
}
