use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "af",
    version,
    about = "A lightweight, local-first security utility for macOS"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory
    Scan {
        /// Path to the file or directory to scan
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            println!("AegisForge");
            println!("Scanning: {}", path.display());
        }
    }
}
