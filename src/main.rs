mod cli;
mod detection;
mod scanner;

use clap::Parser;
use cli::{Cli, Commands};
use scanner::scan::scan_path;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            if let Err(error) = scan_path(&path) {
                eprintln!("Error: {error}");
                std::process::exit(1);
            }
        }
    }
}
