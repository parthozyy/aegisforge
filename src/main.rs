mod cli;
mod scanner;

use clap::Parser;
use cli::{Cli, Commands};
use scanner::path::{PathType, inspect_path};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            println!("AegisForge");

            match inspect_path(&path) {
                Ok(PathType::File) => {
                    println!("Target: {}", path.display());
                    println!("Type: File");
                }

                Ok(PathType::Directory) => {
                    println!("Target: {}", path.display());
                    println!("Type: Directory");
                }

                Err(error) => {
                    eprintln!("Error: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}
