use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "af",
    version,
    about = "A lightweight, local-first security utility for macOS"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a file or directory
    Scan {
        /// Path to the file or directory to scan
        path: PathBuf,
    },
}
