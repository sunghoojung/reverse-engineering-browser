use clap::{Parser, Subcommand};
use origin_trace_backend::vm_pack;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    about = "Apply declarative VM analysis packs or compare local workspace documents offline"
)]
struct Options {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Apply {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        analysis: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Compare {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        left_artifact: String,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        right_artifact: String,
        #[arg(long)]
        output: PathBuf,
    },
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (report, output) = match Options::parse().command {
        Command::Apply {
            pack,
            analysis,
            output,
        } => (
            vm_pack::apply(&vm_pack::read(&pack)?, &vm_pack::read(&analysis)?)?,
            output,
        ),
        Command::Compare {
            pack,
            left,
            left_artifact,
            right,
            right_artifact,
            output,
        } => (
            vm_pack::compare(
                &vm_pack::read(&pack)?,
                &vm_pack::read(&left)?,
                &left_artifact,
                &vm_pack::read(&right)?,
                &right_artifact,
            )?,
            output,
        ),
    };
    vm_pack::write_report(&output, &report)?;
    println!(
        "{}",
        serde_json::json!({"document_digest":report["document_digest"],"network_requests":0})
    );
    Ok(())
}
