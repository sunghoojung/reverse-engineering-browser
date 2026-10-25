use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    about = "Retain unverified caller-supplied Wasm dispatch reports (not a runtime sampler)"
)]
struct Options {
    #[arg(long)]
    artifacts: PathBuf,
    #[arg(long)]
    input: PathBuf,
    /// New private JSONL file; existing files are never replaced or appended.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    let count = origin_trace_backend::vm_dispatch_input::write(
        &options.artifacts,
        &options.input,
        &options.output,
    )?;
    eprintln!(
        "Retained {count} caller-supplied reports; runtime provenance and guest PC units remain unverified"
    );
    Ok(())
}
