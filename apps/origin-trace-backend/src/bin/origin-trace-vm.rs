use clap::Parser;
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Analyze captured JavaScript and WebAssembly for VM candidates")]
struct Options {
    #[arg(long)]
    artifacts: PathBuf,
    #[arg(long)]
    events: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    let document = origin_trace_backend::vm::store(&options.artifacts, &options.events)?;
    if let Some(path) = options.output {
        std::fs::write(path, serde_json::to_vec_pretty(&document)?)?;
    }
    Ok(())
}
