use clap::Parser;
use serde_json::json;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Inspect captured WASM without executing it")]
struct Options {
    #[arg(long)]
    artifacts: PathBuf,
    #[arg(long)]
    artifact_id: String,
}
fn main() {
    let options = Options::parse();
    let result = origin_trace_backend::wasm::load(&options.artifacts, &options.artifact_id)
        .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}));
    println!("{result}");
}
