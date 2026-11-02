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
    /// Comma separated section names to decode. Omit for the whole module.
    #[arg(long)]
    sections: Option<String>,
}
fn main() {
    let options = Options::parse();
    let result = options
        .sections
        .as_deref()
        .map(origin_trace_backend::wasm::requested_sections)
        .transpose()
        .and_then(|sections| {
            origin_trace_backend::wasm::load(
                &options.artifacts,
                &options.artifact_id,
                sections.as_ref(),
            )
        })
        .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}));
    println!("{result}");
}
