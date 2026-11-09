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
    #[arg(long, conflicts_with = "artifact_map")]
    sections: Option<String>,
    /// Print the whole-artifact entropy and kind map instead of inspecting.
    #[arg(long)]
    artifact_map: bool,
}
fn main() {
    let options = Options::parse();
    if options.artifact_map {
        let result =
            origin_trace_backend::artifact_map::load(&options.artifacts, &options.artifact_id)
                .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}));
        println!("{result}");
        return;
    }
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
