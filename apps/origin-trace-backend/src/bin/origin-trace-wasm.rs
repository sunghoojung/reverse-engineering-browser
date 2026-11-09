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
    #[arg(long, conflicts_with_all = ["artifact_map", "functions", "graph_function"])]
    sections: Option<String>,
    /// Print the whole-artifact entropy and kind map instead of inspecting.
    #[arg(long, conflicts_with_all = ["functions", "graph_function"])]
    artifact_map: bool,
    /// List the module's functions as `wasm-function-index-v1` instead.
    #[arg(long, conflicts_with = "graph_function")]
    functions: bool,
    /// Print basic blocks for one function as `wasm-block-graph-v1` instead.
    #[arg(long)]
    graph_function: Option<u32>,
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
    if options.functions || options.graph_function.is_some() {
        let document = match options.graph_function {
            Some(function) => origin_trace_backend::wasm_graph::function_graph(
                &options.artifacts,
                &options.artifact_id,
                function,
            ),
            None => origin_trace_backend::wasm_graph::function_index(
                &options.artifacts,
                &options.artifact_id,
            ),
        };
        match document {
            Ok(text) => println!("{text}"),
            Err(e) => println!("{}", json!({"error":e.message,"status":e.status})),
        }
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
