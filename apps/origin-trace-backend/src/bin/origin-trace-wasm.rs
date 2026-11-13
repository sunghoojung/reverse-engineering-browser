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
    #[arg(long, conflicts_with_all = ["artifact_map", "functions", "graph_function", "identification", "pseudocode_function", "diff_with"])]
    sections: Option<String>,
    /// Print the whole-artifact entropy and kind map instead of inspecting.
    #[arg(long, conflicts_with_all = ["functions", "graph_function", "pseudocode_function", "diff_with"])]
    artifact_map: bool,
    /// List the module's functions as `wasm-function-index-v1` instead.
    #[arg(long, conflicts_with_all = ["graph_function", "pseudocode_function", "diff_with"])]
    functions: bool,
    /// Print basic blocks for one function as `wasm-block-graph-v1` instead.
    #[arg(long, conflicts_with_all = ["identification", "pseudocode_function", "diff_with"])]
    graph_function: Option<u32>,
    /// Print the `wasm-identification-v1` report instead.
    #[arg(long, conflicts_with_all = ["artifact_map", "functions", "pseudocode_function", "diff_with"])]
    identification: bool,
    /// The first row of an identification report or a module diff page.
    #[arg(long)]
    row_offset: Option<usize>,
    /// Rows in an identification report (at most 1024, the default) or a
    /// module diff page (1 to 1000, default 200).
    #[arg(long)]
    row_limit: Option<usize>,
    /// Print one function's readable lift as `wasm-pseudocode-v1` instead.
    #[arg(long, conflicts_with = "diff_with")]
    pseudocode_function: Option<u32>,
    /// First line of the readable lift's window.
    #[arg(long, requires = "pseudocode_function", default_value_t = 0)]
    line_offset: usize,
    /// Lines in the readable lift's window.
    #[arg(long, requires = "pseudocode_function", default_value_t = origin_trace_backend::wasm_pseudocode::DEFAULT_LINE_LIMIT)]
    line_limit: usize,
    /// Match this module's functions against another captured module and
    /// print one page of `wasm-module-diff-v1` instead.
    #[arg(long)]
    diff_with: Option<String>,
    /// Comma separated row statuses for the diff page. Omit for every row.
    #[arg(long, requires = "diff_with")]
    status: Option<String>,
}
fn main() {
    let started = std::time::Instant::now();
    let options = Options::parse();
    if options.artifact_map {
        let result =
            origin_trace_backend::artifact_map::load(&options.artifacts, &options.artifact_id)
                .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}));
        println!("{result}");
        return;
    }
    if let Some(other) = options.diff_with.as_deref() {
        use origin_trace_backend::wasm_diff;
        let result = wasm_diff::Page::new(
            options.row_offset.unwrap_or(0),
            options.row_limit.unwrap_or(wasm_diff::PAGE_DEFAULT_ROWS),
            options.status.as_deref(),
        )
        .and_then(|page| {
            wasm_diff::diff(
                &options.artifacts,
                &options.artifact_id,
                other,
                &page,
                started,
            )
        })
        .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}));
        println!("{result}");
        return;
    }
    if options.identification {
        let row_offset = options.row_offset.unwrap_or(0);
        let row_limit = options
            .row_limit
            .unwrap_or(origin_trace_backend::wasm_identification::SUGGESTION_PAGE);
        let result = if row_limit > origin_trace_backend::wasm_identification::SUGGESTION_PAGE {
            json!({"error":"row_limit is at most 1024","status":400})
        } else {
            origin_trace_backend::wasm_identification::load(
                &options.artifacts,
                &options.artifact_id,
                row_offset,
                row_limit,
            )
            .unwrap_or_else(|e| json!({"error":e.message,"status":e.status}))
        };
        println!("{result}");
        return;
    }
    if let Some(function) = options.pseudocode_function {
        match origin_trace_backend::wasm_pseudocode::pseudocode(
            &options.artifacts,
            &options.artifact_id,
            function,
            options.line_offset,
            options.line_limit,
        ) {
            Ok(text) => println!("{text}"),
            Err(e) => println!("{}", json!({"error":e.message,"status":e.status})),
        }
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
