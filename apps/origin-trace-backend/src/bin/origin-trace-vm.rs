#[global_allocator]
static ALLOCATOR: origin_trace_backend::JavaScriptWorkerAllocator =
    origin_trace_backend::JavaScriptWorkerAllocator;
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
    if std::env::args().nth(1).as_deref() == Some("--classify-javascript-worker") {
        return origin_trace_backend::javascript_worker_main().map_err(Into::into);
    }
    let options = Options::parse();
    let document = origin_trace_backend::vm::store(&options.artifacts, &options.events)?;
    if let Some(path) = options.output {
        std::fs::write(path, serde_json::to_vec_pretty(&document)?)?;
    }
    Ok(())
}
