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
    origin_trace_backend::javascript_worker_entry();
    let options = Options::parse();
    let analysis = origin_trace_backend::vm::store_analysis(&options.artifacts, &options.events)?;
    // Copied as a stream: a long session's document is larger than memory.
    if let Some(path) = options.output {
        let mut output = std::io::BufWriter::new(std::fs::File::create(path)?);
        std::io::copy(&mut analysis.reader(), &mut output)?;
        std::io::Write::flush(&mut output)?;
    }
    Ok(())
}

#[cfg(test)]
origin_trace_backend::javascript_worker_test_entry!();
