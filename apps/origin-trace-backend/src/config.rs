use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Options {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(long, default_value_t = 7319)]
    pub port: u16,
    #[arg(long, default_value = "build/sessions/demo.jsonl")]
    pub store: PathBuf,
    #[arg(long, default_value = "build/sessions/origin-trace.jsonl")]
    pub trace_store: PathBuf,
    #[arg(long, default_value = "build/sessions/request-signals.jsonl")]
    pub signal_store: PathBuf,
    #[arg(long, default_value = "build/sessions/artifacts")]
    pub artifacts: PathBuf,
    #[arg(long)]
    pub demo_evidence: bool,
    #[arg(long)]
    pub endpoint_file: Option<PathBuf>,
}

impl Options {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
