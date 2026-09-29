use clap::Parser;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    pub fn address(&self) -> io::Result<SocketAddr> {
        // Resolve localhost ourselves so DNS cannot expand the listening boundary.
        let host = match self.host.as_str() {
            "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1" | "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Origin Trace only accepts loopback hosts: 127.0.0.1, localhost, or ::1",
                ));
            }
        };
        Ok(SocketAddr::new(host, self.port))
    }
}
