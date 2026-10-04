use clap::Parser;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug, Parser, Clone)]
#[command(about = "Origin Trace local evidence and live-debugger backend")]
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
    #[arg(long, default_value = "build/sessions/api-collection-v1.json")]
    pub api_collection: PathBuf,
    #[arg(long, default_value = "build/sessions/local-analyst-workspace-v1.json")]
    pub local_analyst: PathBuf,
    #[arg(long)]
    pub decoder: Option<PathBuf>,
    #[arg(long)]
    pub debugger_transport: Option<PathBuf>,
    #[arg(long)]
    pub native_console: Option<PathBuf>,
    #[arg(long, env = "REB_BRAVE_BINARY")]
    pub brave_binary: Option<PathBuf>,
    #[arg(long)]
    pub heap_snapshot: Option<PathBuf>,
    #[arg(long, env = "REB_DEOBFUSCATOR_WORKER")]
    pub deobfuscator: Option<PathBuf>,
    #[arg(long)]
    pub analyst_runner: Option<PathBuf>,
    #[arg(long)]
    pub ui_directory: Option<PathBuf>,
    #[arg(long)]
    pub socket: Option<PathBuf>,
    #[arg(long)]
    pub broker_pid: Option<i32>,
    #[arg(long)]
    pub artifact_socket: Option<PathBuf>,
    #[arg(long)]
    pub devtools_active_port: Option<PathBuf>,
    #[arg(long)]
    pub capture_network_content: bool,
    #[arg(long)]
    pub demo_evidence: bool,
    #[arg(long)]
    pub endpoint_file: Option<PathBuf>,
}
impl Options {
    pub fn address(&self) -> io::Result<SocketAddr> {
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
    pub fn resolve(mut self) -> io::Result<Self> {
        let current = std::env::current_dir()?;
        for path in [
            &mut self.store,
            &mut self.trace_store,
            &mut self.signal_store,
            &mut self.artifacts,
            &mut self.api_collection,
            &mut self.local_analyst,
        ] {
            if !path.is_absolute() {
                *path = current.join(&*path);
            }
        }
        for path in [
            &mut self.decoder,
            &mut self.debugger_transport,
            &mut self.native_console,
            &mut self.brave_binary,
            &mut self.heap_snapshot,
            &mut self.deobfuscator,
            &mut self.analyst_runner,
            &mut self.ui_directory,
            &mut self.socket,
            &mut self.artifact_socket,
            &mut self.devtools_active_port,
            &mut self.endpoint_file,
        ]
        .into_iter()
        .flatten()
        {
            if !path.is_absolute() {
                *path = current.join(&*path);
            }
        }
        Ok(self)
    }
    pub fn ui_root(&self) -> PathBuf {
        if let Some(path) = &self.ui_directory {
            return path.clone();
        }
        if let Ok(executable) = std::env::current_exe()
            && let Some(macos) = executable.parent()
        {
            let resources = macos.join("../Resources/research-ui");
            if resources.join("index.html").is_file() {
                return resources;
            }
        }
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../research-ui")
    }
    pub fn worker(&self, option: &Option<PathBuf>, bundle: &str, development: &str) -> PathBuf {
        if let Some(path) = option {
            return path.clone();
        }
        if let Ok(executable) = std::env::current_exe()
            && let Some(directory) = executable.parent()
        {
            let path = directory.join(bundle);
            if path.is_file() {
                return path;
            }
        }
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(development);
        if !path.is_file() && development.contains("/target/debug/") {
            let release = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(development.replace("/target/debug/", "/target/release/"));
            if release.is_file() {
                return release;
            }
        }
        path
    }
    pub fn capture_mode(&self) -> &'static str {
        if self.socket.is_some() {
            "live"
        } else if self.demo_evidence {
            "demo"
        } else {
            "idle"
        }
    }
}
