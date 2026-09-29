use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub struct PublishedEndpoint {
    path: Option<PathBuf>,
    url: String,
}

impl PublishedEndpoint {
    pub fn new(path: Option<&Path>, address: tiny_http::ListenAddr) -> io::Result<Self> {
        let url = match address {
            tiny_http::ListenAddr::IP(address) => endpoint_url(address),
            #[cfg(unix)]
            tiny_http::ListenAddr::Unix(_) => {
                return Err(io::Error::other("Unix HTTP listeners are unsupported"));
            }
        };
        if let Some(path) = path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, format!("{url}\n"))?;
            set_private_permissions(path)?;
        }
        Ok(Self {
            path: path.map(Path::to_owned),
            url,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for PublishedEndpoint {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

fn endpoint_url(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => format!("http://{}:{}", address.ip(), address.port()),
        SocketAddr::V6(address) => format!("http://[{}]:{}", address.ip(), address.port()),
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}
