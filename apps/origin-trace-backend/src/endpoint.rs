use crate::durable;
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
pub struct PublishedEndpoint {
    path: Option<PathBuf>,
    url: String,
}
impl PublishedEndpoint {
    pub fn new(path: Option<&Path>, address: SocketAddr) -> io::Result<Self> {
        let url = format!("http://{address}");
        if let Some(path) = path {
            durable::write_private(path, format!("{url}\n").as_bytes())
                .map_err(|e| io::Error::other(e.message))?;
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
        if let Some(path) = &self.path
            && std::fs::read(path).is_ok_and(|b| b == format!("{}\n", self.url).as_bytes())
        {
            let _ = std::fs::remove_file(path);
        }
    }
}
