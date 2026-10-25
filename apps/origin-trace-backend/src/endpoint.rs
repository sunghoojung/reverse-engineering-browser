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

#[cfg(test)]
mod tests {
    use super::PublishedEndpoint;

    #[test]
    fn retiring_old_session_does_not_remove_replacement_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().join("config/origin-trace/reb-api.endpoint");
        let old =
            PublishedEndpoint::new(Some(&canonical), "127.0.0.1:9100".parse().unwrap()).unwrap();
        let current =
            PublishedEndpoint::new(Some(&canonical), "127.0.0.1:9200".parse().unwrap()).unwrap();
        drop(old);
        assert_eq!(
            std::fs::read_to_string(&canonical).unwrap(),
            "http://127.0.0.1:9200\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(current);
        assert!(!canonical.exists());
    }
}
