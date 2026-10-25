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
        Self::publish(path, address, true)
    }
    /// Shared aliases must outlive their publisher: a read-then-unlink in Drop
    /// could delete a replacement, including one reusing the same port.
    /// Consumers must check health; the next live session replaces stale bytes.
    pub fn retained(path: Option<&Path>, address: SocketAddr) -> io::Result<Self> {
        Self::publish(path, address, false)
    }
    fn publish(path: Option<&Path>, address: SocketAddr, cleanup: bool) -> io::Result<Self> {
        let url = format!("http://{address}");
        if let Some(path) = path {
            durable::write_private(path, format!("{url}\n").as_bytes())
                .map_err(|e| io::Error::other(e.message))?;
        }
        Ok(Self {
            path: path.filter(|_| cleanup).map(Path::to_owned),
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
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn retiring_private_endpoint_removes_its_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("research-ui.endpoint");
        let endpoint =
            PublishedEndpoint::new(Some(&path), "127.0.0.1:9100".parse().unwrap()).unwrap();
        drop(endpoint);
        assert!(!path.exists());
    }

    #[test]
    fn retiring_shared_publisher_cannot_unlink_concurrent_republication() {
        // Equal URLs are especially important: ownership cannot be inferred
        // from matching bytes when a port is reused by another backend.
        for replacement in ["127.0.0.1:9100", "127.0.0.1:9200"] {
            shared_republication(replacement);
        }
    }

    fn shared_republication(replacement: &str) {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().join("config/origin-trace/reb-api.endpoint");
        let old = PublishedEndpoint::retained(Some(&canonical), "127.0.0.1:9100".parse().unwrap())
            .unwrap();
        let (observed_tx, observed_rx) = mpsc::channel();
        let (published_tx, published_rx) = mpsc::channel();
        let observed_path = canonical.clone();
        let retiring = std::thread::spawn(move || {
            assert_eq!(
                std::fs::read_to_string(&observed_path).unwrap(),
                format!("{}\n", old.url())
            );
            observed_tx.send(()).unwrap();
            published_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(old);
        });
        observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let current =
            PublishedEndpoint::retained(Some(&canonical), replacement.parse().unwrap()).unwrap();
        published_tx.send(()).unwrap();
        retiring.join().unwrap();
        assert_eq!(
            std::fs::read_to_string(&canonical).unwrap(),
            format!("http://{replacement}\n")
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
        assert_eq!(
            std::fs::read_to_string(&canonical).unwrap(),
            format!("http://{replacement}\n")
        );
    }
}
