//! An endpoint file names one running backend's loopback root. The file
//! format stays one URL line; ownership lives in the kernel instead. The
//! publisher holds an exclusive lock on the exact file it wrote for its whole
//! life, and the kernel drops that lock when the process dies, so a reader
//! can tell a live publication from one a killed backend left behind.
//! Publishers serialize on a lock of the containing directory, so retiring
//! removes only the file this process wrote, never a successor's.
use std::{
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};
pub struct PublishedEndpoint {
    published: Option<Published>,
    url: String,
}
struct Published {
    path: PathBuf,
    /// The published file. Its lock marks the publication live.
    file: File,
}
impl PublishedEndpoint {
    pub fn new(path: Option<&Path>, address: SocketAddr) -> io::Result<Self> {
        let url = format!("http://{address}");
        let published = path
            .map(|path| publish(path, format!("{url}\n").as_bytes()))
            .transpose()?;
        Ok(Self { published, url })
    }
    pub fn url(&self) -> &str {
        &self.url
    }
}
impl Drop for PublishedEndpoint {
    fn drop(&mut self) {
        if let Some(published) = &self.published {
            retire(published);
        }
    }
}

/// True unless `file`, an open endpoint file, is known to have no live
/// publisher. A lock this probe obtains is released when `file` closes.
pub fn has_live_publisher(file: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // Only an obtained lock proves there is no publisher; a filesystem
        // without locks decides nothing.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        true
    }
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Holds an exclusive lock on a directory while it publishes or retires.
struct Serialized(File);
impl Serialized {
    fn acquire(directory: &Path) -> io::Result<Self> {
        let directory = File::open(directory)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(directory))
    }
}

fn publish(path: &Path, bytes: &[u8]) -> io::Result<Published> {
    let directory = parent(path);
    std::fs::create_dir_all(directory)?;
    let serialized = Serialized::acquire(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        // Lock before the rename, so the file is never visible unowned.
        if unsafe {
            libc::flock(
                temporary.as_file().as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let file = temporary.persist(path).map_err(|e| e.error)?;
    serialized.0.sync_all()?;
    Ok(Published {
        path: path.to_owned(),
        file,
    })
}

fn retire(published: &Published) {
    let Ok(_serialized) = Serialized::acquire(parent(&published.path)) else {
        return;
    };
    if is_same_file(&published.path, &published.file) {
        let _ = std::fs::remove_file(&published.path);
    }
}

fn is_same_file(path: &Path, file: &File) -> bool {
    let (Ok(entry), Ok(own)) = (std::fs::symlink_metadata(path), file.metadata()) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        entry.dev() == own.dev() && entry.ino() == own.ino()
    }
    #[cfg(not(unix))]
    {
        entry.len() == own.len() && entry.modified().ok() == own.modified().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{PublishedEndpoint, has_live_publisher};

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

    /// The same port, and so identical bytes, is still a different publication.
    #[test]
    fn a_successor_at_the_same_port_keeps_its_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reb-api.endpoint");
        let address = "127.0.0.1:7319".parse().unwrap();
        let old = PublishedEndpoint::new(Some(&path), address).unwrap();
        let successor = PublishedEndpoint::new(Some(&path), address).unwrap();
        drop(old);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "http://127.0.0.1:7319\n"
        );
        drop(successor);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn readers_tell_a_live_publication_from_a_left_behind_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reb-api.endpoint");
        let published =
            PublishedEndpoint::new(Some(&path), "127.0.0.1:9100".parse().unwrap()).unwrap();
        assert!(has_live_publisher(&std::fs::File::open(&path).unwrap()));
        // What a killed publisher leaves: the same bytes, and the kernel has
        // released its lock.
        let left = root.path().join("left.endpoint");
        std::fs::write(&left, "http://127.0.0.1:9100\n").unwrap();
        assert!(!has_live_publisher(&std::fs::File::open(&left).unwrap()));
        drop(published);
    }
}
