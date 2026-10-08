//! Cooperative workspace transaction lock. The stable sidecar is never renamed
//! or removed; locking the atomically replaced data file would split ownership.
use crate::error::{Code, Error, Result};
use std::path::Path;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        fs::{DirBuilder, File},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            },
        },
        sync::atomic::{AtomicU64, Ordering},
    };
    use unicode_casefold::UnicodeCaseFold;
    const SUFFIX: &[u8] = b".reb-workspace-lock-v1";
    static TEMPORARY: AtomicU64 = AtomicU64::new(0);
    fn name(value: &OsStr) -> Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| Error::bad("Workspace path contains a null byte"))
    }
    fn open_at(parent: &File, name: &CString, flags: i32, mode: u32) -> std::io::Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn regular_owned(file: &File, label: &str) -> Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::bad(format!(
                "{label} must be a user-owned regular file with one link"
            )));
        }
        Ok(())
    }
    fn same_inode(entry: &libc::stat, file: &File) -> Result<bool> {
        let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), held.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let held = unsafe { held.assume_init() };
        Ok(entry.st_dev == held.st_dev && entry.st_ino == held.st_ino)
    }
    pub struct Lease {
        directory: File,
        // Fresh open-file description per transaction, even in the same process.
        lock: File,
        target: CString,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    impl Lease {
        pub fn acquire(path: &Path) -> Result<Self> {
            let filename = path
                .file_name()
                .ok_or_else(|| Error::bad("Workspace path must name a file"))?;
            let folded = filename
                .to_str()
                .map(|value| value.case_fold().collect::<String>().into_bytes())
                .unwrap_or_else(|| filename.as_bytes().to_ascii_lowercase());
            if folded.ends_with(SUFFIX) || folded.starts_with(b".reb-workspace-") {
                return Err(Error::bad(
                    "Workspace path uses a reserved writer-lock or temporary filename",
                ));
            }
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
            let parent_name = name(parent.as_os_str())?;
            // Parent aliases open the same directory inode. All transaction I/O
            // remains relative to this pinned descriptor, even if the path moves.
            let fd = unsafe {
                libc::open(
                    parent_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let directory = unsafe { File::from_raw_fd(fd) };
            let metadata = directory.metadata()?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o022 != 0
            {
                return Err(Error::bad(
                    "Workspace directory must be user-owned and not writable by group or others",
                ));
            }
            let mut lock_name = filename.as_bytes().to_vec();
            lock_name.extend_from_slice(SUFFIX);
            let lock_name = CString::new(lock_name)
                .map_err(|_| Error::bad("Workspace lock path is invalid"))?;
            let lock = open_at(
                &directory,
                &lock_name,
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
            .map_err(|_| Error::bad("Workspace writer lock could not be opened safely"))?;
            regular_owned(&lock, "Workspace writer lock")?;
            if lock.metadata()?.mode() & 0o7777 != 0o600 || lock.metadata()?.len() != 0 {
                return Err(Error::bad(
                    "Workspace writer lock must be empty with private 0600 permissions",
                ));
            }
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(Error::conflict(
                        "Workspace is busy saving in another window or process; reload before saving again",
                    ));
                }
                return Err(Error::new(
                    500,
                    "Workspace writer lock could not be acquired",
                ));
            }
            let lease = Self {
                directory,
                lock,
                target: name(filename)?,
            };
            let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    lease.directory.as_raw_fd(),
                    lock_name.as_ptr(),
                    entry.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(Error::bad(
                    "Workspace writer lock changed while being acquired",
                ));
            }
            let entry = unsafe { entry.assume_init() };
            if !same_inode(&entry, &lease.lock)?
                || entry.st_nlink != 1
                || entry.st_size != 0
                || entry.st_uid != unsafe { libc::geteuid() }
                || entry.st_mode & libc::S_IFMT != libc::S_IFREG
                || entry.st_mode & 0o7777 != 0o600
            {
                return Err(Error::bad(
                    "Workspace writer lock changed while being acquired",
                ));
            }
            Ok(lease)
        }
        pub fn read(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
            let file = match open_at(
                &self.directory,
                &self.target,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(Error::bad("Workspace store must be a regular file")),
            };
            regular_owned(&file, "Workspace store")?;
            let mut bytes = Vec::new();
            file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > maximum {
                return Err(Error::bad("Store exceeds its byte limit"));
            }
            Ok(Some(bytes))
        }
        pub fn write(&self, bytes: &[u8]) -> Result<()> {
            let (temporary_name, mut temporary) = (0..64)
                .find_map(|_| {
                    let sequence = TEMPORARY.fetch_add(1, Ordering::Relaxed);
                    let name = CString::new(format!(
                        ".reb-workspace-{}-{sequence}.tmp",
                        std::process::id()
                    ))
                    .unwrap();
                    match open_at(
                        &self.directory,
                        &name,
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    ) {
                        Ok(file) => Some(Ok((name, file))),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                        Err(error) => Some(Err(Error::from(error))),
                    }
                })
                .unwrap_or_else(|| {
                    Err(Error::new(500, "Workspace temporary-file limit reached"))
                })?;
            let mut renamed = false;
            let result = (|| {
                temporary.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                let mut target = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe {
                    libc::fstatat(
                        self.directory.as_raw_fd(),
                        self.target.as_ptr(),
                        target.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0
                {
                    let target = unsafe { target.assume_init() };
                    if same_inode(&target, &temporary)? {
                        return Err(Error::bad(
                            "Workspace filename aliases the reserved temporary namespace",
                        ));
                    }
                } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
                    return Err(std::io::Error::last_os_error().into());
                }
                temporary.write_all(bytes)?;
                temporary.sync_all()?;
                if unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        temporary_name.as_ptr(),
                        self.directory.as_raw_fd(),
                        self.target.as_ptr(),
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                renamed = true;
                self.directory.sync_all().map_err(|_| Error::new(500, "Workspace save was published but directory synchronization failed; reload to establish its outcome").with_code(Code::CommandOutcomeUnknown))?;
                Ok(())
            })();
            // Only clean our unpublished temporary; a published name may already
            // have been reused. Never remove the destination or permanent lock.
            if !renamed {
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0);
                }
            }
            result
        }
    }
}
#[cfg(unix)]
pub use unix::Lease;
#[cfg(not(unix))]
pub struct Lease;
#[cfg(not(unix))]
impl Lease {
    pub fn acquire(_: &Path) -> Result<Self> {
        Err(Error::new(
            503,
            "Cooperative workspace saves require a supported local Unix filesystem",
        )
        .with_code(Code::DependencyUnavailable))
    }
    pub fn read(&self, _: usize) -> Result<Option<Vec<u8>>> {
        unreachable!()
    }
    pub fn write(&self, _: &[u8]) -> Result<()> {
        unreachable!()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
        },
        time::{Duration, Instant},
    };
    fn lock_path(path: &Path) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".reb-workspace-lock-v1");
        name.into()
    }
    #[test]
    fn workspace_lease_parent_alias_and_path_replacement_remain_pinned() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        fs::create_dir(&original).unwrap();
        let alias = root.path().join("alias");
        symlink(&original, &alias).unwrap();
        let path = original.join("store.json");
        let lease = Lease::acquire(&path).unwrap();
        assert!(
            matches!(Lease::acquire(&alias.join("store.json")),Err(error) if error.status==409)
        );
        let moved = root.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("store.json"), b"different directory").unwrap();
        lease.write(b"pinned transaction").unwrap();
        assert_eq!(lease.read(100).unwrap().unwrap(), b"pinned transaction");
        assert_eq!(
            fs::read(moved.join("store.json")).unwrap(),
            b"pinned transaction"
        );
        assert_eq!(
            fs::read(original.join("store.json")).unwrap(),
            b"different directory"
        );
        drop(lease);
        assert!(Lease::acquire(&moved.join("store.json")).is_ok());
        assert_eq!(
            fs::metadata(moved.join("store.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(moved.join("store.json.reb-workspace-lock-v1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn workspace_lease_hostile_lock_entries_fail_promptly_and_unchanged() {
        for mode in [
            "symlink",
            "hardlink",
            "fifo",
            "directory",
            "permissions",
            "nonempty",
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("store.json");
            let lock = lock_path(&path);
            let sentinel = root.path().join("sentinel");
            fs::write(&sentinel, b"retained").unwrap();
            match mode {
                "symlink" => symlink(&sentinel, &lock).unwrap(),
                "hardlink" => fs::hard_link(&sentinel, &lock).unwrap(),
                "fifo" => {
                    let name = CString::new(lock.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "directory" => fs::create_dir(&lock).unwrap(),
                _ => {
                    fs::write(
                        &lock,
                        if mode == "nonempty" {
                            &b"x"[..]
                        } else {
                            &b""[..]
                        },
                    )
                    .unwrap();
                    fs::set_permissions(
                        &lock,
                        fs::Permissions::from_mode(if mode == "permissions" {
                            0o644
                        } else {
                            0o600
                        }),
                    )
                    .unwrap();
                }
            }
            let start = Instant::now();
            assert!(Lease::acquire(&path).is_err(), "{mode}");
            assert!(start.elapsed() < Duration::from_secs(1));
            assert_eq!(fs::read(&sentinel).unwrap(), b"retained");
            assert!(!path.exists());
        }
    }
    #[test]
    fn workspace_lease_hostile_stores_and_shared_parent_are_refused() {
        for mode in ["symlink", "hardlink", "fifo", "directory"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("store.json");
            let sentinel = root.path().join("sentinel");
            fs::write(&sentinel, b"retained").unwrap();
            match mode {
                "symlink" => symlink(&sentinel, &path).unwrap(),
                "hardlink" => fs::hard_link(&sentinel, &path).unwrap(),
                "fifo" => {
                    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => fs::create_dir(&path).unwrap(),
            }
            let lease = Lease::acquire(&path).unwrap();
            let start = Instant::now();
            assert!(lease.read(1024).is_err(), "{mode}");
            assert!(start.elapsed() < Duration::from_secs(1));
            assert_eq!(fs::read(&sentinel).unwrap(), b"retained");
        }
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Lease::acquire(&root.path().join("store.json")).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Lease::acquire(&root.path().join("store.json.reb-workspace-lock-v1")).is_err());
        for reserved in [
            ".reb-workspace-123-0.tmp",
            ".REB-WORKSPACE-123-0.tmp",
            ".reb-worKspace-123-0.tmp",
            "store.json.REB-WORKSPACE-LOCK-V1",
        ] {
            assert!(
                Lease::acquire(&root.path().join(reserved)).is_err(),
                "{reserved}"
            );
        }
    }
    #[test]
    fn workspace_lease_child_holder() {
        let Some(path) = std::env::var_os("REB_WORKSPACE_LEASE_CHILD_PATH") else {
            return;
        };
        let lease = Lease::acquire(Path::new(&path)).unwrap();
        std::fs::write(
            std::env::var_os("REB_WORKSPACE_LEASE_CHILD_READY").unwrap(),
            b"ready",
        )
        .unwrap();
        std::hint::black_box(&lease);
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    #[test]
    fn workspace_lease_crashed_process_releases_without_removing_sidecar() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.json");
        let ready = root.path().join("ready");
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "workspace_lease::tests::workspace_lease_child_holder",
                    "--nocapture",
                ])
                .env("REB_WORKSPACE_LEASE_CHILD_PATH", &path)
                .env("REB_WORKSPACE_LEASE_CHILD_READY", &ready)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(Lease::acquire(&path),Err(error) if error.status==409));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let lease = Lease::acquire(&path).unwrap();
        lease.write(b"after crash").unwrap();
        assert_eq!(lease.read(100).unwrap().unwrap(), b"after crash");
        assert!(lock_path(&path).exists());
    }
}
