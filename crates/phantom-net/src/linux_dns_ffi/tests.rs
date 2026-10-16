use super::*;
use configuration_watch::ConfigurationWatch;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn version_requires_bounded_complete_numeric_components() -> TestResult {
    assert_eq!(parse_glibc_version(b"2.39")?, (2, 39));
    assert_eq!(parse_glibc_version(b"2.42.9000")?, (2, 42));
    for value in [
        b"".as_slice(),
        b"2",
        b".42",
        b"2.",
        b"2.42.",
        b"0.42",
        b"2.-1",
        b"2.42-extra",
        b"2.4294967296",
        b"\xff",
    ] {
        assert_eq!(
            parse_glibc_version(value).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    assert!(parse_glibc_version(&[b'2'; 65]).is_err());
    Ok(())
}

#[test]
fn hostname_requires_complete_utf8_without_control_bytes() -> TestResult {
    assert_eq!(copy_hostname(b"host.example\0unused")?, "host.example");
    assert_eq!(copy_hostname("hôte.example\0".as_bytes())?, "hôte.example");
    for bytes in [
        b"".as_slice(),
        b"unterminated",
        b"\0",
        b"bad\nhost\0",
        b"\xff\0",
    ] {
        assert_eq!(
            copy_hostname(bytes).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    Ok(())
}

#[test]
fn interface_names_require_a_complete_bounded_native_string() -> TestResult {
    let name = interface_name("lo")?;
    assert_eq!(&name[..3], b"lo\0");
    for value in [
        "",
        ".",
        "..",
        "a/b",
        "a:b",
        "a b",
        "a\0b",
        "a\nb",
        "0123456789abcdef",
    ] {
        assert_eq!(
            interface_name(value).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn loopback_interface_has_an_authoritative_nonzero_index() -> TestResult {
    assert_ne!(interface_index("lo")?, 0);
    Ok(())
}

#[cfg(target_env = "gnu")]
#[test]
fn native_gnu_version_and_hostname_return_owned_values() -> TestResult {
    let (major, _) = glibc_version()?;
    assert_ne!(major, 0);
    let name = hostname()?;
    assert!(!name.is_empty());
    assert!(name.len() < 256);
    Ok(())
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let number = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("phantom-dns-watch-{}-{number}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no unique test directory",
        ))
    }

    fn remove(self) -> io::Result<()> {
        fs::remove_dir_all(&self.0)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // Error paths still clean the owned directory. Successful paths call
        // remove explicitly and check its result before this fallback runs.
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn owned_watch_fences_writes_replacements_and_added_target_parents() -> TestResult {
    let first = Directory::new()?;
    let second = Directory::new()?;
    let watch = ConfigurationWatch::start(std::slice::from_ref(&first.0))?;
    let observer = watch.observer();
    let result = (|| -> TestResult {
        let before = watch.check()?;
        fs::write(first.0.join("resolv.conf"), b"nameserver 127.0.0.1\n")?;
        let written = watch.check()?;
        assert_ne!(before, written);
        assert_eq!(written, observer.observed()?);
        fs::write(first.0.join("replacement"), b"nameserver 127.0.0.2\n")?;
        fs::rename(first.0.join("replacement"), first.0.join("resolv.conf"))?;
        assert_ne!(written, watch.check()?);
        watch.ensure_paths(&[second.0.clone(), second.0.clone()])?;
        let added = watch.check()?;
        fs::write(second.0.join("resolved.conf"), b"nameserver ::1\n")?;
        assert_ne!(added, watch.check()?);
        Ok(())
    })();
    let stopped = watch.shutdown();
    let first_removed = first.remove();
    let second_removed = second.remove();
    result?;
    stopped?;
    first_removed?;
    second_removed?;
    assert_eq!(
        observer.observed().err().map(|error| error.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    Ok(())
}

#[test]
fn dropping_owner_joins_worker_and_closes_cloned_observers() -> TestResult {
    let directory = Directory::new()?;
    let watch = ConfigurationWatch::start(std::slice::from_ref(&directory.0))?;
    let observer = watch.observer();
    let another = observer.clone();
    watch.check()?;
    drop(watch);
    for observer in [observer, another] {
        assert_eq!(
            observer.observed().err().map(|error| error.kind()),
            Some(io::ErrorKind::BrokenPipe)
        );
    }
    directory.remove()?;
    Ok(())
}

#[test]
fn lost_directory_watch_is_terminal_and_shutdown_reports_it() -> TestResult {
    let directory = Directory::new()?;
    let watch = ConfigurationWatch::start(std::slice::from_ref(&directory.0))?;
    let observer = watch.observer();
    fs::remove_dir(&directory.0)?;
    let checked = watch.check();
    let stopped = watch.shutdown();
    assert_eq!(
        checked.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(
        stopped.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(
        observer.observed().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn invalid_paths_are_rejected_before_native_registration() {
    for paths in [
        Vec::new(),
        vec![PathBuf::from("relative")],
        vec![PathBuf::from("/too-many"); 129],
    ] {
        assert_eq!(
            ConfigurationWatch::start(&paths)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
}

#[test]
fn failed_registrations_stop_owned_workers_and_preserve_terminal_errors() -> TestResult {
    let directory = Directory::new()?;
    let missing = directory.0.join("missing-target");
    assert_eq!(
        ConfigurationWatch::start(std::slice::from_ref(&missing))
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(libc::ENOENT)
    );
    let watch = ConfigurationWatch::start(std::slice::from_ref(&directory.0))?;
    let observer = watch.observer();
    let registration = watch.ensure_paths(&[missing]);
    let shutdown = watch.shutdown();
    directory.remove()?;
    for error in [
        registration.err(),
        shutdown.err(),
        observer.observed().err(),
    ] {
        assert_eq!(
            error.and_then(|error| error.raw_os_error()),
            Some(libc::ENOENT)
        );
    }
    Ok(())
}
