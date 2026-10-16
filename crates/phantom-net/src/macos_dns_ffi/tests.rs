use super::{
    ABI, OPTIONS, RESOLVERS, RawAddress, RawSettings,
    configuration::{ConfigurationError, MacDnsConfiguration, SystemOnlyReason, decode},
};
use std::{io, net::SocketAddr, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn raw() -> RawSettings {
    let mut raw = RawSettings {
        abi: ABI,
        nameserver_count: 1,
        ndots: 1,
        attempts: 2,
        retrans_seconds: 5,
        ..RawSettings::default()
    };
    raw.nameservers[0] = RawAddress {
        family: 4,
        port: 53,
        address: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..RawAddress::default()
    };
    raw
}

#[test]
fn effective_settings_preserve_address_order_ports_scope_search_and_options() -> TestResult {
    let mut raw = raw();
    raw.nameserver_count = 2;
    raw.nameservers[0].port = 5353;
    raw.nameservers[1] = RawAddress {
        family: 6,
        port: 5300,
        scope: 7,
        flow: 11,
        address: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };
    raw.search_count = 2;
    raw.search[0][..11].copy_from_slice(b"one.example");
    raw.search[1][..11].copy_from_slice(b"two.example");
    raw.ndots = 4;
    raw.attempts = 3;
    raw.retrans_seconds = 8;
    raw.rotate = 1;
    let MacDnsConfiguration::BuiltIn(settings) = decode(&raw)? else {
        return Err(io::Error::other("expected built-in settings").into());
    };
    assert_eq!(
        settings.nameservers[0],
        "127.0.0.1:5353".parse::<SocketAddr>()?
    );
    let SocketAddr::V6(v6) = settings.nameservers[1] else {
        return Err(io::Error::other("expected IPv6 nameserver").into());
    };
    assert_eq!(v6.ip().segments(), [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!((v6.port(), v6.scope_id(), v6.flowinfo()), (5300, 7, 11));
    assert_eq!(settings.search, ["one.example", "two.example"]);
    assert_eq!(settings.ndots, 4);
    assert_eq!(settings.attempts, 3);
    assert_eq!(settings.retrans, Duration::from_secs(8));
    assert!(settings.rotate);
    Ok(())
}

#[test]
fn unsupported_options_and_multiple_resolvers_remain_system_only() -> TestResult {
    for reasons in [OPTIONS, RESOLVERS, OPTIONS | RESOLVERS] {
        let mut raw = raw();
        raw.ineligible = reasons;
        let MacDnsConfiguration::SystemOnly(reason) = decode(&raw)? else {
            return Err(io::Error::other("unsupported settings became built-in").into());
        };
        assert_eq!(
            reason,
            SystemOnlyReason::Unsupported {
                resolver_options: reasons & OPTIONS != 0,
                multiple_resolvers: reasons & RESOLVERS != 0,
            }
        );
    }
    Ok(())
}

#[test]
fn foreign_abi_and_unknown_eligibility_flags_are_rejected() {
    let mut raw = raw();
    raw.abi += 1;
    assert!(decode(&raw).is_err());
    raw.abi = ABI;
    raw.ineligible = 4;
    assert!(decode(&raw).is_err());
}

#[test]
fn native_counts_cannot_silently_truncate_servers_or_search() {
    let mut raw = raw();
    for count in [0, 4, u32::MAX] {
        raw.nameserver_count = count;
        assert!(decode(&raw).is_err());
    }
    raw.nameserver_count = 1;
    raw.search_count = 7;
    assert!(decode(&raw).is_err());
}

#[test]
fn malformed_server_family_port_and_unspecified_address_are_rejected() {
    let mut raw = raw();
    raw.nameservers[0].family = 7;
    assert!(decode(&raw).is_err());
    raw.nameservers[0].family = 4;
    for port in [0, 65536] {
        raw.nameservers[0].port = port;
        assert!(decode(&raw).is_err());
    }
    raw.nameservers[0].port = 53;
    raw.nameservers[0].address = [0; 16];
    assert!(decode(&raw).is_err());
    raw.nameservers[0].family = 6;
    assert!(decode(&raw).is_err());
}

#[test]
fn ipv4_cannot_hide_scope_flow_or_unused_address_bytes() {
    let original = raw();
    for which in 0..3 {
        let mut raw = raw();
        match which {
            0 => raw.nameservers[0].scope = 1,
            1 => raw.nameservers[0].flow = 1,
            _ => raw.nameservers[0].address[15] = 1,
        }
        assert!(decode(&raw).is_err());
    }
    assert!(decode(&original).is_ok());
}

#[test]
fn unterminated_non_ascii_and_empty_search_are_rejected() {
    let mut raw = raw();
    raw.search_count = 1;
    raw.search[0] = [b'x'; 256];
    assert!(decode(&raw).is_err());
    raw.search[0] = [0; 256];
    assert!(decode(&raw).is_err());
    raw.search[0][0] = 0xff;
    assert!(decode(&raw).is_err());
}

#[test]
fn invalid_resolver_options_do_not_become_defaults() {
    for which in 0..4 {
        let mut raw = raw();
        match which {
            0 => raw.ndots = 16,
            1 => raw.attempts = 0,
            2 => raw.retrans_seconds = 0,
            _ => raw.rotate = 2,
        }
        assert!(decode(&raw).is_err());
    }
}

#[test]
fn debug_and_errors_do_not_disclose_configuration_values() -> TestResult {
    let raw = raw();
    let rendered = format!("{:?}", decode(&raw)?);
    assert!(!rendered.contains("127.0.0.1"));
    let rendered = ConfigurationError::InvalidData("nameserver port").to_string();
    assert!(!rendered.contains("127.0.0.1"));
    assert!(rendered.contains("nameserver port"));
    Ok(())
}

// Actual owned-temp-path Darwin controls, not fabricated native notifications.
// They require the SDK-linked boundary and remain unexecuted without a Mac.
struct OwnedHosts(std::path::PathBuf);
impl OwnedHosts {
    fn new() -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "phantom-hosts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}
impl Drop for OwnedHosts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_hosts_same_size_write_and_atomic_replacement_invalidate() -> TestResult {
    use super::configuration_watch::{ConfigurationWatch, WatchCause};
    let temp = OwnedHosts::new()?;
    let path = temp.path("hosts");
    std::fs::write(&path, b"127.0.0.1 one\n")?;
    let watch = ConfigurationWatch::start_with_hosts(&path)?;
    let observer = watch.observer();
    let before = watch.check()?;
    // Parent directory metadata is unchanged by this equal-size in-place write.
    std::fs::write(&path, b"127.0.0.1 two\n")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let observed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), observer.changed_since(&before)).await
    })??;
    let written = watch.check()?;
    let old = std::fs::File::open(&path)?;
    let replacement = temp.path("replacement");
    std::fs::write(&replacement, b"127.0.0.1 new\n")?;
    std::fs::rename(&replacement, &path)?;
    let replaced = watch.check()?;
    watch.shutdown()?;
    drop(old);
    assert_ne!(before, observed);
    assert_ne!(before, written);
    assert_ne!(written, replaced);
    assert_eq!(
        observer.observed().err().map(|e| e.cause),
        Some(WatchCause::Stopped)
    );
    Ok(())
}

#[test]
fn native_missing_hosts_arms_existing_ancestor_before_creation() -> TestResult {
    use super::configuration_watch::ConfigurationWatch;
    let temp = OwnedHosts::new()?;
    let path = temp.path("missing/hosts");
    let watch = ConfigurationWatch::start_with_hosts(&path)?;
    let before = watch.check()?;
    std::fs::create_dir(temp.path("missing"))?;
    std::fs::write(&path, b"127.0.0.1 created\n")?;
    let created = watch.check()?;
    std::fs::write(&path, b"127.0.0.1 changed\n")?;
    let written = watch.check()?;
    watch.shutdown()?;
    assert_ne!(before, created);
    assert_ne!(created, written);
    Ok(())
}

#[test]
fn native_intermediate_and_final_symlink_replacement_rearms_new_targets() -> TestResult {
    use super::configuration_watch::ConfigurationWatch;
    use std::os::unix::fs::symlink;
    let temp = OwnedHosts::new()?;
    for name in ["first", "second"] {
        std::fs::create_dir(temp.path(name))?;
        std::fs::write(temp.path(&format!("{name}/contents")), b"127.0.0.1 one\n")?;
        symlink("contents", temp.path(&format!("{name}/hosts")))?;
    }
    symlink("first", temp.path("directory"))?;
    let watch = ConfigurationWatch::start_with_hosts(&temp.path("directory/hosts"))?;
    let before = watch.check()?;
    symlink("second", temp.path("replacement"))?;
    std::fs::rename(temp.path("replacement"), temp.path("directory"))?;
    let moved = watch.check()?;
    std::fs::write(temp.path("second/other"), b"127.0.0.1 two\n")?;
    symlink("other", temp.path("second/replacement"))?;
    std::fs::rename(temp.path("second/replacement"), temp.path("second/hosts"))?;
    let relinked = watch.check()?;
    std::fs::write(temp.path("second/other"), b"127.0.0.1 new\n")?;
    let written = watch.check()?;
    watch.shutdown()?;
    assert_ne!(before, moved);
    assert_ne!(moved, relinked);
    assert_ne!(relinked, written);
    Ok(())
}

#[test]
fn native_hosts_cycles_oversized_files_and_nonregular_targets_fail_closed() -> TestResult {
    use super::configuration_watch::ConfigurationWatch;
    let temp = OwnedHosts::new()?;
    std::os::unix::fs::symlink("cycle", temp.path("cycle"))?;
    std::fs::write(temp.path("large"), vec![b'x'; 1024 * 1024 + 1])?;
    for path in [temp.path("cycle"), temp.path("large"), temp.0.clone()] {
        assert!(ConfigurationWatch::start_with_hosts(&path).is_err());
    }
    Ok(())
}

#[test]
fn invalid_hosts_paths_are_recoverable_and_redacted_before_thread_start() {
    use super::configuration_watch::{ConfigurationWatch, WatchCause};
    for path in ["relative", "/private\0hidden", "/", "/private/"] {
        let result = ConfigurationWatch::start_with_hosts(std::path::Path::new(path));
        let error = match result {
            Err(error) => error,
            Ok(watch) => {
                drop(watch);
                panic!("invalid hosts path accepted");
            }
        };
        assert_eq!(error.cause, WatchCause::InvalidHostsPath);
        assert!(!error.to_string().contains(path));
    }
}
