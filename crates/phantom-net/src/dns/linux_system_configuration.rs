//! Owned Linux host intake around the pure DNS projection and native watcher.

use super::linux_configuration::{
    LibcOptionSyntax, LinuxDnsConfiguration, LinuxDnsEligibility, LinuxDnsIneligibility,
    LinuxDnsOverrides, MAX_INPUT_BYTES, chromium_linux_with_overrides,
};
pub(super) use crate::linux_dns_ffi::configuration_watch::{
    ConfigurationGeneration, ConfigurationObserver,
};
use crate::linux_dns_ffi::{self, configuration_watch::ConfigurationWatch as NativeWatch};
use std::{
    env, fmt,
    fs::OpenOptions,
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) type ConfigurationError = io::Error;
pub(super) type WatchError = io::Error;

#[derive(Clone, Default)]
pub(super) struct ConfigurationIneligibility {
    policy: LinuxDnsIneligibility,
    zero_attempts: bool,
    conflicting_scopes: bool,
    failure: Option<Arc<io::Error>>,
}

impl fmt::Debug for ConfigurationIneligibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationIneligibility")
            .field("policy", &self.policy)
            .field("zero_attempts", &self.zero_attempts)
            .field("conflicting_scopes", &self.conflicting_scopes)
            .field(
                "failure_kind",
                &self.failure.as_ref().map(|error| error.kind()),
            )
            .finish()
    }
}

#[derive(Debug)]
pub(super) enum ConfigurationEligibility {
    BuiltIn(LinuxDnsConfiguration),
    SystemOnly { reasons: ConfigurationIneligibility },
}

impl ConfigurationEligibility {
    fn unavailable(error: io::Error) -> Self {
        Self::SystemOnly {
            reasons: ConfigurationIneligibility {
                failure: Some(Arc::new(error)),
                ..Default::default()
            },
        }
    }
}

#[derive(Default)]
struct Environment {
    local_domain: Option<String>,
    res_options: Option<String>,
}

impl Environment {
    fn capture() -> io::Result<Self> {
        fn value(name: &str) -> io::Result<Option<String>> {
            match env::var(name) {
                Ok(value) if value.len() <= MAX_INPUT_BYTES => Ok(Some(value)),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Linux DNS environment override exceeds its bound",
                )),
                Err(env::VarError::NotPresent) => Ok(None),
                Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Linux DNS environment override is not UTF-8",
                )),
            }
        }
        Ok(Self {
            local_domain: value("LOCALDOMAIN")?,
            res_options: value("RES_OPTIONS")?,
        })
    }
}

pub(super) struct ConfigurationWatch {
    native: NativeWatch,
    // Like the browser process's startup environment, these values belong
    // to this owner. They are never re-read independently by its two views.
    environment: Result<Environment, Arc<io::Error>>,
}

impl fmt::Debug for ConfigurationWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationWatch(..)")
    }
}

impl ConfigurationWatch {
    pub(super) fn start() -> io::Result<Self> {
        let environment = Environment::capture().map_err(Arc::new);
        let paths = watch_paths()?;
        let native = NativeWatch::start(&paths)?;
        Ok(Self {
            native,
            environment,
        })
    }

    pub(super) fn observer(&self) -> ConfigurationObserver {
        self.native.observer()
    }

    pub(super) fn check(&self) -> io::Result<ConfigurationGeneration> {
        self.native.check()
    }

    pub(super) fn shutdown(self) -> io::Result<()> {
        self.native.shutdown()
    }

    pub(super) fn read_configuration(&self) -> io::Result<ConfigurationEligibility> {
        // Re-arm new symlink targets before sampling their contents. Original
        // and prior parents remain watched, so replacements invalidate too.
        let mut paths = watch_paths()?;
        // A link can change while its new parents are being registered. Repeat
        // path discovery until every currently resolved parent was registered.
        // The native generation fences detect later changes to that chain.
        let mut stable = false;
        for _ in 0..8 {
            self.native.ensure_paths(&paths)?;
            let current = watch_paths()?;
            if current.iter().all(|path| paths.contains(path)) {
                stable = true;
                break;
            }
            paths = current;
        }
        if !stable {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Linux DNS paths changed during intake",
            ));
        }
        Ok(match self.read_projected() {
            Ok(eligibility) => eligibility,
            Err(error) => ConfigurationEligibility::unavailable(error),
        })
    }

    fn read_projected(&self) -> io::Result<ConfigurationEligibility> {
        let environment = self.environment.as_ref().map_err(|error| {
            io::Error::new(
                error.kind(),
                "Linux DNS environment override is unavailable",
            )
        })?;
        let syntax = option_syntax(linux_dns_ffi::glibc_version()?)?;
        let resolv = read_bounded(Path::new("/etc/resolv.conf"))?;
        let nsswitch = read_bounded(Path::new("/etc/nsswitch.conf"))?;
        let hostname = linux_dns_ffi::hostname()?;
        let indices = interface_indices(&resolv)?;
        let borrowed = indices
            .iter()
            .map(|(name, index)| (name.as_str(), *index))
            .collect::<Vec<_>>();
        let eligibility = chromium_linux_with_overrides(
            &resolv,
            &nsswitch,
            &LinuxDnsOverrides {
                local_domain: environment.local_domain.as_deref(),
                res_options: environment.res_options.as_deref(),
                hostname: Some(&hostname),
                interface_indices: &borrowed,
                option_syntax: syntax,
            },
        )
        .map_err(io::Error::other)?;
        Ok(match eligibility {
            LinuxDnsEligibility::SystemOnly { reasons, .. } => {
                ConfigurationEligibility::SystemOnly {
                    reasons: ConfigurationIneligibility {
                        policy: reasons,
                        ..Default::default()
                    },
                }
            }
            LinuxDnsEligibility::BuiltIn(configuration) => apply_supported(configuration),
        })
    }
}

fn option_syntax(version: (u32, u32)) -> io::Result<LibcOptionSyntax> {
    match version {
        // glibc 2.26 switched to the complete-suffix six/256 projection.
        // 95f61610 introduced negation for the 2.41 release. Newer uninspected
        // libc versions need an explicit syntax decision rather than a guess.
        (2, 26..=40) => Ok(LibcOptionSyntax::Legacy),
        (2, 41..=42) => Ok(LibcOptionSyntax::Negation),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux DNS libc option syntax is not established",
        )),
    }
}

fn apply_supported(configuration: LinuxDnsConfiguration) -> ConfigurationEligibility {
    // Hickory always makes an initial attempt. It cannot express a native
    // zero-attempt configuration or two identical endpoints on different
    // interfaces without losing their identity.
    let zero_attempts = configuration.attempts == 0;
    let conflicting_scopes = conflicting_scopes(&configuration.servers);
    if zero_attempts || conflicting_scopes {
        ConfigurationEligibility::SystemOnly {
            reasons: ConfigurationIneligibility {
                zero_attempts,
                conflicting_scopes,
                ..Default::default()
            },
        }
    } else {
        ConfigurationEligibility::BuiltIn(configuration)
    }
}

fn conflicting_scopes(servers: &[SocketAddr]) -> bool {
    servers.iter().enumerate().any(|(index, address)| {
        servers[..index].iter().any(|known| {
            known.ip() == address.ip() && known.port() == address.port() && known != address
        })
    })
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    // Reject special files without blocking on a FIFO before metadata can
    // establish its type. O_NONBLOCK has no effect on regular file reads.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        // glibc/NSS use their default configuration when the files are absent.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux DNS input is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux DNS input exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn interface_indices(resolv: &[u8]) -> io::Result<Vec<(String, u32)>> {
    let text = std::str::from_utf8(resolv)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Linux DNS input is not UTF-8"))?;
    let mut indices = Vec::new();
    for line in text.lines() {
        let Some(("nameserver", value)) = line.split_once([' ', '\t']) else {
            continue;
        };
        let Some((_, scope)) = value
            .split_ascii_whitespace()
            .next()
            .and_then(|value| value.split_once('%'))
        else {
            continue;
        };
        if scope.bytes().all(|byte| byte.is_ascii_digit())
            || indices.iter().any(|(known, _)| known == scope)
        {
            continue;
        }
        if indices.len() == 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Linux DNS interface witness count exceeds its bound",
            ));
        }
        indices.push((scope.to_owned(), linux_dns_ffi::interface_index(scope)?));
    }
    Ok(indices)
}

fn watch_paths() -> io::Result<Vec<PathBuf>> {
    configuration_paths(&[
        Path::new("/etc/resolv.conf"),
        Path::new("/etc/nsswitch.conf"),
        Path::new("/etc/hosts"),
    ])
}

fn configuration_paths(inputs: &[&Path]) -> io::Result<Vec<PathBuf>> {
    use std::{collections::VecDeque, path::Component};
    let mut paths = Vec::new();
    for input in inputs {
        if !input.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS watch path is relative",
            ));
        }
        let mut pending = input
            .components()
            .map(|part| part.as_os_str().to_owned())
            .collect::<VecDeque<_>>();
        let mut resolved = PathBuf::from("/");
        let mut links = 0;
        let mut components = 0;
        while let Some(part) = pending.pop_front() {
            components += 1;
            if components > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS watch path exceeds its bound",
                ));
            }
            match Path::new(&part).components().next() {
                Some(Component::RootDir) => {
                    resolved = PathBuf::from("/");
                    continue;
                }
                Some(Component::CurDir) => continue,
                Some(Component::ParentDir) => {
                    resolved.pop();
                    continue;
                }
                Some(Component::Normal(_)) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid DNS watch path",
                    ));
                }
            }
            // Watch each existing directory before following its child. This
            // includes the parent of every intermediate and directory symlink.
            if !paths.contains(&resolved) {
                paths.push(resolved.clone());
            }
            let candidate = resolved.join(&part);
            let metadata = match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() {
                links += 1;
                if links > 40 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS watch symlink limit exceeded",
                    ));
                }
                let target = std::fs::read_link(&candidate)?;
                for part in target.components().rev() {
                    pending.push_front(part.as_os_str().to_owned());
                }
            } else {
                resolved = candidate;
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn configuration(attempts: u8, servers: Vec<SocketAddr>) -> LinuxDnsConfiguration {
        LinuxDnsConfiguration {
            servers,
            search: vec!["internal.test".into()],
            ndots: 2,
            attempts,
            rotate: true,
        }
    }

    #[test]
    fn a_zero_attempt_policy_never_becomes_an_initial_raw_query() {
        let result = apply_supported(configuration(
            0,
            vec![SocketAddr::from(([127, 0, 0, 1], 53))],
        ));
        assert!(
            matches!(result, ConfigurationEligibility::SystemOnly { reasons } if reasons.zero_attempts)
        );
    }

    #[test]
    fn libc_syntax_uses_native_version_and_rejects_unestablished_versions() {
        assert!(matches!(
            option_syntax((2, 39)),
            Ok(LibcOptionSyntax::Legacy)
        ));
        assert!(matches!(
            option_syntax((2, 40)),
            Ok(LibcOptionSyntax::Legacy)
        ));
        assert!(matches!(
            option_syntax((2, 41)),
            Ok(LibcOptionSyntax::Negation)
        ));
        assert!(matches!(
            option_syntax((2, 42)),
            Ok(LibcOptionSyntax::Negation)
        ));
        assert!(option_syntax((2, 25)).is_err());
        assert!(option_syntax((2, 43)).is_err());
        assert!(option_syntax((3, 0)).is_err());
    }

    #[test]
    fn conflicting_interface_scopes_require_the_system_resolver() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let servers = vec![
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 7)),
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 8)),
        ];
        assert!(
            matches!(apply_supported(configuration(2, servers)), ConfigurationEligibility::SystemOnly { reasons } if reasons.conflicting_scopes)
        );
    }

    #[test]
    fn duplicate_identical_scopes_keep_their_order_and_policy() {
        let server = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 7));
        let result = apply_supported(configuration(3, vec![server, server]));
        let ConfigurationEligibility::BuiltIn(configuration) = result else {
            panic!("identical scope was rejected");
        };
        assert_eq!(configuration.servers, [server, server]);
        assert_eq!(configuration.search, ["internal.test"]);
        assert_eq!(configuration.ndots, 2);
        assert_eq!(configuration.attempts, 3);
        assert!(configuration.rotate);
    }

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> io::Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..128 {
                let number = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir()
                    .join(format!("phantom-dns-paths-{}-{number}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path.canonicalize()?)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "no owned DNS test directory",
            ))
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn intermediate_symlink_replacement_invalidates_the_watched_configuration() -> io::Result<()> {
        use std::os::unix::fs::symlink;
        let directory = Directory::new()?;
        let root = &directory.0;
        for path in ["etc", "run/provider", "run/other"] {
            std::fs::create_dir_all(root.join(path))?;
        }
        std::fs::write(
            root.join("run/provider/resolv.conf"),
            b"nameserver 127.0.0.1\n",
        )?;
        std::fs::write(
            root.join("run/other/resolv.conf"),
            b"nameserver 127.0.0.2\n",
        )?;
        symlink("provider/resolv.conf", root.join("run/current"))?;
        symlink("../run/current", root.join("etc/resolv.conf"))?;
        let input = root.join("etc/resolv.conf");
        let paths = configuration_paths(&[&input])?;
        assert!(paths.contains(&root.join("run")));
        let watch = NativeWatch::start(&paths)?;
        let result: io::Result<()> = (|| {
            let before = watch.check()?;
            symlink("other/resolv.conf", root.join("run/next"))?;
            std::fs::rename(root.join("run/next"), root.join("run/current"))?;
            assert_ne!(before, watch.check()?);
            watch.ensure_paths(&configuration_paths(&[&input])?)?;
            let changed = watch.check()?;
            std::fs::write(root.join("run/other/resolv.conf"), b"nameserver ::1\n")?;
            assert_ne!(changed, watch.check()?);
            Ok(())
        })();
        let stopped = watch.shutdown();
        result?;
        stopped
    }

    #[test]
    fn directory_symlink_parents_are_watched_and_cycles_are_rejected() -> io::Result<()> {
        use std::os::unix::fs::symlink;
        let directory = Directory::new()?;
        let root = &directory.0;
        std::fs::create_dir_all(root.join("actual/nested"))?;
        std::fs::create_dir(root.join("links"))?;
        symlink("../actual", root.join("links/directory"))?;
        let paths = configuration_paths(&[&root.join("links/directory/nested/resolv.conf")])?;
        assert!(paths.contains(&root.join("links")));
        assert!(paths.contains(&root.join("actual/nested")));
        symlink("cycle", root.join("cycle"))?;
        assert!(configuration_paths(&[&root.join("cycle")]).is_err());
        Ok(())
    }
}
