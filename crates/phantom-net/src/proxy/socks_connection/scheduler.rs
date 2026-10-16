//! A delayed second complete SOCKS negotiation, separate from proxy TCP walking.
use super::{Setup, SocksConnectionError, SocksSlower, Target};
use crate::tcp::{AddressFamily, AddressFamilyMemory, ProfileTcpStream};
use phantom_profile::TcpBackupConnection;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
type Attempt = Pin<Box<dyn Future<Output = Result<ProfileTcpStream, SocksConnectionError>> + Send>>;
#[derive(Clone)]
struct Targets {
    first: VecDeque<Target>,
    other: Option<VecDeque<Target>>,
    timeout: Option<Duration>,
    switched: bool,
}
impl Targets {
    fn next(&mut self) -> Option<(Target, Option<Duration>)> {
        if let Some(target) = self.first.pop_front() {
            return Some((target, self.timeout));
        }
        self.first = self.other.take()?;
        self.timeout = None;
        self.switched = true;
        self.first.pop_front().map(|target| (target, None))
    }
}
pub(super) struct Connected {
    pub(super) stream: ProfileTcpStream,
    target: Target,
    switched: bool,
}
impl Connected {
    pub(super) fn remember(&self, memory: &AddressFamilyMemory) {
        if let Target::Address(a) = self.target {
            memory.record_connection(&a, self.switched)
        }
    }
}
pub(super) struct Walk {
    attempt: Attempt,
    targets: Targets,
    target: Target,
    started: Instant,
}
impl Walk {
    fn start(mut targets: Targets, setup: Arc<Setup>, started: Instant) -> Option<Self> {
        let (target, timeout) = targets.next()?;
        let owned = target.clone();
        let attempt = Box::pin(async move {
            // Schedule once before I/O; the limit encloses proxy DNS/TCP/auth/reply.
            let deadline = timeout
                .map(crate::tcp::deadline)
                .transpose()
                .map_err(|e| setup.route.connect_error(e))?;
            let connect = setup.connect(&owned, started);
            let mut connect = std::pin::pin!(connect);
            match deadline {
                None => connect.await,
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        result = &mut connect => result,
                        () = deadline => Err(SocksConnectionError::AttemptTimeout(setup.route.four())),
                    }
                }
            }
        });
        Some(Self {
            attempt,
            targets,
            target,
            started,
        })
    }
    fn connected(self, stream: ProfileTcpStream) -> Connected {
        Connected {
            stream,
            target: self.target,
            switched: self.targets.switched,
        }
    }
    fn next(self, error: &SocksConnectionError, setup: Arc<Setup>) -> Option<Self> {
        if !error.retry_target() {
            return None;
        }
        Self::start(self.targets, setup, self.started)
    }
    async fn poll(slot: &mut Option<Self>) -> Result<ProfileTcpStream, SocksConnectionError> {
        match slot {
            Some(walk) => walk.attempt.as_mut().await,
            None => std::future::pending().await,
        }
    }
    pub(super) async fn finish(
        mut self,
        setup: Arc<Setup>,
    ) -> Result<Connected, SocksConnectionError> {
        loop {
            match self.attempt.as_mut().await {
                Ok(stream) => return Ok(self.connected(stream)),
                Err(error) => match self.next(&error, Arc::clone(&setup)) {
                    Some(next) => self = next,
                    None => return Err(error),
                },
            }
        }
    }
}
fn plans(
    targets: Vec<Target>,
    family: Option<AddressFamily>,
    timeout: Option<Duration>,
) -> (Targets, Targets) {
    match family {
        None => {
            let backup = targets
                .iter()
                .filter(|t| t.ipv6() != Some(true))
                .cloned()
                .collect();
            (
                Targets {
                    first: targets.into(),
                    other: None,
                    timeout: None,
                    switched: false,
                },
                Targets {
                    first: backup,
                    other: None,
                    timeout: None,
                    switched: false,
                },
            )
        }
        Some(family) => {
            // Remote DNS has no observed logical family; never filter it by a synthetic value.
            let (first, other) = targets.into_iter().partition(|t| {
                t.ipv6()
                    .is_none_or(|ipv6| ipv6 == (family == AddressFamily::Ipv6))
            });
            let primary = Targets {
                first,
                other: Some(other),
                timeout: None,
                switched: false,
            };
            let backup = Targets {
                timeout,
                ..primary.clone()
            };
            (primary, backup)
        }
    }
}
pub(super) async fn connect(
    setup: Arc<Setup>,
    targets: Vec<Target>,
    family: &AddressFamilyMemory,
    backup: TcpBackupConnection,
    started: Instant,
) -> Result<(ProfileTcpStream, Option<SocksSlower>), SocksConnectionError> {
    let (primary, secondary) = plans(targets, family.family(), backup.known_family_backup_timeout);
    let delay = crate::tcp::deadline(backup.delay).map_err(|e| setup.route.connect_error(e))?;
    let mut delay = std::pin::pin!(delay);
    let mut primary = Walk::start(primary, Arc::clone(&setup), started);
    let mut secondary = Some(secondary);
    let mut backup_walk = None;
    let mut last = None;
    loop {
        if primary.is_none() && backup_walk.is_none() {
            return Err(last.unwrap_or_else(|| {
                setup.route.connect_error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no SOCKS target addresses",
                ))
            }));
        }
        tokio::select! {
            biased;
            result = Walk::poll(&mut primary), if primary.is_some() => {
                let Some(walk) = primary.take() else { continue };
                match result {
                    Ok(stream) => {
                        let connected = walk.connected(stream);
                        connected.remember(family);
                        let slower = backup_walk.map(|walk| {
                            SocksSlower::new(walk, Arc::clone(&setup), family.clone())
                        });
                        return Ok((connected.stream, slower));
                    }
                    Err(error) => {
                        if error.terminal() { return Err(error); }
                        primary = walk.next(&error, Arc::clone(&setup));
                        last = Some(error);
                    }
                }
                if primary.is_none() && backup_walk.is_none() { secondary = None; }
            }
            result = Walk::poll(&mut backup_walk), if backup_walk.is_some() => {
                let Some(walk) = backup_walk.take() else { continue };
                match result {
                    Ok(stream) => {
                        let connected = walk.connected(stream);
                        connected.remember(family);
                        let slower = primary.map(|walk| {
                            SocksSlower::new(walk, Arc::clone(&setup), family.clone())
                        });
                        return Ok((connected.stream, slower));
                    }
                    Err(error) => {
                        if error.terminal() { return Err(error); }
                        backup_walk = walk.next(&error, Arc::clone(&setup));
                        last = Some(error);
                    }
                }
            }
            () = &mut delay, if secondary.is_some() && primary.is_some() => {
                if let Some(targets) = secondary.take() {
                    backup_walk = Walk::start(targets, Arc::clone(&setup), Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
