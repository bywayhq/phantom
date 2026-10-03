//! Keepalive that follows an HTTP connection's life, as
//! [`TcpKeepaliveSchedule`] describes.
//!
//! The HTTP layers report what the connection is doing through a
//! [`TcpKeepaliveControl`]; the socket options change when the connection's
//! stream is next polled, so they always precede the bytes written after the
//! change. Reporting a change wakes the task that last polled the stream.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Waker},
    time::{Duration, Instant},
};

use phantom_profile::TcpKeepaliveSchedule;
use socket2::SockRef;
use tokio::{net::TcpStream, sync::oneshot};

use super::{option_error, with_interval};

/// Extra time Firefox adds to the short-lived period before the switch
/// (`netwerk/protocol/http/nsHttpConnection.cpp:2183-2184` at tag
/// `FIREFOX_157_0_RELEASE`).
const SWITCH_MARGIN: Duration = Duration::from_secs(2);

/// What keepalive a connection's socket carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeepalivePhase {
    /// Nothing set since the socket connected.
    Unset,
    /// The short-lived idle time and the probe interval.
    ShortLived,
    /// The long-lived idle time and the probe interval.
    LongLived,
    /// Keepalive turned off.
    Disabled,
}

/// The probe interval for a connection whose host lookup and connect took
/// `setup`: whole seconds, at least the schedule's minimum
/// (`netwerk/protocol/http/nsHttpConnection.cpp:2146`).
pub(crate) fn probe_interval(schedule: &TcpKeepaliveSchedule, setup: Duration) -> Duration {
    Duration::from_secs(setup.as_secs()).max(schedule.minimum_interval)
}

/// Time from a request's dispatch until the switch to long-lived keepalive
/// (`netwerk/protocol/http/nsHttpConnection.cpp:2167-2190`).
pub(crate) fn switch_delay(schedule: &TcpKeepaliveSchedule, interval: Duration) -> Duration {
    let time = schedule.short_lived_time.as_secs();
    let idle = schedule.short_lived_idle.as_secs().max(1);
    // A valid schedule's values are far from overflowing; saturating keeps an
    // unchecked one from panicking.
    let probes = interval
        .checked_mul(schedule.probe_count)
        .unwrap_or(Duration::MAX);
    Duration::from_secs(time - time % idle)
        .saturating_add(probes)
        .saturating_add(SWITCH_MARGIN)
}

/// The keepalive state of one connection, shared by its stream and the HTTP
/// layers above it.
#[derive(Clone)]
pub(crate) struct TcpKeepaliveControl {
    shared: Arc<Mutex<State>>,
}

struct State {
    schedule: TcpKeepaliveSchedule,
    interval: Duration,
    wanted: KeepalivePhase,
    applied: KeepalivePhase,
    /// No request is outstanding: the connection waits in a pool.
    idle: bool,
    /// The connection was opened for a request that has not been reported
    /// yet; that report does not restart the short-lived period.
    opening: bool,
    /// When the switch to long-lived keepalive falls due, if it is pending.
    switch_at: Option<Instant>,
    /// The one deadline the connection holds, which falls due at or before
    /// `switch_at`; a request moves the switch later, and the deadline is
    /// then set again for the rest of the wait.
    deadline: Option<oneshot::Receiver<()>>,
    waker: Option<Waker>,
    #[cfg(test)]
    log: Vec<KeepalivePhase>,
}

impl TcpKeepaliveControl {
    /// Starts the schedule of a connection opened for a request, whose host
    /// lookup and connect took `setup`.
    ///
    /// The short-lived values apply before the first byte is written, as
    /// Firefox applies them when it dispatches the request that opened the
    /// connection, before any TLS handshake
    /// (`netwerk/protocol/http/nsHttpConnection.cpp:686`).
    pub(crate) fn opened(schedule: TcpKeepaliveSchedule, setup: Duration) -> Self {
        let interval = probe_interval(&schedule, setup);
        let mut state = State {
            schedule,
            interval,
            wanted: KeepalivePhase::ShortLived,
            applied: KeepalivePhase::Unset,
            idle: false,
            opening: true,
            switch_at: None,
            deadline: None,
            waker: None,
            #[cfg(test)]
            log: Vec::new(),
        };
        state.arm_switch();
        let control = Self {
            shared: Arc::new(Mutex::new(state)),
        };
        #[cfg(test)]
        observed::record(&control);
        control
    }

    /// Starts the schedule of a connection that waits in a pool before its
    /// first request, whose attempt took `setup` to connect.
    ///
    /// Nothing is applied until [`Self::request_dispatched`]: Firefox puts
    /// such a plaintext connection in its idle list without a transaction,
    /// and keepalive starts when it dispatches the first one
    /// (`netwerk/protocol/http/DnsAndConnectSocket.cpp:711-717`,
    /// `netwerk/protocol/http/nsHttpConnection.cpp:686`).
    pub(crate) fn opened_idle(schedule: TcpKeepaliveSchedule, setup: Duration) -> Self {
        let control = Self {
            shared: Arc::new(Mutex::new(State {
                schedule,
                interval: probe_interval(&schedule, setup),
                wanted: KeepalivePhase::Unset,
                applied: KeepalivePhase::Unset,
                idle: true,
                opening: false,
                switch_at: None,
                deadline: None,
                waker: None,
                #[cfg(test)]
                log: Vec::new(),
            })),
        };
        #[cfg(test)]
        observed::record(&control);
        control
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reports an HTTP/1 request dispatched on the connection.
    ///
    /// The connection returns to short-lived keepalive and the switch is
    /// scheduled again, unless keepalive is off. The request that opened the
    /// connection keeps the period that began when it connected.
    pub(crate) fn request_dispatched(&self) {
        let mut state = self.lock();
        state.idle = false;
        if state.opening {
            state.opening = false;
            return;
        }
        if state.wanted == KeepalivePhase::Disabled {
            return;
        }
        state.wanted = KeepalivePhase::ShortLived;
        state.arm_switch();
        state.wake();
    }

    /// Reports that the connection finished its request and waits in a pool.
    ///
    /// A switch that falls due while it waits leaves it short-lived
    /// (`netwerk/protocol/http/nsHttpConnection.cpp:1411-1414`).
    pub(crate) fn connection_idle(&self) {
        let mut state = self.lock();
        state.opening = false;
        state.idle = true;
    }

    /// Reports that the connection now carries another protocol, such as
    /// WebSocket: short-lived keepalive becomes long-lived at once
    /// (`netwerk/protocol/http/nsHttpConnection.cpp:1303-1320`).
    pub(crate) fn upgraded(&self) {
        let mut state = self.lock();
        state.opening = false;
        if state.wanted == KeepalivePhase::ShortLived {
            state.wanted = KeepalivePhase::LongLived;
            state.switch_at = None;
            state.wake();
        }
    }

    /// Reports that the connection negotiated HTTP/2, which turns keepalive
    /// off for good (`netwerk/protocol/http/nsHttpConnection.cpp:405-406`,
    /// `:2243-2262`).
    pub(crate) fn http2_negotiated(&self) {
        let mut state = self.lock();
        state.opening = false;
        state.wanted = KeepalivePhase::Disabled;
        state.switch_at = None;
        state.wake();
    }

    /// Brings the socket's keepalive up to date before an I/O call on it.
    ///
    /// `waker` is the polling task's, woken when the switch falls due or the
    /// HTTP layers report a change.
    pub(crate) fn apply(&self, socket: &TcpStream, waker: &Waker) -> io::Result<()> {
        let mut state = self.lock();
        if !state
            .waker
            .as_ref()
            .is_some_and(|stored| stored.will_wake(waker))
        {
            state.waker = Some(waker.clone());
        }
        state.poll_switch(waker);
        if state.wanted == state.applied {
            return Ok(());
        }
        let socket = SockRef::from(socket);
        let idle = match state.wanted {
            KeepalivePhase::ShortLived => Some(state.schedule.short_lived_idle),
            KeepalivePhase::LongLived => Some(state.schedule.long_lived_idle),
            KeepalivePhase::Disabled | KeepalivePhase::Unset => None,
        };
        match idle {
            Some(idle) => {
                let parameters =
                    with_interval(socket2::TcpKeepalive::new().with_time(idle), state.interval)?;
                socket
                    .set_tcp_keepalive(&parameters)
                    .map_err(|error| option_error("TCP keepalive", error))?;
            }
            // Keepalive was never turned on when nothing was applied yet.
            None if state.applied == KeepalivePhase::Unset => {}
            None => socket
                .set_keepalive(false)
                .map_err(|error| option_error("SO_KEEPALIVE", error))?,
        }
        state.applied = state.wanted;
        #[cfg(test)]
        {
            let applied = state.applied;
            state.log.push(applied);
        }
        Ok(())
    }

    /// Whether the connection waits in a pool with no request outstanding.
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        self.lock().idle
    }

    /// The probe interval this connection uses.
    #[cfg(test)]
    pub(crate) fn interval(&self) -> Duration {
        self.lock().interval
    }

    /// Every phase applied to the socket so far, in order.
    #[cfg(test)]
    pub(crate) fn applied_phases(&self) -> Vec<KeepalivePhase> {
        self.lock().log.clone()
    }
}

impl State {
    /// Schedules the switch to long-lived keepalive from now. A deadline
    /// already pending falls due earlier and is set again then.
    fn arm_switch(&mut self) {
        self.switch_at = Instant::now().checked_add(switch_delay(&self.schedule, self.interval));
        if self.deadline.is_none() {
            self.set_deadline();
        }
    }

    /// Sets the deadline for the rest of the wait until `switch_at`. The
    /// connector checked that the deadline service runs, so scheduling fails
    /// only for a wait too long to represent, which never ends.
    fn set_deadline(&mut self) {
        self.deadline = self.switch_at.and_then(|at| {
            crate::shutdown_timer::after(at.saturating_duration_since(Instant::now())).ok()
        });
    }

    /// Switches a connection with a request outstanding to long-lived
    /// keepalive once the switch falls due, and keeps `waker` registered
    /// with the pending deadline.
    fn poll_switch(&mut self, waker: &Waker) {
        let mut context = Context::from_waker(waker);
        while let Some(deadline) = self.deadline.as_mut() {
            // The deadline service never drops a pending deadline, so an
            // error counts as the deadline too.
            if Pin::new(deadline).poll(&mut context).is_pending() {
                return;
            }
            self.deadline = None;
            let Some(at) = self.switch_at else {
                return;
            };
            if Instant::now() < at {
                self.set_deadline();
                continue;
            }
            self.switch_at = None;
            if self.wanted == KeepalivePhase::ShortLived && !self.idle {
                self.wanted = KeepalivePhase::LongLived;
            }
        }
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
}

/// Schedules opened on the test thread, for tests that cannot reach the
/// connection a connector built.
#[cfg(test)]
pub(crate) mod observed {
    use std::cell::RefCell;

    use super::TcpKeepaliveControl;

    thread_local! {
        static CONTROLS: RefCell<Vec<TcpKeepaliveControl>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(control: &TcpKeepaliveControl) {
        CONTROLS.with(|controls| controls.borrow_mut().push(control.clone()));
    }

    /// Returns and clears the schedules opened on this thread.
    pub(crate) fn take() -> Vec<TcpKeepaliveControl> {
        CONTROLS.with(|controls| std::mem::take(&mut *controls.borrow_mut()))
    }
}

#[cfg(test)]
mod tests;
