//! Caller policy for using a learned HTTP/3 alternative.

use std::{num::NonZeroUsize, time::Duration};

use crate::BuildError;

/// The most alternatives one race may set up at once.
///
/// An HTTP/3 pool entry keeps connections for four transport locations
/// before it closes the least recently used one: the origin's own location,
/// which exact HTTP/3 dials, and three alternatives.
pub(crate) const MAX_RACED_ALTERNATIVES: usize = 3;

/// How a negotiated HTTPS request uses a fresh learned `h3` alternative.
///
/// The default, [`AltSvcPolicy::sequential`], uses the alternative alone: its
/// setup failure is terminal for the request and removes that alternative
/// from the advertisement, so a later request takes the next one the field
/// listed.
/// [`AltSvcPolicy::race`] instead races alternative connection setup against
/// origin connection setup. Racing chooses a connection, never a request
/// replay: the request is sent once, on the winner, and both candidates keep
/// the request's origin identity and route.
///
/// Set the policy with
/// [`ClientBuilder::alt_svc_policy`](crate::ClientBuilder::alt_svc_policy).
/// It has no effect until [`ClientBuilder::alt_svc`](crate::ClientBuilder::alt_svc)
/// enables the store; a racing policy without it makes
/// [`ClientBuilder::build`](crate::ClientBuilder::build) fail with
/// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use phantom::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace};
///
/// let race = AltSvcRace::new(Duration::from_millis(300), AltSvcBrokenBackoff::CHROMIUM_153);
/// let policy = AltSvcPolicy::race(race);
/// assert_eq!(policy.race_settings(), Some(race));
/// assert_eq!(AltSvcPolicy::default(), AltSvcPolicy::sequential());
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AltSvcPolicy {
    race: Option<AltSvcRace>,
}

impl AltSvcPolicy {
    /// Uses the alternative alone; setup failure is terminal and evicts it.
    #[must_use]
    pub const fn sequential() -> Self {
        Self { race: None }
    }

    /// Races alternative setup against delayed origin setup.
    #[must_use]
    pub const fn race(race: AltSvcRace) -> Self {
        Self { race: Some(race) }
    }

    /// Returns the racing parameters, or `None` for sequential use.
    #[must_use]
    pub const fn race_settings(self) -> Option<AltSvcRace> {
        self.race
    }

    pub(crate) fn validate(self) -> Result<(), BuildError> {
        match self.race {
            Some(race)
                if std::time::Instant::now()
                    .checked_add(race.origin_delay)
                    .is_none() =>
            {
                Err(BuildError::invalid_policy(
                    "Alt-Svc origin delay is not representable",
                ))
            }
            Some(race)
                if std::time::Instant::now()
                    .checked_add(race.alternative_setup_limit)
                    .is_none() =>
            {
                Err(BuildError::invalid_policy(
                    "Alt-Svc alternative setup limit is not representable",
                ))
            }
            Some(race) if race.max_alternatives.get() > MAX_RACED_ALTERNATIVES => Err(
                BuildError::invalid_policy("Alt-Svc race allows at most 3 alternatives"),
            ),
            Some(_) | None => Ok(()),
        }
    }
}

/// Parameters for racing a learned HTTP/3 alternative against the origin.
///
/// QUIC setup to the alternative starts first. Origin H1/H2 setup starts
/// after `origin_delay`, or at once when every raced alternative fails first
/// or the origin already has a reusable pooled HTTP/2 connection. The first
/// candidate to finish setup carries the request.
///
/// One alternative is raced by default: the first one the field listed that
/// is not broken, as Chrome 154 does.
/// [`AltSvcRace::with_max_alternatives`] races more of them at once, which is
/// caller policy rather than browser behavior.
///
/// An alternative connection attempt, including name resolution and any
/// proxy setup, runs for at most 4 seconds by default, Chrome 153's timeout
/// for a blackholed alternative; reaching it is a setup failure.
/// [`AltSvcRace::with_alternative_setup_limit`] changes it. Chrome restarts
/// that timeout on every received packet, so a responsive alternative whose
/// handshake needs longer fails here but not in Chrome.
///
/// When another candidate wins while an alternative is connecting, that
/// alternative's setup continues in the background on the current Tokio
/// runtime and keeps its HTTP/3 admission permit until it ends; a finished
/// connection is pooled for later requests. A setup still waiting for
/// admission or for another setup to the same location is cancelled instead.
/// Without a Tokio runtime handle the unfinished setup is dropped, and
/// nothing is pooled or marked.
///
/// An alternative that fails while the origin succeeds is marked broken for
/// [`AltSvcBrokenBackoff`] and is not raced again until that period ends.
/// Meanwhile the next alternative the field listed is raced, as Chrome does.
/// With every listed alternative broken the origin is used alone, without
/// the HTTPS-record lookup Chrome would still race. When every candidate
/// fails, nothing is marked.
///
/// When several alternatives race and one of them wins, a failed one is
/// marked broken too, once the winner's handshake has completed; one still
/// connecting when the winner was chosen is marked if it fails later, as a
/// background setup is. Chrome never races two alternatives, so this is
/// Phantom's choice for the caller policy, not browser behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AltSvcRace {
    origin_delay: Duration,
    broken_backoff: AltSvcBrokenBackoff,
    alternative_setup_limit: Duration,
    max_alternatives: NonZeroUsize,
}

/// Longest time one raced alternative connection attempt may run once it
/// holds its location's connect turn: Chromium's client QUIC idle timeout
/// before the handshake completes.
///
/// At 153.0.8010.48, `QuicParams::max_idle_time_before_crypto_handshake` is
/// `quic::kInitialIdleTimeoutSecs` (`net/quic/quic_context.h` line 172), 5
/// seconds at the pinned quiche revision 2c4a1246
/// (`quiche/quic/core/quic_constants.h` line 159), and quiche shortens a
/// client's idle timeout by one second (`QuicConnection::SetNetworkTimeouts`,
/// `quic_connection.cc` lines 4983-4984). The `udp-blackhole` capture shows
/// the orphaned QUIC job failing with `ERR_QUIC_HANDSHAKE_FAILED` 4002-4016
/// ms after it started.
///
/// Chromium restarts that timer on every received packet and lets a
/// responsive handshake run for up to 10 seconds
/// (`kMaxTimeForCryptoHandshakeSecs`). Phantom cannot observe handshake
/// packets at this layer, so it bounds the whole attempt instead, including
/// name resolution and proxy setup that Chromium's timer does not cover.
pub(crate) const DEFAULT_ALTERNATIVE_SETUP_LIMIT: Duration = Duration::from_secs(4);

impl AltSvcRace {
    /// Creates racing parameters.
    ///
    /// Chromium computes its origin delay per request from QUIC history and
    /// measured round-trip time, so Phantom takes a fixed caller value; zero
    /// starts both candidates together. An `origin_delay` too large to add to
    /// the runtime clock makes [`ClientBuilder::build`](crate::ClientBuilder::build)
    /// fail with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub const fn new(origin_delay: Duration, broken_backoff: AltSvcBrokenBackoff) -> Self {
        Self {
            origin_delay,
            broken_backoff,
            alternative_setup_limit: DEFAULT_ALTERNATIVE_SETUP_LIMIT,
            max_alternatives: NonZeroUsize::MIN,
        }
    }

    /// Sets how many learned alternatives one race sets up at once, at most
    /// 3.
    ///
    /// The default is 1, the first alternative the field listed that is not
    /// broken, as Chrome 154 races. A larger value is caller policy
    /// that no browser shows on the wire: it starts QUIC setup to up to that
    /// many alternatives together, distinct and not broken, in field order,
    /// and sends the request on whichever finishes setup first, with an
    /// `Alt-Used` field that names it. The origin still waits for
    /// `origin_delay`, and starts early only when every raced alternative has
    /// failed. An alternative that fails while another one wins is marked
    /// broken once the winner's handshake has completed, and one still
    /// connecting then is marked if it fails later.
    ///
    /// Every raced setup needs its own HTTP/3 admission for the origin. With
    /// [`ClientBuilder::max_concurrent_http3_requests_per_origin`](crate::ClientBuilder::max_concurrent_http3_requests_per_origin)
    /// at 1, later alternatives wait for that admission while the first one
    /// connects, and are cancelled when another candidate wins. A value above
    /// 3 makes [`ClientBuilder::build`](crate::ClientBuilder::build) fail with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{num::NonZeroUsize, time::Duration};
    ///
    /// use phantom::{AltSvcBrokenBackoff, AltSvcRace};
    ///
    /// let race = AltSvcRace::new(Duration::from_millis(300), AltSvcBrokenBackoff::CHROMIUM_153);
    /// assert_eq!(race.max_alternatives(), NonZeroUsize::MIN);
    /// let two = NonZeroUsize::new(2).ok_or("two is not zero")?;
    /// assert_eq!(race.with_max_alternatives(two).max_alternatives(), two);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn with_max_alternatives(mut self, max: NonZeroUsize) -> Self {
        self.max_alternatives = max;
        self
    }

    /// Returns how many learned alternatives one race sets up at once.
    #[must_use]
    pub const fn max_alternatives(self) -> NonZeroUsize {
        self.max_alternatives
    }

    /// Sets how long one alternative connection attempt may run, including
    /// name resolution and proxy setup.
    ///
    /// The default is 4 seconds, Chrome 153's limit for an alternative that
    /// never answers. A shorter limit marks an unreachable alternative broken
    /// sooner, and it also fails a slow but working alternative that Chrome
    /// would have used. The limit changes when Phantom gives up on the QUIC
    /// handshake, which the alternative's server can observe. The request's
    /// own connect and total timeouts still apply when shorter. A limit the
    /// runtime clock cannot represent makes
    /// [`ClientBuilder::build`](crate::ClientBuilder::build) fail with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub const fn with_alternative_setup_limit(mut self, limit: Duration) -> Self {
        self.alternative_setup_limit = limit;
        self
    }

    /// Returns how long one alternative connection attempt may run.
    #[must_use]
    pub const fn alternative_setup_limit(self) -> Duration {
        self.alternative_setup_limit
    }

    /// Returns how long origin setup waits after alternative setup starts.
    #[must_use]
    pub const fn origin_delay(self) -> Duration {
        self.origin_delay
    }

    /// Returns how long a failed alternative stays broken.
    #[must_use]
    pub const fn broken_backoff(self) -> AltSvcBrokenBackoff {
        self.broken_backoff
    }
}

/// How long an alternative stays broken after failing a race.
///
/// The first failure marks the alternative broken for `initial`. Each later
/// failure before a successful alternative connection doubles the period, up
/// to `maximum`. A failure reported while the alternative is already broken
/// counts toward the next period without extending the current one. A
/// successful alternative connection clears the history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AltSvcBrokenBackoff {
    initial: Duration,
    maximum: Duration,
}

impl AltSvcBrokenBackoff {
    /// Chromium 153's defaults: 300 seconds, doubling, capped at two days.
    ///
    /// The 300-second first period and its doubling were observed in Chrome
    /// 153.0.8010.48 NetLogs; the two-day cap is from
    /// `net/http/broken_alternative_services.cc` at that version.
    pub const CHROMIUM_153: Self = Self {
        initial: Duration::from_secs(300),
        maximum: Duration::from_secs(2 * 24 * 60 * 60),
    };

    /// Creates a backoff from the first broken period and the cap.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] with kind
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// when `initial` is zero or exceeds `maximum`.
    pub fn new(initial: Duration, maximum: Duration) -> Result<Self, BuildError> {
        if initial.is_zero() || initial > maximum {
            return Err(BuildError::invalid_policy(
                "Alt-Svc broken backoff needs 0 < initial <= maximum",
            ));
        }
        Ok(Self { initial, maximum })
    }

    /// Returns the first broken period.
    #[must_use]
    pub const fn initial(self) -> Duration {
        self.initial
    }

    /// Returns the longest broken period.
    #[must_use]
    pub const fn maximum(self) -> Duration {
        self.maximum
    }

    /// Returns the broken period after `previous_failures` earlier failures.
    #[must_use]
    pub fn period(self, previous_failures: u32) -> Duration {
        2_u32
            .checked_pow(previous_failures)
            .and_then(|factor| self.initial.checked_mul(factor))
            .map_or(self.maximum, |period| period.min(self.maximum))
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use super::{AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, MAX_RACED_ALTERNATIVES};
    use crate::BuildErrorKind;

    fn race() -> AltSvcRace {
        AltSvcRace::new(
            Duration::from_millis(300),
            AltSvcBrokenBackoff::CHROMIUM_153,
        )
    }

    #[test]
    fn a_race_sets_up_one_alternative_by_default() {
        assert_eq!(race().max_alternatives(), NonZeroUsize::MIN);
    }

    #[test]
    fn a_race_accepts_up_to_three_alternatives_and_rejects_four() -> Result<(), &'static str> {
        for count in 1..=MAX_RACED_ALTERNATIVES {
            let max = NonZeroUsize::new(count).ok_or("zero alternatives")?;
            let policy = AltSvcPolicy::race(race().with_max_alternatives(max));
            assert!(policy.validate().is_ok(), "{count}");
        }
        let four = NonZeroUsize::new(MAX_RACED_ALTERNATIVES + 1).ok_or("zero alternatives")?;
        let error = AltSvcPolicy::race(race().with_max_alternatives(four))
            .validate()
            .err()
            .ok_or("four alternatives must be rejected")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
        // The message states the cap that `validate` applies.
        assert!(
            error
                .to_string()
                .contains(&format!("at most {MAX_RACED_ALTERNATIVES} alternatives")),
            "{error}"
        );
        Ok(())
    }
}
