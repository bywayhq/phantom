//! Native address TTL selection without retaining foreign records.

use std::time::{Duration, Instant};

/// An unavailable TTL keeps the profile fallback; a known invalid deadline does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemTtl {
    Unavailable,
    Deadline(Instant),
    Uncacheable,
}

impl SystemTtl {
    pub(crate) fn earliest(self, other: Self) -> Self {
        match (self, other) {
            (Self::Uncacheable, _) | (_, Self::Uncacheable) => Self::Uncacheable,
            (Self::Unavailable, ttl) | (ttl, Self::Unavailable) => ttl,
            (Self::Deadline(a), Self::Deadline(b)) => Self::Deadline(a.min(b)),
        }
    }
}

/// Selects only answer records of the requested type, as Firefox does.
pub(crate) struct QueryTtl {
    record_type: u16,
    started_at: Instant,
    minimum: u32,
}

impl QueryTtl {
    pub(crate) fn new(record_type: u16, started_at: Instant) -> Self {
        Self {
            record_type,
            started_at,
            minimum: u32::MAX,
        }
    }

    pub(crate) fn observe(&mut self, record_type: u16, section: u32, ttl: u32) {
        if record_type == self.record_type && section == 1 {
            self.minimum = self.minimum.min(ttl);
        }
    }

    pub(crate) fn finish(self) -> SystemTtl {
        // Firefox uses UINT32_MAX as the no-record sentinel, including when
        // records themselves carry that value (GetAddrInfo.cpp:163-177).
        if self.minimum == u32::MAX {
            return SystemTtl::Unavailable;
        }

        self.started_at
            .checked_add(Duration::from_secs(u64::from(self.minimum)))
            .map_or(SystemTtl::Uncacheable, SystemTtl::Deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, Instant, QueryTtl, SystemTtl};

    #[test]
    fn only_answer_records_of_the_requested_type_contribute() {
        for query in [1, 28] {
            let start = Instant::now();
            let mut ttl = QueryTtl::new(query, start);
            for section in [0, 2, 3] {
                ttl.observe(query, section, 0);
            }
            for kind in [1, 5, 28, 65] {
                if kind != query {
                    ttl.observe(kind, 1, 0);
                }
            }
            ttl.observe(query, 1, 45);
            ttl.observe(query, 1, 90);
            ttl.observe(query, 1, 30);

            assert_eq!(
                ttl.finish(),
                SystemTtl::Deadline(start + Duration::from_secs(30))
            );
        }
    }

    #[test]
    fn missing_and_sentinel_records_preserve_fallback_but_zero_does_not() {
        let start = Instant::now();
        assert_eq!(QueryTtl::new(1, start).finish(), SystemTtl::Unavailable);
        let mut sentinel = QueryTtl::new(1, start);
        sentinel.observe(1, 1, u32::MAX);
        assert_eq!(sentinel.finish(), SystemTtl::Unavailable);

        let mut zero = QueryTtl::new(1, start);
        zero.observe(1, 1, 0);
        zero.observe(1, 1, u32::MAX);
        assert_eq!(zero.finish(), SystemTtl::Deadline(start));
    }

    #[test]
    fn family_deadlines_keep_their_separate_query_anchors() {
        let start = Instant::now();
        let mut a = QueryTtl::new(1, start);
        a.observe(1, 1, 30);
        let mut aaaa = QueryTtl::new(28, start + Duration::from_secs(10));
        aaaa.observe(28, 1, 25);

        let first = a.finish();
        let second = aaaa.finish();
        let expected = SystemTtl::Deadline(start + Duration::from_secs(30));
        assert_eq!(first.earliest(second), expected);
        assert_eq!(second.earliest(first), expected);
        assert_eq!(SystemTtl::Unavailable.earliest(first), first);
        assert_eq!(first.earliest(SystemTtl::Unavailable), first);
        assert_eq!(
            first.earliest(SystemTtl::Uncacheable),
            SystemTtl::Uncacheable
        );
        assert_eq!(
            SystemTtl::Uncacheable.earliest(first),
            SystemTtl::Uncacheable
        );
    }
}
