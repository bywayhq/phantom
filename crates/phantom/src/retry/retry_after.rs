//! `Retry-After` field values (RFC 9110, section 10.2.3).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, header::RETRY_AFTER};

const DAY_NAMES: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTH_NAMES: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const SECONDS_PER_DAY: i64 = 86_400;

/// Returns the delay a response's `Retry-After` field requests, measured from `now`.
///
/// Accepts `delta-seconds` and the IMF-fixdate `HTTP-date` form, the only one
/// senders generate (RFC 9110, section 5.6.7). An absent or repeated field, an
/// obsolete RFC 850 or asctime date, and any other malformed value return
/// `None`. A date at or before `now` requests no delay; an overflowing
/// `delta-seconds` saturates.
pub(super) fn requested_delay(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.as_bytes().trim_ascii();
    if value.first().is_some_and(u8::is_ascii_digit) {
        return delta_seconds(value);
    }
    let date = imf_fixdate(value)?;
    Some(date.duration_since(now).unwrap_or(Duration::ZERO))
}

/// `delta-seconds = 1*DIGIT` (RFC 9111, section 1.2.2).
fn delta_seconds(value: &[u8]) -> Option<Duration> {
    let mut seconds = 0_u64;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        seconds = seconds
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'));
    }
    Some(Duration::from_secs(seconds))
}

/// Parses `IMF-fixdate`, for example `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// The day name must agree with the date. Dates before the Unix epoch map to
/// the epoch, which is always in the past for a delay computation.
fn imf_fixdate(value: &[u8]) -> Option<SystemTime> {
    let value: &[u8; 29] = value.try_into().ok()?;
    if &value[3..5] != b", "
        || value[7] != b' '
        || value[11] != b' '
        || value[16] != b' '
        || value[19] != b':'
        || value[22] != b':'
        || &value[25..] != b" GMT"
    {
        return None;
    }
    let day_name = DAY_NAMES
        .iter()
        .position(|name| name.as_slice() == &value[..3])?;
    let day = digits(&value[5..7])?;
    let month = MONTH_NAMES
        .iter()
        .position(|name| name.as_slice() == &value[8..11])?
        + 1;
    let year = digits(&value[12..16])?;
    let hour = digits(&value[17..19])?;
    let minute = digits(&value[20..22])?;
    // RFC 9110 permits a leap second of 60.
    let second = digits(&value[23..25])?;
    let month = i64::try_from(month).ok()?;
    if day == 0 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let weekday = usize::try_from((days + 4).rem_euclid(7)).ok()?;
    if weekday != day_name {
        return None;
    }
    let seconds = days * SECONDS_PER_DAY + hour * 3_600 + minute * 60 + second;
    Some(match u64::try_from(seconds) {
        Ok(seconds) => UNIX_EPOCH.checked_add(Duration::from_secs(seconds))?,
        Err(_) => UNIX_EPOCH,
    })
}

fn digits(value: &[u8]) -> Option<i64> {
    value.iter().try_fold(0_i64, |total, byte| {
        byte.is_ascii_digit()
            .then(|| total * 10 + i64::from(byte - b'0'))
    })
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use http::{HeaderMap, HeaderValue, header::RETRY_AFTER};

    use super::{imf_fixdate, requested_delay};

    /// `Sun, 06 Nov 1994 08:49:37 GMT`, the RFC 9110 example.
    const RFC_EXAMPLE_SECONDS: u64 = 784_111_777;

    fn fields(values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(RETRY_AFTER, HeaderValue::from_static(value));
        }
        headers
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn delta_seconds_request_that_many_seconds() {
        let now = SystemTime::now();
        assert_eq!(
            requested_delay(&fields(&["120"]), now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(requested_delay(&fields(&["0"]), now), Some(Duration::ZERO));
        assert_eq!(
            requested_delay(&fields(&["007"]), now),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn overflowing_delta_seconds_saturate() {
        assert_eq!(
            requested_delay(&fields(&["99999999999999999999999"]), SystemTime::now()),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn malformed_delta_seconds_are_ignored() {
        for value in ["1.5", "10s", "1 2", "0x10"] {
            assert_eq!(
                requested_delay(&fields(&[value]), SystemTime::now()),
                None,
                "{value}"
            );
        }
    }

    #[test]
    fn missing_empty_or_repeated_fields_are_ignored() {
        let now = SystemTime::now();
        assert_eq!(requested_delay(&HeaderMap::new(), now), None);
        assert_eq!(requested_delay(&fields(&[""]), now), None);
        assert_eq!(requested_delay(&fields(&["-1"]), now), None);
        assert_eq!(requested_delay(&fields(&["1", "2"]), now), None);
    }

    #[test]
    fn imf_fixdate_matches_the_rfc_example() {
        assert_eq!(
            imf_fixdate(b"Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(at(RFC_EXAMPLE_SECONDS))
        );
        assert_eq!(imf_fixdate(b"Thu, 01 Jan 1970 00:00:00 GMT"), Some(at(0)));
        assert_eq!(
            imf_fixdate(b"Tue, 29 Feb 2000 23:59:60 GMT"),
            Some(at(951_868_800))
        );
    }

    #[test]
    fn http_date_requests_the_delta_from_now() {
        let headers = fields(&["Sun, 06 Nov 1994 08:49:37 GMT"]);
        assert_eq!(
            requested_delay(&headers, at(RFC_EXAMPLE_SECONDS - 90)),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            requested_delay(&headers, at(RFC_EXAMPLE_SECONDS + 1)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn obsolete_and_malformed_dates_are_ignored() {
        for value in [
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 gmt",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:60:00 GMT",
            "Mon, 29 Feb 1999 00:00:00 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun,  06 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(imf_fixdate(value.as_bytes()), None, "{value}");
        }
    }

    #[test]
    fn dates_before_the_epoch_request_no_delay() {
        assert_eq!(
            imf_fixdate(b"Wed, 31 Dec 1969 23:59:59 GMT"),
            Some(UNIX_EPOCH)
        );
        assert_eq!(
            requested_delay(&fields(&["Wed, 31 Dec 1969 23:59:59 GMT"]), at(10)),
            Some(Duration::ZERO)
        );
    }
}
