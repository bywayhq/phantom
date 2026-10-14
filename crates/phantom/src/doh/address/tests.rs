use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tokio::time::Instant;

use super::{Family, aggregate};
use crate::AddressNegativeKind;

fn positive(addresses: Vec<IpAddr>, expiry: Instant) -> io::Result<Family> {
    Ok(Family::Positive { addresses, expiry })
}
fn negative(kind: AddressNegativeKind, expiry: Option<Instant>) -> io::Result<Family> {
    Ok(Family::Negative { kind, expiry })
}

#[test]
fn family_aggregation_preserves_order_duplicates_and_complete_lifetime() -> io::Result<()> {
    let now = Instant::now();
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let ipv6_expiry = now + Duration::from_secs(8);
    let ipv4_expiry = now + Duration::from_secs(13);
    let answer = aggregate(
        positive(vec![v6, v6], ipv6_expiry),
        positive(vec![v4], ipv4_expiry),
    )?;
    let Family::Positive { addresses, expiry } = answer else {
        return Err(io::Error::other("expected a positive answer"));
    };
    assert_eq!(addresses, [v6, v6, v4]);
    assert_eq!(expiry, ipv6_expiry);
    for reverse in [false, true] {
        let left = positive(vec![v4], ipv4_expiry);
        let right = negative(AddressNegativeKind::NoData, Some(ipv6_expiry));
        let answer = if reverse {
            aggregate(right, left)?
        } else {
            aggregate(left, right)?
        };
        let Family::Positive { expiry, .. } = answer else {
            return Err(io::Error::other("expected NODATA with a positive answer"));
        };
        assert_eq!(expiry, ipv6_expiry);
    }
    Ok(())
}

#[test]
fn incomplete_lifetime_or_failed_family_cannot_cache_a_positive_subset() -> io::Result<()> {
    let now = Instant::now();
    let expiry = now + Duration::from_secs(20);
    for partial in [
        negative(AddressNegativeKind::NoData, None),
        Err(io::Error::new(io::ErrorKind::TimedOut, "family failed")),
    ] {
        let answer = aggregate(
            positive(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], expiry),
            partial,
        )?;
        let Family::Positive { expiry, .. } = answer else {
            return Err(io::Error::other("expected a usable positive subset"));
        };
        assert!(expiry <= Instant::now());
    }
    let error = aggregate(
        negative(AddressNegativeKind::NoData, Some(expiry)),
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "endpoint failed",
        )),
    )
    .err()
    .map(|error| error.kind());
    assert_eq!(error, Some(io::ErrorKind::PermissionDenied));
    Ok(())
}

#[test]
fn authoritative_negative_and_name_existence_disagreement_remain_distinct() -> io::Result<()> {
    let now = Instant::now();
    let early = now + Duration::from_secs(3);
    let late = now + Duration::from_secs(7);
    for kind in [AddressNegativeKind::NxDomain, AddressNegativeKind::NoData] {
        let answer = aggregate(negative(kind, Some(early)), negative(kind, Some(late)))?;
        let Family::Negative {
            kind: actual,
            expiry,
        } = answer
        else {
            return Err(io::Error::other("expected an authoritative negative"));
        };
        assert_eq!(actual, kind);
        assert_eq!(expiry, Some(early));
        let answer = aggregate(negative(kind, Some(early)), negative(kind, None))?;
        assert!(matches!(answer, Family::Negative { expiry: None, .. }));
    }
    for other in [
        negative(AddressNegativeKind::NoData, Some(late)),
        positive(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], late),
    ] {
        assert_eq!(
            aggregate(negative(AddressNegativeKind::NxDomain, Some(early)), other)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    Ok(())
}
