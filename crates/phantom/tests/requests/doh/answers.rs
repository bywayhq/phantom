use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use phantom::{AddressNegative, AddressNegativeKind, dns::DohAddressFamilies};
use tokio::time::sleep;

use super::{
    failures::error_kind,
    peer::{
        application::{Fixture, drive, equal},
        scripted::Reply,
    },
};
use crate::support::tls::TestResult;

const LOOKUP: Duration = Duration::from_secs(8);
const IPV4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const IPV6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

#[tokio::test]
async fn http_age_bounds_positive_cache_without_applying_the_record_floor() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        let reply = |q: &super::peer::wire::Question| Reply::dns(q.addresses(&[IPV4], 5)?).age(4);
        drive(&mut fixture.peer, &fixture.application, 1, reply).await??;
        drive(&mut fixture.peer, &fixture.application, 0, reply).await??;
        sleep(Duration::from_millis(1_100)).await;
        drive(&mut fixture.peer, &fixture.application, 1, reply).await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn fractional_query_time_survives_cache_publication() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            let mut reply = Reply::dns(q.addresses(&[IPV4], 5)?);
            reply.delay = Duration::from_millis(1_200);
            Ok(reply)
        })
        .await??;
        sleep(Duration::from_millis(3_300)).await;
        drive(&mut fixture.peer, &fixture.application, 0, |_| {
            Err("fractional lifetime was rounded down".into())
        })
        .await??;
        sleep(Duration::from_millis(1_000)).await;
        drive(&mut fixture.peer, &fixture.application, 1, |q| {
            Ok(Reply::dns(q.addresses(&[IPV4], 5)?))
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn terminal_http_age_does_not_age_an_earlier_cname_again() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        drive(&mut fixture.peer, &fixture.application, 2, |q| {
            match q.name.as_str() {
                "application.test" => Reply::dns(q.cname("target.test", 30)?).age(0),
                "target.test" => Reply::dns(q.addresses(&[IPV4], 100)?).age(90),
                _ => Err("unexpected CNAME followup identity".into()),
            }
        })
        .await??;
        drive(&mut fixture.peer, &fixture.application, 0, |_| {
            Err("terminal Age expired earlier CNAME metadata".into())
        })
        .await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn an_earlier_cname_can_expire_while_the_terminal_response_is_in_flight() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        for _ in 0..2 {
            drive(&mut fixture.peer, &fixture.application, 2, |q| {
                if q.name == "application.test" {
                    return Ok(Reply::dns(q.cname("target.test", 1)?));
                }
                equal(q.name.as_str(), "target.test")?;
                let mut reply = Reply::dns(q.addresses(&[IPV4], 100)?);
                reply.delay = Duration::from_millis(1_100);
                Ok(reply)
            })
            .await??;
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn current_message_age_applies_to_cname_and_terminal_records() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        let reply = |q: &super::peer::wire::Question| {
            Reply::dns(q.cname_addresses("target.test", 2, 100)?).age(1)
        };
        drive(&mut fixture.peer, &fixture.application, 1, reply).await??;
        drive(&mut fixture.peer, &fixture.application, 0, reply).await??;
        sleep(Duration::from_millis(1_100)).await;
        drive(&mut fixture.peer, &fixture.application, 1, reply).await??;
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn authoritative_negative_uses_soa_minimum_and_http_age() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        let reply =
            |q: &super::peer::wire::Question| Reply::dns(q.negative(true, Some((60, 2)))?).age(1);
        for count in [1, 0] {
            let error = drive(&mut fixture.peer, &fixture.application, count, reply)
                .await?
                .err()
                .ok_or("NXDOMAIN succeeded")?;
            negative(error.as_ref(), AddressNegativeKind::NxDomain)?;
        }
        sleep(Duration::from_millis(1_100)).await;
        let error = drive(&mut fixture.peer, &fixture.application, 1, reply)
            .await?
            .err()
            .ok_or("NXDOMAIN succeeded")?;
        negative(error.as_ref(), AddressNegativeKind::NxDomain)
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn no_soa_and_expired_negative_lifetimes_do_not_enter_the_cache() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        for soa in [None, Some((0, 60)), Some((60, 0))] {
            for _ in 0..2 {
                let error = drive(&mut fixture.peer, &fixture.application, 1, |q| {
                    Ok(Reply::dns(q.negative(false, soa)?))
                })
                .await?
                .err()
                .ok_or("NODATA succeeded")?;
                negative(error.as_ref(), AddressNegativeKind::NoData)?;
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn zero_ttl_and_age_expired_duplicate_addresses_remain_usable_without_reuse() -> TestResult<()>
{
    let mut fixture = Fixture::start(DohAddressFamilies::Ipv4Only, LOOKUP, true, false).await?;
    let primary = async {
        for (ttl, age) in [(0, 0), (1, 1), (60, u64::MAX)] {
            for _ in 0..2 {
                drive(&mut fixture.peer, &fixture.application, 1, |q| {
                    Reply::dns(q.addresses(&[IPV4, IPV4], ttl)?).age(age)
                })
                .await??;
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn dual_family_transport_failure_and_missing_soa_keep_positive_subsets_uncached()
-> TestResult<()> {
    let mut fixture =
        Fixture::start(DohAddressFamilies::DualIpv6First, LOOKUP, true, false).await?;
    let primary = async {
        for failed in [true, false] {
            for _ in 0..2 {
                drive(&mut fixture.peer, &fixture.application, 2, |q| {
                    match q.kind {
                        1 => Ok(Reply::dns(q.addresses(&[IPV4], 60)?)),
                        28 => {
                            if failed {
                                Ok(Reply::dns(q.server_failure()))
                            } else {
                                Ok(Reply::dns(q.negative(false, None)?))
                            }
                        }
                        _ => Err("unexpected dual question type".into()),
                    }
                })
                .await??;
            }
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn dual_family_name_existence_conflict_is_an_uncached_error() -> TestResult<()> {
    let mut fixture =
        Fixture::start(DohAddressFamilies::DualIpv6First, LOOKUP, true, false).await?;
    let primary = async {
        for _ in 0..2 {
            let error = drive(&mut fixture.peer, &fixture.application, 2, |q| {
                match q.kind {
                    1 => Ok(Reply::dns(q.addresses(&[IPV4], 60)?)),
                    28 => Ok(Reply::dns(q.negative(true, Some((60, 60)))?)),
                    _ => Err("unexpected dual question type".into()),
                }
            })
            .await?
            .err()
            .ok_or("contradictory NXDOMAIN succeeded")?;
            equal(
                error_kind(error.as_ref()),
                Some(std::io::ErrorKind::InvalidData),
            )?;
        }
        Ok(())
    }
    .await;
    fixture.finish(primary).await
}

#[tokio::test]
async fn dual_family_ipv6_result_precedes_ipv4_at_the_application_peer() -> TestResult<()> {
    let mut fixture = Fixture::start(DohAddressFamilies::DualIpv6First, LOOKUP, true, true).await?;
    let primary = async {
        let result = drive(&mut fixture.peer, &fixture.application, 2, |q| {
            match q.kind {
                1 => Ok(Reply::dns(q.addresses(&[IPV4], 60)?)),
                28 => Ok(Reply::dns(q.addresses(&[IPV6, IPV6], 60)?)),
                _ => Err("unexpected dual question type".into()),
            }
        })
        .await??;
        equal(result.as_ref(), b"ipv6".as_slice())
    }
    .await;
    fixture.finish(primary).await
}

fn negative(
    mut error: &(dyn std::error::Error + 'static),
    kind: AddressNegativeKind,
) -> TestResult<()> {
    loop {
        if let Some(negative) = error.downcast_ref::<AddressNegative>() {
            return equal(negative.kind(), kind);
        }
        error = super::failures::next_cause(error)
            .ok_or("missing typed authoritative negative cause")?;
    }
}
