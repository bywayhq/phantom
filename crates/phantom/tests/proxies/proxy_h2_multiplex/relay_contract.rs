use crate::proxy_h2::relay_contract::{Failure, RelayOwner, actual_relay};

use super::TestResult;

#[tokio::test]
async fn an_actual_multiplex_relay_keeps_a_postexchange_write_failure() -> TestResult<()> {
    actual_relay(RelayOwner::Multiplex, Failure::DownstreamWrite).await
}

#[tokio::test]
async fn an_actual_multiplex_relay_keeps_a_postexchange_read_failure() -> TestResult<()> {
    actual_relay(RelayOwner::Multiplex, Failure::UpstreamRead).await
}

#[tokio::test]
async fn an_actual_multiplex_relay_keeps_an_internal_error_body_reset() -> TestResult<()> {
    actual_relay(RelayOwner::Multiplex, Failure::BodyReset).await
}

#[tokio::test]
async fn an_actual_multiplex_relay_keeps_its_rejected_final_send_after_a_reset() -> TestResult<()> {
    actual_relay(RelayOwner::Multiplex, Failure::ResponseReset).await
}

#[tokio::test]
async fn an_actual_multiplex_relay_finishes_after_traffic_and_end_stream() -> TestResult<()> {
    actual_relay(RelayOwner::Multiplex, Failure::HealthyEof).await
}
