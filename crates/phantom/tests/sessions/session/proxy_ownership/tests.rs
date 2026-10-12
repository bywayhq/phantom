use std::{future::Future, pin::Pin};

use super::super::body_ownership::tests::Exit;
use super::super::body_ownership::tests::peer_fixture::{
    Fixture, completed_target, deadline_target,
};
use super::{Control, TestResult, https_controlled, plaintext_controlled};
use crate::support::tunnel_proxy::finish_with_cleanup;

enum Tunnel {
    Plaintext,
    Https,
}

impl Tunnel {
    fn caller(self, control: Control) -> Pin<Box<dyn Future<Output = TestResult<()>>>> {
        match self {
            Self::Plaintext => Box::pin(plaintext_controlled(Some(control))),
            Self::Https => Box::pin(https_controlled(Some(control))),
        }
    }
}

#[tokio::test]
async fn dropping_plaintext_tunnel_caller_destroys_its_actual_accepted_proxy() -> TestResult<()> {
    pending(Tunnel::Plaintext, Exit::Drop).await
}

#[tokio::test]
async fn plaintext_tunnel_deadline_destroys_its_actual_accepted_proxy() -> TestResult<()> {
    pending(Tunnel::Plaintext, Exit::Deadline).await
}

#[tokio::test]
async fn plaintext_input_error_retains_both_completed_original_peer_causes() -> TestResult<()> {
    completed(Tunnel::Plaintext).await
}

#[tokio::test]
async fn dropping_https_tunnel_caller_destroys_its_actual_accepted_proxy() -> TestResult<()> {
    pending(Tunnel::Https, Exit::Drop).await
}

#[tokio::test]
async fn https_tunnel_deadline_destroys_its_actual_accepted_proxy() -> TestResult<()> {
    pending(Tunnel::Https, Exit::Deadline).await
}

#[tokio::test]
async fn https_input_error_retains_both_completed_original_peer_causes() -> TestResult<()> {
    completed(Tunnel::Https).await
}

async fn pending(tunnel: Tunnel, exit: Exit) -> TestResult<()> {
    let (control, mut fixture) = Fixture::new(None);
    let mut caller = tunnel.caller(control);
    let preparation = fixture.start(&mut caller).await;

    let target = match preparation {
        Err(error) => {
            drop(caller);
            Err(error)
        }
        Ok(()) => match exit {
            Exit::Drop => {
                drop(caller);
                fixture
                    .exited("proxy peer remained live after actual caller drop")
                    .await
            }
            Exit::Deadline => {
                let result = caller.await;

                let destruction = fixture
                    .exited("proxy peer remained live after original deadline")
                    .await;

                deadline_target(result, destruction)
            }
        },
    };

    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}

async fn completed(tunnel: Tunnel) -> TestResult<()> {
    let (control, mut fixture) = Fixture::new(Some("https://["));
    let mut caller = tunnel.caller(control);
    let target = async {
        fixture.start(&mut caller).await?;

        let ids = fixture.foreign_abort()?;
        fixture.finished().await?;

        fixture.resume()?;

        let result = caller.as_mut().await;
        completed_target(result, &ids)
    }
    .await;

    drop(caller);
    let backup = fixture.stop().await;
    finish_with_cleanup(target, backup)
}
