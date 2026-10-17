use super::*;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn diagnostics(capacity: usize) -> RequestDiagnostics {
    let Some(capacity) = NonZeroUsize::new(capacity) else {
        panic!("test capacity must be positive")
    };
    RequestDiagnostics::new(capacity)
}

#[tokio::test]
async fn snapshots_keep_pending_failure_and_cancelled_work_distinct() -> TestResult {
    let trace = diagnostics(8);
    assert_eq!(trace.snapshot().outcome, RequestTimelineOutcome::NotStarted);
    let mut request = Box::pin(trace.observe(async {
        let _phase = PhaseObservation::begin(RequestTimingPhase::TcpConnect, None);
        std::future::pending::<Result<(), ()>>().await
    }));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(request.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let pending = trace.snapshot();
    assert_eq!(pending.outcome, RequestTimelineOutcome::Pending);
    assert_eq!(pending.events[0].outcome, RequestTimingOutcome::Pending);
    assert!(pending.events[0].finished.is_none());
    drop(request);
    let cancelled = trace.snapshot();
    assert_eq!(cancelled.outcome, RequestTimelineOutcome::Cancelled);
    assert_eq!(
        cancelled.events[0].outcome,
        RequestTimingOutcome::Interrupted
    );

    let failed = diagnostics(8);
    let result: Result<(), ()> = failed
        .observe(PhaseObservation::run(
            RequestTimingPhase::TlsHandshake,
            None,
            async { Err(()) },
        ))
        .await;
    assert!(result.is_err());
    assert_eq!(failed.snapshot().outcome, RequestTimelineOutcome::Failed);
    assert_eq!(
        failed.snapshot().events[0].outcome,
        RequestTimingOutcome::Failed
    );
    Ok(())
}

#[tokio::test]
async fn truncation_preserves_retained_events_and_total_admissions() -> TestResult {
    let trace = diagnostics(1);
    trace
        .observe(async {
            Observation::admit(Some(Version::HTTP_2));
            Observation::admit(Some(Version::HTTP_2));
            PhaseObservation::run(RequestTimingPhase::ResolutionWait, None, async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await
        })
        .await?;
    let snapshot = trace.snapshot();
    assert_eq!(snapshot.events.len(), 1);
    assert_eq!(snapshot.events[0].id, 0);
    assert_eq!(snapshot.events[0].admission, Some(1));
    assert_eq!(snapshot.events[0].outcome, RequestTimingOutcome::Completed);
    assert_eq!(snapshot.admitted_attempts, 2);
    assert_eq!(snapshot.dropped_events, 2);
    Ok(())
}

#[tokio::test]
async fn owned_branch_scopes_retain_late_setup_without_claiming_an_admission() -> TestResult {
    let trace = diagnostics(8);
    let (release, gate) = tokio::sync::oneshot::channel();
    let mut child = None;
    trace
        .observe(async {
            let branch = Observation::current().ok_or("missing observer")?.branch();
            let future = Observation::scope(Some(branch), async {
                let mut phase = PhaseObservation::begin(
                    RequestTimingPhase::QuicHandshake,
                    Some(Version::HTTP_3),
                );
                assert!(gate.await.is_ok());
                phase.finish(RequestTimingOutcome::Completed);
            });
            child = Some(tokio::spawn(future));
            Observation::admit(Some(Version::HTTP_2));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?;
    release.send(()).map_err(|()| "receiver gone")?;
    child.ok_or("missing child")?.await?;
    let snapshot = trace.snapshot();
    assert_eq!(snapshot.outcome, RequestTimelineOutcome::ResponseHead);
    let setup = snapshot
        .events
        .iter()
        .find(|event| event.phase == RequestTimingPhase::QuicHandshake)
        .ok_or("missing QUIC timing")?;
    assert_eq!(setup.admission, None);
    assert_eq!(setup.outcome, RequestTimingOutcome::Completed);
    assert!(setup.finished.ok_or("unfinished setup")? >= setup.started);
    Ok(())
}

#[tokio::test]
async fn concurrent_requests_and_redirect_hops_have_independent_contexts() -> TestResult {
    let first = diagnostics(8);
    let second = diagnostics(8);
    let run = || async {
        for _ in 0..2 {
            Observation::scope(Observation::next_hop(), async {
                Observation::admit(Some(Version::HTTP_11));
                tokio::task::yield_now().await;
            })
            .await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (a, b) = tokio::join!(first.observe(run()), second.observe(run()));
    a?;
    b?;
    for snapshot in [first.snapshot(), second.snapshot()] {
        assert_eq!(snapshot.admitted_attempts, 2);
        assert_eq!(snapshot.events[0].hop, 0);
        assert_eq!(snapshot.events[1].hop, 1);
        assert_eq!(snapshot.events[0].admission, Some(1));
        assert_eq!(snapshot.events[1].admission, Some(2));
    }
    assert!(Observation::current().is_none());
    Ok(())
}

#[tokio::test]
async fn captured_setup_keeps_its_original_admission_after_a_retry() -> TestResult {
    let trace = diagnostics(8);
    trace
        .observe(async {
            Observation::admit(Some(Version::HTTP_2));
            let original = Observation::capture();
            Observation::admit(Some(Version::HTTP_2));
            Observation::scope(original, async {
                PhaseObservation::run(RequestTimingPhase::TlsHandshake, None, async {
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                })
                .await
            })
            .await
        })
        .await?;
    assert_eq!(trace.snapshot().events[2].admission, Some(1));
    Ok(())
}

#[tokio::test]
async fn nested_requests_and_unobserved_scopes_do_not_inherit_a_collector() -> TestResult {
    let outer = diagnostics(8);
    let inner = diagnostics(8);
    outer
        .observe(async {
            Observation::admit(None);
            inner
                .observe(async {
                    Observation::admit(None);
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                })
                .await?;
            Observation::scope(None, async {
                assert!(Observation::current().is_none());
                Observation::admit(None);
            })
            .await;
            Observation::admit(None);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?;
    assert_eq!(outer.snapshot().admitted_attempts, 2);
    assert_eq!(inner.snapshot().admitted_attempts, 1);
    Ok(())
}
