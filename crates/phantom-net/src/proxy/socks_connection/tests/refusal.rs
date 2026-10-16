//! A real physical refusal gates a successful complete sibling, without sleeps.
use super::*;
use std::{fmt, sync::atomic::AtomicBool};
use tokio::sync::Notify;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};
#[derive(Clone, Default)]
struct Refusal {
    seen: Arc<AtomicBool>,
    wake: Arc<Notify>,
}
struct RefusalField(bool);
impl Visit for RefusalField {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "error_kind" && format!("{value:?}") == "ConnectionRefused" {
            self.0 = true;
        }
    }
}
impl Subscriber for Refusal {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "phantom_net::proxy::socks_connection" {
            return;
        }
        let mut fields = RefusalField(false);
        event.record(&mut fields);
        if fields.0 {
            self.seen.store(true, Ordering::Release);
            self.wake.notify_one();
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}
impl Refusal {
    async fn wait(&self) {
        loop {
            let next = self.wake.notified();
            if self.seen.load(Ordering::Acquire) {
                return;
            }
            next.await;
        }
    }
}
#[tokio::test]
async fn an_actual_physical_refusal_leaves_an_already_started_complete_sibling_alive() -> TestResult
{
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |host| {
            assert_eq!(host, "proxy.test");
            let first = count.fetch_add(1, Ordering::Relaxed) == 0;
            async move {
                Ok(vec![if first {
                    Ipv4Addr::new(127, 0, 0, 2).into()
                } else {
                    Ipv4Addr::LOCALHOST.into()
                }])
            }
        }));
        let family = AddressFamilyMemory::default();
        let observed = Refusal::default();
        crate::tracing_test::OutcomeSubscriber::install_dynamic_callsite_fallback();
        let dispatch = Dispatch::new(observed.clone());
        tracing::callsite::rebuild_interest_cache();
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: "proxy.test",
                    port,
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: "127.0.0.1",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let (winner, slower) = connect_retaining(
                Dialer {
                    resolver: Some(&resolver),
                    ..Dialer::default()
                },
                route,
                &family,
                backup(),
            )
            .await
            .map_err(|e| e.into_leg())?;
            assert!(observed.seen.load(Ordering::Acquire));
            assert!(
                slower.is_none(),
                "the actually refused primary was retained"
            );
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            drop(winner);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .with_subscriber(dispatch);
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let request = peer::five(&mut stream, None).await?;
            assert_eq!(request.host, Host::Ip(Ipv4Addr::LOCALHOST.into()));
            // The real primary socket must fail before this sibling may win.
            timeout(WAIT, observed.wait()).await?;
            peer::reply(&mut stream, 0).await?;
            peer::closed(&mut stream).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        Ok(())
    })
    .await
}
