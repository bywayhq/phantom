use std::{future::Future, ops::Range, time::Duration};

use tokio::time::{Instant, timeout, timeout_at};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{TEST_TIMEOUT, TestResult};

#[derive(Default)]
pub(super) struct Requests {
    tasks: Vec<ConnectionPeer<TestResult>>,
    primary: Option<TestResult>,
    failures: Vec<Box<dyn std::error::Error + Send + Sync>>,
}

impl Requests {
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn spawn(&mut self, future: impl Future<Output = TestResult> + Send + 'static) {
        self.tasks.push(ConnectionPeer::spawn(future));
    }

    pub(super) fn peer(&mut self, index: usize) -> TestResult<&mut ConnectionPeer<TestResult>> {
        self.tasks
            .get_mut(index)
            .ok_or_else(|| "request worker missing".into())
    }

    pub(super) fn any_finished(&self, indices: Range<usize>) -> TestResult<bool> {
        let tasks = self
            .tasks
            .get(indices)
            .ok_or("request worker range missing")?;
        Ok(tasks.iter().any(ConnectionPeer::is_finished))
    }

    pub(super) async fn join(&mut self, indices: Range<usize>) -> TestResult {
        for index in indices {
            timeout(TEST_TIMEOUT, self.peer(index)?.join()).await???;
        }
        Ok(())
    }

    pub(super) async fn finish(&mut self, primary: TestResult) -> TestResult {
        self.primary = Some(match self.primary.take() {
            Some(previous) => finish_with_cleanup(previous, primary),
            None => primary,
        });
        for task in &self.tasks {
            if !task.is_finished() {
                task.abort();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        for task in &mut self.tasks {
            let result = timeout_at(deadline, task.shutdown()).await;
            let result = match result {
                Ok(result) => result,
                Err(elapsed) => Err(FixtureDeadline::new(
                    "HTTP/3 request cleanup exceeded its deadline",
                    elapsed,
                )
                .into()),
            };
            if let Err(error) = result {
                self.failures.push(error);
            }
        }
        let mut result = self
            .primary
            .take()
            .ok_or("request cleanup lost its caller outcome")?;
        for error in std::mem::take(&mut self.failures) {
            result = finish_with_cleanup(result, Err(error));
        }
        result
    }
}
