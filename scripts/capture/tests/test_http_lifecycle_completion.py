import unittest
from dataclasses import replace

from scripts.capture.http_lifecycle import ConnectionRecord, RequestRecord, Run


class CompletionTests(unittest.IsolatedAsyncioTestCase):
    def run_with_done(self, scenario: str = "revalidate") -> Run:
        run = Run(scenario, "token", 100)
        run.connections.extend(
            [ConnectionRecord(0, "main", 0), ConnectionRecord(1, "main", 0)]
        )
        run.select(0, "/start?run=token")
        run.requests.append(RequestRecord(1, 1, 0, "GET", "/done", [], {}, status=200))
        self.addCleanup(lambda: run.completion.cancel() if run.completion else None)
        return run

    async def test_revalidation_can_complete_on_another_owned_main_connection(
        self,
    ) -> None:
        run = self.run_with_done()

        run.finish("/done?run=token&result=ok", 1, request=run.requests[0])

        self.assertEqual(run.page_result, "ok")
        self.assertIsNotNone(run.completion)
        self.assertEqual(run.page_connection, 0)

    async def test_selected_connection_keeps_existing_completion_behavior(self) -> None:
        for scenario in ("revalidate", "idle-ping", "ping-unanswered"):
            with self.subTest(scenario=scenario):
                run = self.run_with_done(scenario)
                run.requests.append(replace(run.requests[0], connection=0))

                run.finish("/done?run=token&result=ok", 0, request=run.requests[-1])

                self.assertEqual(run.page_result, "ok")
                self.assertIsNotNone(run.completion)
                self.assertEqual(run.page_connection, 0)

    async def test_ping_scenarios_reject_completion_on_another_connection(self) -> None:
        for scenario in ("idle-ping", "ping-unanswered"):
            with self.subTest(scenario=scenario):
                run = self.run_with_done(scenario)

                run.finish("/done?run=token&result=ok", 1, request=run.requests[0])

                self.assertIsNone(run.page_result)
                self.assertIsNone(run.completion)
                self.assertEqual(run.page_connection, 0)

    async def test_revalidation_requires_owned_main_connection_and_completed_get(
        self,
    ) -> None:
        done = RequestRecord(1, 1, 0, "GET", "/done", [], {}, status=200)
        cases = (
            ("unknown connection", {"connections": [ConnectionRecord(0, "main", 0)]}),
            (
                "secondary listener",
                {
                    "connections": [
                        ConnectionRecord(0, "main", 0),
                        ConnectionRecord(1, "h1", 0),
                    ]
                },
            ),
            ("no selected page", {"page_connection": None}),
            ("no current request", {"requests": []}),
            (
                "request on another connection",
                {"requests": [replace(done, connection=0)]},
            ),
            ("non-GET request", {"requests": [replace(done, method="POST")]}),
            ("different request path", {"requests": [replace(done, path="/etag")]}),
            ("pending response", {"requests": [replace(done, status=None)]}),
            ("unsuccessful response", {"requests": [replace(done, status=500)]}),
            ("stopping", {"stopping": True}),
        )
        for name, changes in cases:
            with self.subTest(case=name):
                run = self.run_with_done()
                for field, value in changes.items():
                    setattr(run, field, value)

                request = run.requests[0] if run.requests else None
                run.finish("/done?run=token&result=ok", 1, request=request)

                self.assertIsNone(run.page_result)
                self.assertIsNone(run.completion)

    async def test_cross_connection_completion_still_requires_the_exact_token(
        self,
    ) -> None:
        for target in (
            "/done?run=other",
            "/done?run=token&run=token",
            "/done?run=token&run=",
            "/done?run=to\nken",
            "/done?run=token#fragment",
            "//local/done?run=token",
        ):
            with self.subTest(target=target):
                run = self.run_with_done()

                run.finish(target, 1, request=run.requests[0])

                self.assertIsNone(run.page_result)
                self.assertIsNone(run.completion)

    async def test_later_completion_cannot_replace_the_first_result_or_timer(
        self,
    ) -> None:
        run = self.run_with_done()
        run.requests.append(replace(run.requests[0], connection=0))
        run.finish("/done?run=token&result=first", 0, request=run.requests[-1])
        completion = run.completion
        self.assertIsNotNone(completion)

        run.finish("/done?run=token&result=second", 1, request=run.requests[0])

        self.assertEqual(run.page_result, "first")
        self.assertIs(run.completion, completion)
        self.assertEqual(run.page_connection, 0)

    async def test_a_prior_get_cannot_qualify_a_later_post_for_completion(self) -> None:
        run = self.run_with_done()
        previous = run.requests[0]
        run.finish("/done?run=other&result=old", 1, request=previous)
        self.assertIsNone(run.completion)
        current = replace(previous, method="POST")
        run.requests.append(current)

        run.finish("/done?run=token&result=ok", 1, request=current)

        self.assertIsNone(run.page_result)
        self.assertIsNone(run.completion)
        self.assertEqual(run.page_connection, 0)


if __name__ == "__main__":
    unittest.main()
