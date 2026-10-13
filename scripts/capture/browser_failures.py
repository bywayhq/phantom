"""Retain browser entry, body and independent cleanup failures."""

import asyncio


class BrowserLaunchFailures(Exception):
    """Retain the initiating error and independent cleanup failures."""

    def __init__(
        self, primary: BaseException | None, cleanup: tuple[BaseException, ...]
    ) -> None:
        self.primary = primary
        self.cleanup = cleanup
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        self.interruption_cause: BaseException | None = None
        self.interruption_context: BaseException | None = None
        super().__init__("browser launch cleanup failed")


def raise_browser_failures(
    primary: BaseException | None, cleanup: tuple[BaseException, ...]
) -> None:
    if not cleanup:
        if primary is not None:
            raise primary
        return

    if primary is None and len(cleanup) == 1:
        raise cleanup[0]

    failure = BrowserLaunchFailures(primary, cleanup)
    interruption = next(
        (
            error
            for error in (primary, *cleanup)
            if isinstance(
                error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
            )
        ),
        None,
    )
    if interruption is not None:
        failure.interruption_cause = interruption.__cause__
        failure.interruption_context = interruption.__context__
        raise interruption from failure

    raise failure from primary
