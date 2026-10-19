"""Retain capture operation failures and independent cleanup failures."""

import asyncio


class CleanupFailures(Exception):
    """Retain cause snapshots before an interruption is chained to cleanup."""

    def __init__(
        self,
        primary: BaseException | None,
        cleanup: tuple[BaseException, ...],
        message: str,
    ) -> None:
        self.primary = primary
        self.cleanup = cleanup
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        self.interruption_cause: BaseException | None = None
        self.interruption_context: BaseException | None = None
        super().__init__(message)

    def raise_interruption(self) -> None:
        """Re-raise the first cancellation, keyboard interrupt or process exit."""
        interruption = next(
            (
                error
                for error in (self.primary, *self.cleanup)
                if isinstance(
                    error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
                )
            ),
            None,
        )
        if interruption is not None:
            self.interruption_cause = interruption.__cause__
            self.interruption_context = interruption.__context__
            raise interruption from self


class BrowserLaunchFailures(CleanupFailures):
    """Retain the initiating error and independent cleanup failures."""

    def __init__(
        self, primary: BaseException | None, cleanup: tuple[BaseException, ...]
    ) -> None:
        super().__init__(primary, cleanup, "browser launch cleanup failed")


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
    failure.raise_interruption()

    raise failure from primary
