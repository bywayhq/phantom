"""Derive Alt-Svc job-controller decisions from a Chrome NetLog JSON file.

A NetLog written by `--log-net-log` ends with `polledData` only when the
browser exits cleanly; a killed browser leaves a truncated events array, which
is still read line by line. Times are NetLog tick milliseconds.
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from pathlib import Path

CONTROLLER = "HTTP_STREAM_JOB_CONTROLLER"
# Chrome prints this local time without zero padding, as in `15:42:6`.
BROKEN_UNTIL = re.compile(r"\(broken until (\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)\)")


@dataclass(frozen=True)
class Event:
    index: int
    time_ms: int
    type: str
    phase: str
    source_id: int
    source_type: str
    params: dict

    def dependency(self) -> int | None:
        dependency = self.params.get("source_dependency")
        if isinstance(dependency, dict) and "id" in dependency:
            return int(dependency["id"])
        return None


class NetLog:
    def __init__(
        self,
        constants: dict,
        events: list[Event],
        polled: list[dict] | None,
    ) -> None:
        self.constants = constants
        self.events = events
        self.polled = polled
        self.by_source: dict[int, list[Event]] = {}
        for event in events:
            self.by_source.setdefault(event.source_id, []).append(event)

    @property
    def complete(self) -> bool:
        return self.polled is not None

    @classmethod
    def load(cls, path: Path) -> NetLog:
        return cls.parse(path.read_text(encoding="utf-8", errors="replace"))

    @classmethod
    def parse(cls, text: str) -> NetLog:
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None
        if document is not None:
            constants = document["constants"]
            raw_events = document.get("events", [])
            polled = document.get("polledData")
            if isinstance(polled, dict):
                polled = [polled]
        else:
            head, separator, body = text.partition('"events": [')
            if not separator:
                raise ValueError("NetLog has no events array")
            constants = json.loads(head.strip().rstrip(",") + "}")["constants"]
            raw_events = []
            for line in body.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        raw_events.append(json.loads(line.rstrip("]")))
                    except json.JSONDecodeError:
                        continue
            polled = None
        names = {value: name for name, value in constants["logEventTypes"].items()}
        sources = {value: name for name, value in constants["logSourceType"].items()}
        phases = {value: name for name, value in constants["logEventPhase"].items()}
        events = []
        for index, raw in enumerate(raw_events):
            source = raw.get("source", {})
            params = raw.get("params", {})
            events.append(
                Event(
                    index=index,
                    time_ms=int(raw["time"]),
                    type=names.get(raw["type"], str(raw["type"])),
                    phase=phases.get(raw.get("phase", 0), "PHASE_NONE"),
                    source_id=int(source.get("id", -1)),
                    source_type=sources.get(
                        source.get("type"), str(source.get("type"))
                    ),
                    params=params if isinstance(params, dict) else {},
                )
            )
        return cls(constants, events, polled)

    def wall_ms(self, tick_ms: int) -> float:
        """Convert NetLog tick milliseconds to Unix milliseconds."""
        return float(self.constants["timeTickOffset"]) + tick_ms

    def first(self, source_id: int, event_type: str, phase: str | None = None):
        for event in self.by_source.get(source_id, ()):
            if event.type == event_type and (phase is None or event.phase == phase):
                return event
        return None

    def alternative_services(self) -> tuple[str, ...]:
        """Return polled Alt-Svc mappings, which name brokenness expiry."""
        mappings = []
        for context in self.polled or ():
            for entry in context.get("altSvcMappings", ()):
                for alternative in entry.get("alternative_service", ()):
                    mappings.append(f"{entry.get('server')} {alternative}")
        return tuple(mappings)


@dataclass(frozen=True)
class RaceObservation:
    """One non-preconnect job controller for the capture origin."""

    path: str
    start_ms: int
    end_ms: int | None
    alt_svc_broken: bool | None
    jobs: tuple[str, ...]
    main_should_wait: bool | None
    main_job_wait_ms: int | None
    main_resumed_ms: int | None
    main_outcome: str
    alternative_outcome: str
    bound_job: str
    quic_first_packet_ms: int | None
    tcp_connect_ms: int | None

    @property
    def tcp_minus_quic_start_ms(self) -> int | None:
        if self.quic_first_packet_ms is None or self.tcp_connect_ms is None:
            return None
        return self.tcp_connect_ms - self.quic_first_packet_ms

    def render(self) -> str:
        """Render with times relative to the controller's start."""

        def value(item: object) -> str:
            return "none" if item is None else str(item).lower()

        return ",".join(
            (
                f"path:{self.path}",
                f"alt_svc_broken:{value(self.alt_svc_broken)}",
                f"jobs:{'+'.join(self.jobs)}",
                f"main_should_wait:{value(self.main_should_wait)}",
                f"main_job_wait_ms:{value(self.main_job_wait_ms)}",
                f"main_resumed_ms:{value(self.main_resumed_ms)}",
                f"quic_first_packet_ms:{value(self.quic_first_packet_ms)}",
                f"tcp_connect_ms:{value(self.tcp_connect_ms)}",
                f"main:{self.main_outcome}",
                f"alternative:{self.alternative_outcome}",
                f"bound:{self.bound_job}",
                f"controller_ms:{value(None if self.end_ms is None else self.end_ms - self.start_ms)}",
            )
        )


def observe_races(netlog: NetLog, host: str, port: int) -> list[RaceObservation]:
    """Summarize every non-preconnect controller whose URL is the origin."""
    origin = f"https://{host}:{port}/"
    observations = []
    for event in netlog.events:
        if (
            event.type == CONTROLLER
            and event.phase == "PHASE_BEGIN"
            and str(event.params.get("url", "")).startswith(origin)
            and not event.params.get("is_preconnect", False)
        ):
            observations.append(observe_controller(netlog, event, origin))
    return observations


def observe_controller(netlog: NetLog, begin: Event, origin: str) -> RaceObservation:
    controller = begin.source_id
    start = begin.time_ms
    path = str(begin.params["url"])[len(origin) - 1 :].split("?", 1)[0]
    controller_events = netlog.by_source.get(controller, [])
    end = next(
        (
            event.time_ms
            for event in controller_events
            if event.type == CONTROLLER and event.phase == "PHASE_END"
        ),
        None,
    )
    alt_svc = next(
        (
            bool(event.params.get("is_broken"))
            for event in controller_events
            if event.type == "HTTP_STREAM_JOB_CONTROLLER_ALT_SVC_FOUND"
        ),
        None,
    )
    delays = [
        int(event.params.get("delay", 0))
        for event in controller_events
        if event.type == "HTTP_STREAM_JOB_DELAYED"
    ]
    jobs: dict[str, int] = {}
    for event in netlog.events:
        if (
            event.type == "HTTP_STREAM_JOB"
            and event.phase == "PHASE_BEGIN"
            and event.dependency() == controller
        ):
            jobs[str(event.params.get("type"))] = event.source_id
    main = jobs.get("main")
    alternative = jobs.get("alternative")
    bound = "none"
    for kind, job in jobs.items():
        if netlog.first(job, "HTTP_STREAM_JOB_BOUND_TO_REQUEST") is not None:
            bound = kind
    should_wait = None
    resumed = None
    tcp_connect = None
    main_outcome = "absent"
    if main is not None:
        waiting = netlog.first(main, "HTTP_STREAM_JOB_WAITING", "PHASE_BEGIN")
        if waiting is not None:
            should_wait = bool(waiting.params.get("should_wait"))
        resumed_event = netlog.first(main, "HTTP_STREAM_JOB_RESUMED")
        if resumed_event is not None:
            resumed = resumed_event.time_ms - start
        main_outcome, connect_time = main_job_outcome(netlog, main)
        if connect_time is not None:
            tcp_connect = connect_time - start
    quic_packet = None
    alternative_outcome = "absent"
    if alternative is not None:
        alternative_outcome, packet_time = alternative_job_outcome(netlog, alternative)
        if packet_time is not None:
            quic_packet = packet_time - start
    return RaceObservation(
        path=path,
        start_ms=start,
        end_ms=end,
        alt_svc_broken=alt_svc,
        jobs=tuple(sorted(jobs)),
        main_should_wait=should_wait,
        main_job_wait_ms=delays[0] if delays else None,
        main_resumed_ms=resumed,
        main_outcome=main_outcome,
        alternative_outcome=alternative_outcome,
        bound_job=bound,
        quic_first_packet_ms=quic_packet,
        tcp_connect_ms=tcp_connect,
    )


def main_job_outcome(netlog: NetLog, job: int) -> tuple[str, int | None]:
    """Classify the TCP job and find its first TCP connect attempt.

    A cancelled job's connect job is never bound to it; the pool creates that
    connect job synchronously, so it is the first one logged after the job's
    `SOCKET_POOL` begin event.
    """
    events = netlog.by_source.get(job, [])
    types = {event.type for event in events}
    if "HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION" in types:
        outcome = "existing-h2-session"
    elif "SOCKET_POOL_BOUND_TO_CONNECT_JOB" in types:
        outcome = "new-connection"
    elif "SOCKET_POOL_BOUND_TO_SOCKET" in types:
        # An idle socket, such as one a preconnect left in the pool.
        outcome = "idle-socket"
    elif "CANCELLED" in types:
        outcome = "cancelled"
    elif "HTTP_STREAM_JOB_INIT_CONNECTION" not in types:
        outcome = "not-started"
    else:
        outcome = "other"
    pool = netlog.first(job, "SOCKET_POOL", "PHASE_BEGIN")
    if pool is None:
        return outcome, None
    connect_job = None
    for event in netlog.events[pool.index + 1 :]:
        if (
            event.type == "CONNECT_JOB"
            and event.phase == "PHASE_BEGIN"
            and event.source_type
            in {"SSL_CONNECT_JOB", "TRANSPORT_CONNECT_JOB", "TCP_CONNECT_JOB"}
        ):
            connect_job = event.source_id
            break
        if event.time_ms > pool.time_ms:
            break
    if connect_job is None:
        return outcome, None
    for event in netlog.by_source.get(connect_job, []):
        if event.type == "TCP_CONNECT_JOB_CONNECTOR_CONNECT_START":
            socket = event.dependency()
            attempt = (
                netlog.first(socket, "TCP_CONNECT_ATTEMPT", "PHASE_BEGIN")
                if socket is not None
                else None
            )
            if attempt is not None:
                return outcome, attempt.time_ms
            return outcome, event.time_ms
    return outcome, None


def alternative_job_outcome(netlog: NetLog, job: int) -> tuple[str, int | None]:
    """Classify the QUIC job and find its session's first sent packet."""
    events = netlog.by_source.get(job, [])
    types = {event.type for event in events}
    pool_job = next(
        (
            event.dependency()
            for event in events
            if event.type == "BOUND_TO_QUIC_SESSION_POOL_JOB"
        ),
        None,
    )
    session = None
    error = None
    if pool_job is not None:
        for event in netlog.by_source.get(pool_job, []):
            if event.type == "QUIC_SESSION_CREATED":
                session = event.dependency()
            if event.phase == "PHASE_END" and "net_error" in event.params:
                error = int(event.params["net_error"])
    orphaned = "HTTP_STREAM_JOB_ORPHANED" in types
    if "HTTP_STREAM_JOB_BOUND_TO_REQUEST" in types:
        outcome = "bound" if pool_job is not None else "bound-existing-quic-session"
    elif pool_job is None:
        outcome = "existing-quic-session"
    elif error is not None and error != 0:
        outcome = f"failed:{error}"
    elif netlog.first(pool_job, "QUIC_SESSION_POOL_JOB", "PHASE_END") is not None:
        outcome = "connected"
    else:
        outcome = "unfinished"
    if orphaned:
        outcome = f"orphaned-{outcome}"
    packet = None
    if session is not None:
        sent = netlog.first(session, "QUIC_SESSION_PACKET_SENT")
        if sent is not None:
            packet = sent.time_ms
    return outcome, packet


def broken_until_seconds(netlog: NetLog, mark_tick_ms: int) -> list[int]:
    """Return polled brokenness lifetimes in seconds from `mark_tick_ms`.

    Chrome prints the expiry as local wall time with one-second precision, so
    each lifetime is rounded to the nearest second.
    """
    lifetimes = []
    mark_seconds = netlog.wall_ms(mark_tick_ms) / 1000
    for mapping in netlog.alternative_services():
        match = BROKEN_UNTIL.search(mapping)
        if match is None:
            continue
        until = datetime.datetime(*(int(part) for part in match.groups()))
        lifetimes.append(round(until.timestamp() - mark_seconds))
    return lifetimes
