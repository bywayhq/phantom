"""Check the public-client result contract before computing measurements."""

from workload_config import effective_config, validate_cancellation


def unsigned(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def validate_result(raw, config):
    if not isinstance(raw, dict) or (
        not unsigned(raw.get("elapsed_ns"))
        or raw["elapsed_ns"] == 0
        or type(raw.get("heap_instrumented")) is not bool
        or not unsigned(raw.get("observer_storage_bytes"))
    ):
        raise ValueError("invalid client elapsed time or instrumentation fields")
    unavailable = raw.get("unavailable_timings", {})
    if not isinstance(unavailable, dict) or any(
        key != "head_ns"
        or not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > 512
        for key, reason in unavailable.items()
    ):
        raise ValueError("unavailable head timing needs an explicit short reason")
    expected = effective_config(config)
    validate_cancellation(expected)
    effective = raw.get("config")
    if (
        not isinstance(effective, dict)
        or set(effective) != set(expected)
        or any(
            key not in effective
            or type(effective[key]) is not type(value)
            or effective[key] != value
            for key, value in expected.items()
        )
    ):
        raise ValueError("client result configuration differs from requested work")
    samples = raw.get("samples")
    requests = config.get("requests", 2000)
    if not isinstance(samples, list) or len(samples) != requests:
        raise ValueError("wrong number of measured operations")
    ids = set()
    for sample in samples:
        if not isinstance(sample, dict) or any(
            not unsigned(sample.get(field))
            for field in (
                "id",
                "scheduled_ns",
                "started_ns",
                "application_wait_ns",
                "build_ns",
                "complete_ns",
                "bytes",
            )
        ):
            raise ValueError(
                "client sample needs unsigned integer counters and timings"
            )
        if sample["id"] >= requests or sample["id"] in ids:
            raise ValueError("client sample IDs must cover each operation once")
        ids.add(sample["id"])
        if "error" not in sample or (
            sample["error"] is not None and not isinstance(sample["error"], str)
        ):
            raise ValueError("client sample error must be null or a string")
        head = sample.get("head_ns")
        if "head_ns" not in sample:
            raise ValueError("client sample must declare head timing")
        if head is None:
            if "head_ns" not in unavailable and sample["error"] is None:
                raise ValueError("unavailable head timing needs an explicit reason")
        elif not unsigned(head) or "head_ns" in unavailable:
            raise ValueError("head timing must agree with declared availability")
        first = sample.get("first_byte_ns")
        if "first_byte_ns" not in sample or (first is not None and not unsigned(first)):
            raise ValueError(
                "first body byte timing must be null or an unsigned integer"
            )
        if (
            sample["application_wait_ns"]
            != max(0, sample["started_ns"] - sample["scheduled_ns"])
            or sample["complete_ns"] < max(sample["build_ns"], head or 0)
            or sample["started_ns"] + sample["complete_ns"] > raw["elapsed_ns"]
            or (first is not None and not (head or 0) <= first <= sample["complete_ns"])
        ):
            raise ValueError("client sample timing boundaries are inconsistent")
        cancelled = sample.get("cancelled", False)
        should_cancel = bool(expected["cancel_after_bytes"] and sample["id"] % 2 == 0)
        if type(cancelled) is not bool or (cancelled and sample["error"] is not None):
            raise ValueError("cancellation must be a distinct outcome")
        if sample["error"] is None and cancelled != should_cancel:
            raise ValueError("wrong cancellation selection")
        if (
            cancelled
            and not expected["cancel_after_bytes"]
            <= sample["bytes"]
            < expected["bytes"]
        ):
            raise ValueError(
                "cancelled stream must stop after its prefix and before completion"
            )
        expected_bytes = (
            0 if config.get("protocol") == "construct" else config.get("bytes", 1024)
        )
        if (
            sample["error"] is None
            and not cancelled
            and sample["bytes"] != expected_bytes
        ):
            raise ValueError(
                "successful client sample has the wrong response byte count"
            )
        if config.get("consume", "stream") == "collect" and first is not None:
            raise ValueError(
                "collected bodies cannot report a first data-frame timestamp"
            )
        if (
            config.get("consume", "stream") == "stream"
            and config.get("protocol") != "construct"
            and sample["error"] is None
            and sample["bytes"] > 0
            and first is None
        ):
            raise ValueError(
                "successful nonempty streams need a first data-frame timestamp"
            )
