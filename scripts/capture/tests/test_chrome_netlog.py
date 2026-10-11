import json
import unittest

from scripts.capture.chrome_netlog import NetLog


CONSTANTS = {
    "logEventTypes": {"HTTP_STREAM_JOB_CONTROLLER": 1},
    "logSourceType": {"HTTP_STREAM_JOB_CONTROLLER": 1},
    "logEventPhase": {"PHASE_BEGIN": 1},
}
EVENT = {
    "time": "17",
    "type": 1,
    "phase": 1,
    "source": {"id": 2, "type": 1},
    "params": {"url": "https://server.phantom.test:443/r/1"},
}
PREFIX = '{"constants": ' + json.dumps(CONSTANTS) + ',\n"events": [\n'
RECORD = json.dumps(EVENT)


class ChromeNetLogRecordTests(unittest.TestCase):
    def test_complete_log_keeps_original_event_and_polled_data(self) -> None:
        log = NetLog.parse(
            json.dumps({"constants": CONSTANTS, "events": [EVENT], "polledData": []})
        )

        self.assertTrue(log.complete)
        self.assertEqual(log.polled, [])
        self.assertEqual(len(log.events), 1)
        self.assertEqual(log.events[0].time_ms, 17)
        self.assertEqual(log.events[0].source_id, 2)
        self.assertEqual(log.events[0].params, EVENT["params"])

    def test_truncated_array_keeps_every_complete_record(self) -> None:
        log = NetLog.parse(PREFIX + RECORD + ",\n" + RECORD + ",\n")

        self.assertFalse(log.complete)
        self.assertEqual([event.index for event in log.events], [0, 1])
        self.assertEqual([event.time_ms for event in log.events], [17, 17])

    def test_incomplete_final_event_keeps_preceding_complete_records(self) -> None:
        log = NetLog.parse(PREFIX + RECORD + ',\n{"time": "18", "params": {')

        self.assertFalse(log.complete)
        self.assertEqual(len(log.events), 1)
        self.assertEqual(log.events[0].time_ms, 17)

    def test_malformed_middle_event_is_rejected_before_later_event(self) -> None:
        with self.assertRaises(ValueError):
            NetLog.parse(PREFIX + '{"time": invalid},\n' + RECORD + ",\n")

    def test_closed_malformed_document_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            NetLog.parse(
                PREFIX + '{"time": invalid},\n' + RECORD + '\n],"polledData": []}'
            )

    def test_unrelated_middle_line_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            NetLog.parse(PREFIX + "not an event\n" + RECORD + ",\n")

    def test_complete_malformed_final_event_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            NetLog.parse(PREFIX + RECORD + ',\n{"time": invalid},\n')
