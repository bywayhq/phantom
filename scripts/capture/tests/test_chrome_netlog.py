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

    def test_every_valid_event_cut_keeps_only_preceding_complete_events(self) -> None:
        event = dict(EVENT)
        event["params"] = {
            "escaped": 'quote " slash \\ newline \n snowman ☃ face 🙂',
            "nested": {"array": [True, False, None, -1.25e-100, 1.5e100]},
        }
        record = json.dumps(event)
        for cut in range(len(record)):
            with self.subTest(cut=cut):
                log = NetLog.parse(PREFIX + RECORD + ",\n" + record[:cut])

                self.assertFalse(log.complete)
                self.assertIsNone(log.polled)
                self.assertEqual([event.index for event in log.events], [0])
                self.assertEqual(log.events[0].params, EVENT["params"])

        log = NetLog.parse(PREFIX + RECORD + ",\n" + record)
        self.assertEqual([event.index for event in log.events], [0, 1])
        self.assertEqual(log.events[1].params, event["params"])

    def test_valid_partial_envelope_after_events_preserves_records_without_polled_data(self) -> None:
        suffix = '], "polledData": [{"value": true}]}'
        for cut in range(1, len(suffix)):
            with self.subTest(cut=cut):
                log = NetLog.parse(PREFIX + RECORD + suffix[:cut])

                self.assertFalse(log.complete)
                self.assertIsNone(log.polled)
                self.assertEqual([event.index for event in log.events], [0])
                self.assertEqual(log.events[0].params, EVENT["params"])

        log = NetLog.parse(PREFIX + RECORD + suffix)
        self.assertTrue(log.complete)
        self.assertEqual(log.polled, [{"value": True}])

    def test_complete_multiline_and_same_line_records_keep_their_order(self) -> None:
        second = dict(EVENT, time="18")
        log = NetLog.parse(PREFIX + RECORD + "," + json.dumps(second, indent=2))

        self.assertFalse(log.complete)
        self.assertEqual([event.index for event in log.events], [0, 1])
        self.assertEqual([event.time_ms for event in log.events], [17, 18])

    def test_constants_string_cannot_be_mistaken_for_the_events_array(self) -> None:
        constants = dict(CONSTANTS, description='contains "events": [ in a string')
        prefix = '{"constants": ' + json.dumps(constants) + ', "events": ['
        log = NetLog.parse(prefix + RECORD + ",")

        self.assertEqual(log.constants, constants)
        self.assertEqual([event.index for event in log.events], [0])

    def test_invalid_event_tokens_are_rejected_even_without_closing_the_document(self) -> None:
        for tail in (
            '{"params": {"value": "\\x',
            '{"params": {"value": "\\u00Z',
            '{"params": {"value": "line\n',
            '{"params": {"value": 01',
            '{"params": {"value": 1ee',
            '{"params": {"value": 1e ',
            '{"params": {"value": .1',
            '{"params": {"value": truth',
            '{"params": {"value": true false',
            '{"params": {"value": [}',
            '{"params": {"value": "\\x"}}}',
            "true",
            "tru",
            RECORD + " trailing garbage",
        ):
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                NetLog.parse(PREFIX + RECORD + ",\n" + tail)

    def test_recovery_requires_complete_constants_and_an_established_events_array(self) -> None:
        for text in (
            '{"constants": {',
            '{"constants": ' + json.dumps(CONSTANTS) + ",",
            '{"constants": ' + json.dumps(CONSTANTS) + ', "events":',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                NetLog.parse(text)

        with self.assertRaises(KeyError):
            NetLog.parse('{"events": [')
