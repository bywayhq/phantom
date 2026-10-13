"""Launch test peers retain native failures and retire before backups."""

import asyncio
import contextlib
import inspect
import shutil
import socket
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import browser_launch
from scripts.capture.tests import test_browser_launch as launch_tests


class LaunchPeerCompletionTests(unittest.TestCase):
    def run_case(self, method, body):
        case = launch_tests.EnterBrowserTests(method)
        try:
            case.setUp()
            body(case)
        finally:
            self.assertTrue(case.doCleanups(), "launch control cleanup failed")

    def test_failed_first_lock_releases_and_collects_the_waiting_thread(self):
        case = launch_tests.LaunchTurnTests(
            "test_launches_take_turns_when_a_runner_sets_the_lock_directory"
        )
        original_turn = browser_launch.launch_turn
        original_thread = threading.Thread
        original_event = threading.Event
        events = []
        workers = []
        directories = []
        cause = OSError("original first lock failure")

        def event(*args, **kwargs):
            result = original_event(*args, **kwargs)
            events.append(result)
            return result

        def thread(*args, **kwargs):
            result = original_thread(*args, **kwargs)
            workers.append(result)
            return result

        @contextlib.contextmanager
        def turn(name):
            if threading.current_thread() is threading.main_thread():
                directories.append(
                    Path(
                        browser_launch.os.environ[browser_launch.LAUNCH_LOCK_DIRECTORY]
                    )
                )
                raise cause
            with original_turn(name) as shared:
                yield shared

        try:
            with (
                mock.patch.object(browser_launch, "launch_turn", turn),
                mock.patch.object(threading, "Thread", thread),
                mock.patch.object(threading, "Event", event),
                self.assertRaises(OSError) as caught,
            ):
                case.test_launches_take_turns_when_a_runner_sets_the_lock_directory()
            self.assertIs(caught.exception, cause)
            self.assertTrue(workers)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
        finally:
            # The negative assertion above precedes the original peer backup.
            for ready in events:
                ready.set()
            for worker in workers:
                if worker.ident is not None:
                    worker.join(10)
            case.doCleanups()
            for directory in directories:
                if directory.exists():
                    shutil.rmtree(directory)

    def test_enter_failure_closes_actual_listener_and_client_before_backup(self):
        accepted = asyncio.Event()
        servers = []
        listener_sockets = []
        writers = []
        workers = []
        actual_start = asyncio.start_server
        actual_thread = threading.Thread
        cause = OSError("original entered launch failure")

        async def start(callback, *args, **kwargs):
            def observe(reader, writer):
                writers.append(writer)
                accepted.set()
                return callback(reader, writer)

            server = await actual_start(observe, *args, **kwargs)
            servers.append(server)
            listener_sockets.extend(sock._sock for sock in server.sockets)
            return server

        def thread(*args, **kwargs):
            worker = actual_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        async def entered(_browser):
            await asyncio.wait_for(accepted.wait(), 2.0)
            raise cause

        def body(case):
            with (
                mock.patch.object(asyncio, "start_server", start),
                mock.patch.object(threading, "Thread", thread),
                mock.patch.object(browser_launch, "enter_browser", entered),
                self.assertRaises(OSError) as caught,
            ):
                case.test_the_server_answers_while_a_firefox_launch_waits()
            self.assertIs(caught.exception, cause)
            self.assertTrue(servers)
            self.assertTrue(all(not server.is_serving() for server in servers))
            self.assertTrue(all(writer.is_closing() for writer in writers))
            self.assertTrue(all(not worker.is_alive() for worker in workers))

        try:
            self.run_case("test_the_server_answers_while_a_firefox_launch_waits", body)
        finally:
            # This baseline backup runs after the original asyncio.run closed
            # its loop. Close the recorded native listeners without using it.
            for sock in listener_sockets:
                sock.close()
            for worker in workers:
                if worker.ident is not None:
                    worker.join(10)

    def test_background_response_failure_is_the_original_test_failure(self):
        servers = []
        writers = []
        actual_start = asyncio.start_server
        cause = ValueError("original accepted response failure")

        async def start(callback, *args, **kwargs):
            def observe(reader, writer):
                writers.append(writer)

                async def drain():
                    raise cause

                writer.drain = drain
                result = callback(reader, writer)
                return result if inspect.isawaitable(result) else None

            server = await actual_start(observe, *args, **kwargs)
            servers.append(server)
            return server

        def body(case):
            with (
                mock.patch.object(asyncio, "start_server", start),
                self.assertRaises(ValueError) as caught,
            ):
                case.test_the_server_answers_while_a_firefox_launch_waits()
            self.assertIs(caught.exception, cause)
            self.assertTrue(servers)
            self.assertTrue(all(not server.is_serving() for server in servers))
            self.assertTrue(all(writer.is_closing() for writer in writers))

        try:
            self.run_case("test_the_server_answers_while_a_firefox_launch_waits", body)
        finally:
            for server in servers:
                server.close()

    def test_failed_second_lock_propagates_original_worker_failure(self):
        case = launch_tests.LaunchTurnTests(
            "test_launches_take_turns_when_a_runner_sets_the_lock_directory"
        )
        original_turn = browser_launch.launch_turn
        original_thread = threading.Thread
        workers = []
        cause = OSError("original second lock failure")

        def thread(*args, **kwargs):
            worker = original_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        @contextlib.contextmanager
        def turn(name):
            if threading.current_thread() is not threading.main_thread():
                raise cause
            with original_turn(name) as shared:
                yield shared

        try:
            with (
                mock.patch.object(browser_launch, "launch_turn", turn),
                mock.patch.object(threading, "Thread", thread),
                self.assertRaises(OSError) as caught,
            ):
                case.test_launches_take_turns_when_a_runner_sets_the_lock_directory()
            self.assertIs(caught.exception, cause)
            self.assertTrue(workers)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
        finally:
            for worker in workers:
                if worker.ident is not None:
                    worker.join(10)
            self.assertTrue(case.doCleanups())

    def test_holder_failure_is_collected_before_setup_returns(self):
        original_thread = threading.Thread
        workers = []
        cause = ValueError("original holder failure")

        def thread(*args, **kwargs):
            worker = original_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        @contextlib.contextmanager
        def turn(_name):
            raise cause
            yield  # Keep this a context manager without entering its body.

        with (
            mock.patch.object(browser_launch, "launch_turn", turn),
            mock.patch.object(threading, "Thread", thread),
            self.assertRaises(ValueError) as caught,
        ):
            self.run_case(
                "test_the_server_answers_while_a_firefox_launch_waits", lambda _: None
            )
        self.assertIs(caught.exception, cause)
        self.assertTrue(workers)
        self.assertTrue(all(not worker.is_alive() for worker in workers))

    def test_native_client_failure_is_collected_with_its_socket_closed(self):
        actual_connect = socket.create_connection
        sockets = []
        cause = OSError("original client receive failure")

        class FailedReceive:
            def __init__(self, sock):
                self.sock = sock

            def __enter__(self):
                return self

            def __exit__(self, *_details):
                self.sock.close()

            def sendall(self, data):
                self.sock.sendall(data)

            def recv(self, count):
                self.sock.recv(count)
                raise cause

        def connect(*args, **kwargs):
            sock = actual_connect(*args, **kwargs)
            sockets.append(sock)
            return FailedReceive(sock)

        def body(case):
            with (
                mock.patch.object(socket, "create_connection", connect),
                self.assertRaises(OSError) as caught,
            ):
                case.test_the_server_answers_while_a_firefox_launch_waits()
            self.assertIs(caught.exception, cause)
            self.assertTrue(sockets)
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets))

        self.run_case("test_the_server_answers_while_a_firefox_launch_waits", body)

    def test_response_and_close_failures_keep_both_original_causes(self):
        actual_start = asyncio.start_server
        writers = []
        response_error = ValueError("original response error before cleanup")
        prior_error = RuntimeError("original response cause")
        response_error.__cause__ = prior_error
        close_error = OSError("original accepted writer close failure")

        async def start(callback, *args, **kwargs):
            def accept(reader, writer):
                writers.append(writer)
                actual_close = writer.close
                first_close = True

                async def drain():
                    raise response_error

                def close():
                    nonlocal first_close
                    actual_close()
                    if first_close:
                        first_close = False
                        raise close_error

                writer.drain = drain
                writer.close = close
                return callback(reader, writer)

            return await actual_start(accept, *args, **kwargs)

        def body(case):
            with (
                mock.patch.object(asyncio, "start_server", start),
                self.assertRaises(ValueError) as caught,
            ):
                case.test_the_server_answers_while_a_firefox_launch_waits()
            self.assertIs(caught.exception, response_error)
            packet = caught.exception.__cause__
            self.assertIsInstance(packet, launch_tests.LaunchPeerFailures)
            self.assertIs(packet.primary, response_error)
            self.assertIs(packet.prior_cause, prior_error)
            self.assertEqual(len(packet.cleanup), 1)
            self.assertIs(packet.cleanup[0], close_error)
            self.assertTrue(writers)
            self.assertTrue(all(writer.is_closing() for writer in writers))
            self.assertFalse(packet.pending)

        self.run_case("test_the_server_answers_while_a_firefox_launch_waits", body)
