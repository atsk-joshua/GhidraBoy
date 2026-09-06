"""Local transport failure conformance; no claims about emulator observations."""
import json
import socket
import threading
import time
import unittest

from emulicious_probe import Dap


def frame(message):
    payload = json.dumps(message).encode()
    return b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.client, self.peer = socket.socketpair()
        self.addCleanup(self.client.close)
        self.addCleanup(self.peer.close)
        self.dap = Dap(self.client, timeout=0.1)

    def test_interleaved_event_and_reply_retained(self):
        event = dict(type="event", event="stopped", body=dict(reason="pause"))
        reply = dict(type="response", request_seq=7, success=True)
        self.peer.sendall(frame(event) + frame(reply))
        self.assertEqual(reply, self.dap.response(7))
        self.assertEqual(event["body"], self.dap.event("stopped"))

    def test_event_cursor_does_not_reuse_old_stop(self):
        self.peer.sendall(frame(dict(type="event", event="stopped", body=dict(reason="entry"))))
        self.dap.event("stopped")
        cursor = len(self.dap.messages)
        self.peer.sendall(frame(dict(type="event", event="stopped", body=dict(reason="step"))))
        self.assertEqual("step", self.dap.event("stopped", after=cursor)["reason"])

    def test_fragmented_frame(self):
        expected = dict(type="event", event="stopped")
        payload = frame(expected)

        def writer():
            for part in (payload[:9], payload[9:27], payload[27:]):
                self.peer.sendall(part)
                time.sleep(0.005)

        worker = threading.Thread(target=writer)
        worker.start()
        self.addCleanup(worker.join)
        self.assertEqual(expected, self.dap.read())

    def test_peer_exit_is_visible(self):
        self.peer.sendall(b"Content-Length: 20\r\n\r\n{")
        self.peer.close()
        with self.assertRaises(EOFError):
            self.dap.read()

    def test_malformed_or_excessive_frames_rejected(self):
        for payload in (b"Content-Length: 1048577\r\n\r\n", b"Content-Length: -1\r\n\r\n",
                        b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n{", b"x" * 4096,
                        b"Content-Length: 2\r\n\r\n[]"):
            with self.subTest(payload=payload[:60]):
                left, right = socket.socketpair()
                with left, right:
                    right.sendall(payload)
                    with self.assertRaises(ValueError):
                        Dap(left, timeout=0.1).read()

    def test_slow_peer_cannot_extend_request_deadline(self):
        stop = threading.Event()

        def writer():
            while not stop.wait(0.02):
                self.peer.sendall(b"x")

        worker = threading.Thread(target=writer)
        worker.start()
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                self.dap.response(1)
        finally:
            stop.set()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertLess(time.monotonic() - started, 1)

    def test_unsuccessful_reply_is_visible(self):
        self.peer.sendall(frame(dict(type="response", request_seq=1, success=False,
                                    message="unsupported")))
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            self.dap.request("readMemory", {})


if __name__ == "__main__":
    unittest.main()
