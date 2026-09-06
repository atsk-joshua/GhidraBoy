#!/usr/bin/env python3
"""Bounded DAP feasibility check against an owned, isolated Emulicious process."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import shutil
import subprocess
import time


class Dap:
    def __init__(self, connection, timeout=15):
        self.connection = connection
        self.timeout = timeout
        self.buffer = bytearray()
        self.sequence = 0
        self.messages = []

    def send(self, command, arguments):
        self.sequence += 1
        request = dict(seq=self.sequence, type="request", command=command, arguments=arguments)
        raw = json.dumps(request).encode()
        self.connection.sendall(b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
        self.messages.append(dict(direction="sent", message=request))
        return self.sequence

    def _receive(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DAP request deadline exceeded")
        self.connection.settimeout(remaining)
        try:
            chunk = self.connection.recv(4096)
        except socket.timeout as error:
            raise TimeoutError("DAP request deadline exceeded") from error
        if not chunk:
            raise EOFError("DAP connection closed or frame truncated")
        self.buffer.extend(chunk)

    def read(self, deadline=None):
        deadline = deadline if deadline is not None else time.monotonic() + self.timeout
        while b"\r\n\r\n" not in self.buffer:
            if len(self.buffer) >= 4096:
                raise ValueError("Excessive DAP header length")
            self._receive(deadline)
        header_end = self.buffer.index(b"\r\n\r\n")
        if header_end > 4096:
            raise ValueError("Excessive DAP header length")
        header = bytes(self.buffer[:header_end])
        del self.buffer[:header_end + 4]
        lengths = []
        for line in header.split(b"\r\n"):
            key, value = line.split(b":", 1)
            if key.lower() == b"content-length":
                lengths.append(int(value))
        length = lengths[0] if len(lengths) == 1 else None
        if length is None or not 0 <= length <= 1024 * 1024:
            raise ValueError("Missing or excessive DAP body length")
        while len(self.buffer) < length:
            self._receive(deadline)
        raw = bytes(self.buffer[:length])
        del self.buffer[:length]
        message = json.loads(raw)
        if not isinstance(message, dict):
            raise ValueError("DAP body must be an object")
        self.messages.append(dict(direction="received", message=message))
        return message

    def response(self, sequence):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            for item in self.messages:
                message = item["message"]
                if item["direction"] == "received" and message.get("type") == "response" and message.get("request_seq") == sequence:
                    return message
            self.read(deadline)
        raise TimeoutError("No DAP response")

    def request(self, command, arguments):
        response = self.response(self.send(command, arguments))
        if not response.get("success"):
            raise RuntimeError(command + ": " + json.dumps(response))
        return response.get("body", {})

    def event(self, name, after=0):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            for item in self.messages[after:]:
                message = item["message"]
                if item["direction"] == "received" and message.get("type") == "event" and message.get("event") == name:
                    return message.get("body", {})
            self.read(deadline)
        raise TimeoutError("No DAP event " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java", "jar", "rom", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.is_relative_to(args.jar.resolve().parent):
        parser.error("Work directory must be outside the supplied emulator directory")
    work.mkdir(parents=True, exist_ok=False)
    emulator = work / "emulator"
    shutil.copytree(args.jar.resolve().parent, emulator, ignore=shutil.ignore_patterns("Emulicious.ini"))
    # The inspected vendor startup handler uses Update=0 for no update checks.
    # Pin the test copy and avoid its first-run modal; never change the supplied app's settings.
    (emulator / "Emulicious.ini").write_text("Update=0\nAudioSync=false\n")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [str(args.java.resolve()), "-Duser.home=" + str(work / "home"),
               "-jar", str(emulator / args.jar.name), "-remotedebug", str(port), "-muted"]
    result = dict(schema=1, status="RUNNING", command=command, scope="M1 external attachment feasibility",
                  jarSha256=hashlib.sha256(args.jar.read_bytes()).hexdigest(),
                  romSha256=hashlib.sha256(args.rom.read_bytes()).hexdigest())
    dap = None
    connection = None
    with (work / "emulator.log").open("w") as log:
        process = subprocess.Popen(command, cwd=work, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Emulator exited before connection")
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                    break
                except OSError:
                    time.sleep(0.1)
            if connection is None:
                raise TimeoutError("Emulator did not open its remote port")
            connection.settimeout(10)
            dap = Dap(connection)
            result["capabilities"] = dap.request("initialize", dict(adapterID="emulicious", clientID="ghidraboy-probe",
                pathFormat="path", linesStartAt1=True, columnsStartAt1=True, supportsVariableType=True,
                supportsMemoryReferences=True))
            launch = dap.send("launch", dict(type="emulicious-debugger", request="launch", name="GhidraBoy probe",
                                             program=str(args.rom.resolve()), stopOnEntry=True, port=port))
            if result["capabilities"].get("supportsConfigurationDoneRequest"):
                dap.event("initialized")
                dap.request("configurationDone", {})
            if not dap.response(launch).get("success"):
                raise RuntimeError("Launch request failed")
            result["stop"] = dap.event("stopped")
            result["threads"] = dap.request("threads", {})
            thread = result["threads"]["threads"][0]["id"]
            result["stack"] = dap.request("stackTrace", dict(threadId=thread))
            frame = result["stack"]["stackFrames"][0]["id"]
            result["scopes"] = dap.request("scopes", dict(frameId=frame))
            result["variables"] = {}
            for scope in result["scopes"]["scopes"]:
                result["variables"][scope["name"]] = dap.request("variables", dict(variablesReference=scope["variablesReference"]))
            cursor = len(dap.messages)
            result["stepReply"] = dap.request("stepIn", dict(threadId=thread, granularity="instruction"))
            result["stepStop"] = dap.event("stopped", after=cursor)
            result["stackAfterStep"] = dap.request("stackTrace", dict(threadId=thread))
            frame_after = result["stackAfterStep"]["stackFrames"][0]["id"]
            scopes_after = dap.request("scopes", dict(frameId=frame_after))
            registers_scope = next(scope for scope in scopes_after["scopes"] if scope.get("presentationHint") == "registers")
            result["registersAfterStep"] = dap.request("variables", dict(variablesReference=registers_scope["variablesReference"]))
            def pc(variables):
                value = next(v["value"] for v in variables["variables"] if v["name"] == "PC")
                return int(value.removeprefix('$'), 16)
            result["pcBefore"] = pc(result["variables"]["Registers"])
            result["pcAfter"] = pc(result["registersAfterStep"])
            if result["pcBefore"] == result["pcAfter"]:
                raise RuntimeError("Step stop did not advance the observed PC")
            dap.request("disconnect", dict(terminateDebuggee=False))
            try:
                process.wait(timeout=0.5)
                result["detachPreservesEmulator"] = False
            except subprocess.TimeoutExpired:
                result["detachPreservesEmulator"] = True
            if not result["detachPreservesEmulator"]:
                raise RuntimeError("Disconnect terminated the external emulator")
            result["status"] = "PASS"
        except Exception as error:
            result.update(status="FAIL", error=str(error))
            jcmd = args.java.resolve().with_name("jcmd")
            if process.poll() is None and jcmd.is_file():
                with (work / "threads.log").open("w") as threads:
                    try:
                        subprocess.run([str(jcmd), str(process.pid), "Thread.print"],
                                       stdout=threads, stderr=subprocess.STDOUT, timeout=5, check=False)
                    except subprocess.TimeoutExpired:
                        result["threadDiagnostic"] = "TIMED_OUT"
        finally:
            if dap:
                (work / "dap.json").write_text(json.dumps(dap.messages, indent=2) + "\n")
            if connection:
                connection.close()
            # This probe created the emulator. Detach above is deliberately separate
            # from cleanup of this owned process; an attached user's emulator is never targeted.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            result["ownedProcessExitCode"] = process.returncode
            (work / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "scope")}, indent=2))
    if result["status"] != "PASS":
        raise SystemExit(result["error"])


if __name__ == "__main__":
    main()
