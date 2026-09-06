#!/usr/bin/env python3
"""Bounded DAP feasibility check against an owned, isolated Emulicious process."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time


class Dap:
    def __init__(self, connection):
        self.connection = connection
        self.stream = connection.makefile("rb")
        self.sequence = 0
        self.messages = []

    def send(self, command, arguments):
        self.sequence += 1
        request = dict(seq=self.sequence, type="request", command=command, arguments=arguments)
        raw = json.dumps(request).encode()
        self.connection.sendall(b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
        self.messages.append(dict(direction="sent", message=request))
        return self.sequence

    def read(self):
        length = None
        while True:
            line = self.stream.readline(4096)
            if not line:
                raise EOFError("DAP connection closed")
            if line in (b"\r\n", b"\n"):
                break
            key, value = line.decode().split(":", 1)
            if key.lower() == "content-length":
                length = int(value)
        if length is None or not 0 <= length <= 1024 * 1024:
            raise ValueError("Missing or excessive DAP body length")
        raw = self.stream.read(length)
        if len(raw) != length:
            raise EOFError("Truncated DAP body")
        message = json.loads(raw)
        self.messages.append(dict(direction="received", message=message))
        return message

    def response(self, sequence):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for item in self.messages:
                message = item["message"]
                if message.get("type") == "response" and message.get("request_seq") == sequence:
                    return message
            self.read()
        raise TimeoutError("No DAP response")

    def request(self, command, arguments):
        response = self.response(self.send(command, arguments))
        if not response.get("success"):
            raise RuntimeError(command + ": " + json.dumps(response))
        return response.get("body", {})

    def event(self, name, after=0):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for item in self.messages[after:]:
                message = item["message"]
                if message.get("type") == "event" and message.get("event") == name:
                    return message.get("body", {})
            self.read()
        raise TimeoutError("No DAP event " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java", "jar", "rom", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [str(args.java.resolve()), "-Duser.home=" + str(work / "home"),
               "-jar", str(args.jar.resolve()), "-remotedebug", str(port)]
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
            dap.request("disconnect", dict(terminateDebuggee=False))
            result["detachPreservesEmulator"] = process.poll() is None
            if not result["detachPreservesEmulator"]:
                raise RuntimeError("Disconnect terminated the external emulator")
            result["status"] = "PASS"
        except Exception as error:
            result.update(status="FAIL", error=str(error))
        finally:
            if dap:
                (work / "dap.json").write_text(json.dumps(dap.messages, indent=2) + "\n")
                dap.stream.close()
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
