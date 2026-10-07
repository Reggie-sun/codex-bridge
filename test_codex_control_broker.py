import io
import json
import os
import queue
import socket
import sys
import threading
import time
import uuid

import pytest

import feige_codex_control_broker as broker
import feige_codex_control_entry as entry
from windows_control_gate import BOUNDARIES, BoundedChild, WindowsControlProxy


def test_pipe_sddl_is_exact_user_and_system_dacl():
    sid = "S-1-5-21-111-222-333-1001"
    sddl = f"O:{sid}G:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)"
    assert sddl.count("(A;;GA;;;") == 2
    assert ";;;WD" not in sddl and ";;;AN" not in sddl
    assert broker.PIPE_REJECT_REMOTE_CLIENTS == 0x8


def test_pipe_stream_consumes_half_close_after_jsonl_frames():
    class Input:
        def __init__(self):
            self.parts = [b'{"id":1,', b'"method":"initialize"}\n' + entry.CLIENT_EOF]
        def read(self, _n):
            return self.parts.pop(0) if self.parts else b""
        def write(self, data):
            return len(data)
        def flush(self):
            pass
    stream = broker.PipeStream(Input())
    assert stream.readline(1024) == b'{"id":1,"method":"initialize"}\n'
    assert stream.readline(1024) == b""


def test_pipe_client_reads_short_jsonl_frame_without_waiting_for_stdin_eof():
    class OpenBufferedStdin:
        def __init__(self): self.calls = 0
        def read(self, _n): raise AssertionError("blocking_read_must_not_be_used")
        def read1(self, _n):
            self.calls += 1
            return b'{"id":1,"method":"initialize"}\n' if self.calls == 1 else b""
    stream = OpenBufferedStdin()
    frame = entry._read_available(stream, entry.COPY_CHUNK)
    assert frame.endswith(b"\n") and len(frame) < entry.COPY_CHUNK
    assert stream.calls == 1


def test_entry_pipe_relay_to_broker_fake_preserves_jsonl_and_final_after_stdin_eof(monkeypatch):
    client_sock, server_sock = socket.socketpair()
    client_pipe = client_sock.makefile("rwb", buffering=0)
    server_pipe = server_sock.makefile("rwb", buffering=0)
    incoming = io.BytesIO(b'{"id":1,"method":"initialize"}\n')
    outgoing = io.BytesIO()
    observed = {}

    def fake_runner(argv, workspace, journal_root, parent_in, parent_out):
        observed["argv"] = argv
        observed["workspace"] = workspace
        observed["journal_root"] = journal_root
        observed["request"] = parent_in.readline(1024)
        observed["eof"] = parent_in.readline(1024)
        # SSH stdin EOF is a half-close; the final response remains deliverable.
        parent_out.write(b'{"id":1,"result":{"ok":true}}\n')
        parent_out.flush()

    def serve_fake():
        try:
            broker.serve_connection(server_pipe, ["fake-codex"], "public-workspace",
                                    "private-journals", fake_runner)
        finally:
            server_pipe.close()
            server_sock.close()
    runner = threading.Thread(target=serve_fake, daemon=True)
    runner.start()
    assert entry._relay(incoming, outgoing, client_pipe, wall_seconds=2) is None
    runner.join(timeout=2)
    assert not runner.is_alive()
    assert observed["request"] == b'{"id":1,"method":"initialize"}\n'
    assert observed["eof"] == b""
    assert observed["workspace"] == "public-workspace"
    assert outgoing.getvalue() == b'{"id":1,"result":{"ok":true}}\n'
    client_sock.close()
    server_sock.close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_fake_native_appserver_roundtrips_through_pipeclient_and_broker():
    client_sock, server_sock = socket.socketpair()
    client_pipe = client_sock.makefile("rwb", buffering=0)
    server_pipe = server_sock.makefile("rwb", buffering=0)
    workspace = os.getcwd()
    source = r'''import json,sys
thread=None
def send(v): print(json.dumps(v,separators=(",",":")),flush=True)
for line in sys.stdin:
 m=json.loads(line); method=m.get("method"); p=m.get("params",{}); mid=m.get("id")
 if method=="initialize": send({"id":mid,"result":{"protocolVersion":"fake"}})
 elif method=="initialized": pass
 elif method=="thread/start":
  thread="fake-broker-thread"
  send({"id":mid,"result":{"cwd":p["cwd"],"approvalPolicy":"never","sandbox":{"type":"readOnly","networkAccess":False},"thread":{"id":thread}}})
 elif method=="turn/start":
  turn="fake-broker-turn"
  send({"id":mid,"result":{"turn":{"id":turn}}})
  send({"method":"item/completed","params":{"threadId":thread,"turnId":turn,"item":{"type":"agentMessage","phase":"final_answer","text":"BROKER_FAKE_FINAL"}}})
  send({"method":"turn/completed","params":{"threadId":thread,"turn":{"id":turn,"status":"completed"}}})
'''
    class Journal:
        def __init__(self): self.state = []
        def record_unknown(self, prompt, job_id, sandbox):
            self.state.append(("OUTCOME_UNKNOWN", prompt, job_id))
            return __import__("hashlib").sha256(prompt.encode()).hexdigest()
        def mark_completed(self, digest): self.state.append(("COMPLETED", digest))
    journal = Journal()

    def fake_runner(_argv, cwd, _journal_root, parent_in, parent_out):
        proxy = WindowsControlProxy([sys.executable, "-u", "-c", source], cwd,
            os.getcwd(), parent_in, parent_out, journal_override=journal)
        proxy.run()

    def broker_thread():
        try:
            broker.serve_connection(server_pipe, ["ignored-by-fake"], workspace,
                                    "private-journals", fake_runner)
        finally:
            server_pipe.close()
            server_sock.close()

    class QueueInput:
        def __init__(self): self.q = queue.Queue()
        def feed(self, raw): self.q.put(raw)
        def close(self): self.q.put(None)
        def read(self, _n):
            value = self.q.get(timeout=15)
            return b"" if value is None else value

    class CaptureOutput:
        def __init__(self): self.cv = threading.Condition(); self.data = bytearray()
        def write(self, raw):
            with self.cv:
                self.data.extend(raw); self.cv.notify_all()
            return len(raw)
        def flush(self): pass
        def readline(self, timeout=15):
            deadline = time.monotonic() + timeout
            with self.cv:
                while b"\n" not in self.data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise TimeoutError("FAKE_ROUNDTRIP_TIMEOUT")
                    self.cv.wait(remaining)
                end = self.data.index(b"\n") + 1
                line = bytes(self.data[:end]); del self.data[:end]
                return json.loads(line)

    request_in, response_out = QueueInput(), CaptureOutput()
    broker_worker = threading.Thread(target=broker_thread, daemon=True)
    broker_worker.start()
    relay_errors = []
    relay_worker = threading.Thread(target=lambda: relay_errors.append(
        entry._relay(request_in, response_out, client_pipe, wall_seconds=15)), daemon=True)
    relay_worker.start()
    request_in.feed(json.dumps({"id": 1, "method": "initialize", "params": {
        "clientInfo": {"name": "feige-parent", "title": "Feige project control", "version": "1"},
        "capabilities": {"experimentalApi": False, "requestAttestation": False,
                         "explicitGatewayOauth": True}}}, separators=(",", ":")).encode()+b"\n")
    assert response_out.readline()["id"] == 1
    request_in.feed(b'{"method":"initialized","params":{}}\n')
    request_in.feed(json.dumps({"id": 2, "method": "thread/start", "params": {
        "cwd": workspace, "sandbox": "read-only", "approvalPolicy": "never",
        "ephemeral": True, "developerInstructions": BOUNDARIES}}, separators=(",", ":")).encode()+b"\n")
    thread_reply = response_out.readline()
    assert thread_reply["result"]["thread"]["id"] == "fake-broker-thread"
    prompt = "fake broker route task"
    request_in.feed(json.dumps({"id": 3, "method": "turn/start", "params": {
        "threadId": "fake-broker-thread", "clientUserMessageId": str(uuid.uuid4()),
        "input": [{"type": "text", "text": prompt, "text_elements": []}]}},
        separators=(",", ":")).encode()+b"\n")
    turn_reply = response_out.readline()
    final_item = response_out.readline()
    settled = response_out.readline()
    assert turn_reply["result"]["turn"]["id"] == "fake-broker-turn"
    assert final_item["params"]["item"]["text"] == "BROKER_FAKE_FINAL"
    assert settled["params"]["turn"]["status"] == "completed"
    request_in.close()
    relay_worker.join(timeout=5); broker_worker.join(timeout=5)
    assert not relay_worker.is_alive() and not broker_worker.is_alive()
    assert relay_errors == [None]
    assert len(journal.state) == 2 and journal.state[-1][0] == "COMPLETED"
    client_sock.close()


def test_fixed_ssh_entry_denies_other_original_command(monkeypatch, capsys):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "arbitrary-command")
    monkeypatch.setattr(entry.sys, "argv", ["feige_codex_control_entry.py"])
    assert entry.main() == 64
    assert "FIXED_COMMAND_REQUIRED" in capsys.readouterr().err


def _pipe_api_events(capsys):
    prefix = "FEIGE_ENTRY_PIPE_API "
    stderr = capsys.readouterr().err
    return [json.loads(line[len(prefix):]) for line in stderr.splitlines() if line.startswith(prefix)]


def test_entry_pipe_diagnostic_waitnamedpipe_failure_is_stage_and_code_only(monkeypatch, capsys):
    from types import SimpleNamespace
    monkeypatch.setattr(entry, "os", SimpleNamespace(**{**vars(os), "name": "nt", "O_BINARY": getattr(os, "O_BINARY", 0)}))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    class Call:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)

    class Kernel:
        WaitNamedPipeW = Call(lambda *_: 0)
        CreateFileW = Call(lambda *_: None)

    monkeypatch.setenv("FEIGE_CONTROL_DIAGNOSTICS", "1")
    monkeypatch.setattr(entry.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel(), raising=False)
    monkeypatch.setattr(entry.ctypes, "get_last_error", lambda: 2, raising=False)
    with pytest.raises(RuntimeError, match="CONTROL_BROKER_UNAVAILABLE"):
        entry._connect_pipe()
    assert _pipe_api_events(capsys) == [
        {"stage": "wait_named_pipe", "ok": False, "error_kind": "win32", "error_code": 2}
    ]


def test_entry_pipe_diagnostic_createfile_failure_records_winerror(monkeypatch, capsys):
    from types import SimpleNamespace
    monkeypatch.setattr(entry, "os", SimpleNamespace(**{**vars(os), "name": "nt", "O_BINARY": getattr(os, "O_BINARY", 0)}))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    class Call:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)

    class Kernel:
        WaitNamedPipeW = Call(lambda *_: 1)
        CreateFileW = Call(lambda *_: None)

    monkeypatch.setenv("FEIGE_CONTROL_DIAGNOSTICS", "1")
    monkeypatch.setattr(entry.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel(), raising=False)
    monkeypatch.setattr(entry.ctypes, "get_last_error", lambda: 5, raising=False)
    with pytest.raises(RuntimeError, match="CONTROL_BROKER_CONNECT_FAILED_5"):
        entry._connect_pipe()
    assert _pipe_api_events(capsys) == [
        {"stage": "wait_named_pipe", "ok": True},
        {"stage": "create_file", "ok": False, "error_kind": "win32", "error_code": 5},
    ]


def test_entry_pipe_diagnostic_duplicatehandle_failure_records_stage_and_code(monkeypatch, capsys):
    from types import SimpleNamespace
    monkeypatch.setattr(entry, "os", SimpleNamespace(**{**vars(os), "name": "nt", "O_BINARY": getattr(os, "O_BINARY", 0)}))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    class Call:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)

    class Kernel:
        WaitNamedPipeW = Call(lambda *_: 1)
        CreateFileW = Call(lambda *_: 1234)
        GetCurrentProcess = Call(lambda: 42)
        DuplicateHandle = Call(lambda *_: 0)
        CloseHandle = Call(lambda *_: 1)

    monkeypatch.setenv("FEIGE_CONTROL_DIAGNOSTICS", "1")
    monkeypatch.setattr(entry.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel(), raising=False)
    monkeypatch.setattr(entry.ctypes, "get_last_error", lambda: 6, raising=False)
    with pytest.raises(RuntimeError, match="CONTROL_PIPE_DUPLICATE_FAILED"):
        entry._connect_pipe()
    assert _pipe_api_events(capsys) == [
        {"stage": "wait_named_pipe", "ok": True},
        {"stage": "create_file", "ok": True},
        {"stage": "duplicate_read", "ok": False, "error_kind": "win32", "error_code": 6},
    ]


def test_entry_pipe_diagnostic_open_osfhandle_records_errno_without_exception_text(monkeypatch, capsys):
    from types import SimpleNamespace
    monkeypatch.setattr(entry, "os", SimpleNamespace(**{**vars(os), "name": "nt", "O_BINARY": getattr(os, "O_BINARY", 0)}))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace())
    class Call:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)

    duplicate_count = 0

    def duplicate(_source, _handle, _target_process, target, *_rest):
        nonlocal duplicate_count
        duplicate_count += 1
        entry.ctypes.cast(target, entry.ctypes.POINTER(entry.ctypes.c_void_p)).contents.value = 1000 + duplicate_count
        return 1

    class Kernel:
        WaitNamedPipeW = Call(lambda *_: 1)
        CreateFileW = Call(lambda *_: 1234)
        GetCurrentProcess = Call(lambda: 42)
        DuplicateHandle = Call(duplicate)
        CloseHandle = Call(lambda *_: 1)

    class Msvcrt:
        @staticmethod
        def open_osfhandle(*_args): raise OSError(9, "private exception text")

    monkeypatch.setenv("FEIGE_CONTROL_DIAGNOSTICS", "1")
    monkeypatch.setattr(entry.ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel(), raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", Msvcrt)
    with pytest.raises(OSError):
        entry._connect_pipe()
    stderr = capsys.readouterr().err
    assert "private exception text" not in stderr
    prefix = "FEIGE_ENTRY_PIPE_API "
    events = [json.loads(line[len(prefix):]) for line in stderr.splitlines() if line.startswith(prefix)]
    assert events[-1] == {"stage": "open_osfhandle_read", "ok": False,
                          "error_kind": "errno", "error_code": 9}


def test_broker_runtime_refuses_admin_or_wrong_integrity(monkeypatch):
    monkeypatch.setattr(broker, "_ordinary_token_conditions", lambda: {
        "read_status": "PASS", "type": 1, "is_elevated": True,
        "admin_enabled": True, "integrity_rid": 0x3000, "elevation_type": 2})
    with pytest.raises(broker.Reject, match="BROKER_REQUIRES_ORDINARY_MEDIUM_TOKEN"):
        broker._load_runtime()


def test_pipe_security_accepts_only_exact_dacl_shape():
    valid = {"security_info_read": True, "owner_current_user": True,
             "dacl_protected": True, "dacl_read": True, "acl_info_read": True,
             "exactly_two_aces": True, "aces_allow_only": True,
             "generic_all_masks": False, "file_all_access_masks": True,
             "principals_exact": True}
    assert broker._pipe_security_valid(valid)
    assert not broker._pipe_security_valid({**valid, "principals_exact": False})
    assert not broker._pipe_security_valid({**valid, "file_all_access_masks": False})


@pytest.mark.skipif(os.name != "nt", reason="Windows named pipe ACL integration")
@pytest.mark.windows_integration
@pytest.mark.skipif(os.environ.get("FEIGE_RUN_WINDOWS_INTEGRATION") != "1",
                    reason="set FEIGE_RUN_WINDOWS_INTEGRATION=1 only in an authorized Windows integration environment")
def test_real_named_pipe_instance_has_verified_acl_and_bidirectional_io():
    handle, k32 = broker._create_server_pipe()
    user = broker._current_user_sid()
    assert broker._verify_pipe_security(handle, user)
    errors = []
    allow_disconnect = threading.Event()

    def server():
        try:
            connected = bool(k32.ConnectNamedPipe(handle, None))
            if not connected and __import__("ctypes").get_last_error() != broker.ERROR_PIPE_CONNECTED:
                raise RuntimeError("CONNECT_FAILED")
            stream = broker._stream_from_handle(handle)
            deadline = time.monotonic() + 2
            received = None
            while received is None and time.monotonic() < deadline:
                received = stream.read(4)
                if received is None:
                    time.sleep(0.005)
            assert received == b"ping"
            stream.write(b"pong")
            stream.flush()
            allow_disconnect.wait(timeout=2)
            k32.DisconnectNamedPipe(handle)
            stream.close()
        except Exception as error:
            errors.append(type(error).__name__)

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    client = entry._connect_pipe()
    response = []
    def client_reader():
        deadline = time.monotonic() + 2
        value = None
        while value is None and time.monotonic() < deadline:
            value = client.read(4)
            if value is None:
                time.sleep(0.005)
        response.append((value, client.last_peek_error))
        allow_disconnect.set()
    reader = threading.Thread(target=client_reader, daemon=True)
    reader.start()
    client.write(b"ping")
    client.flush()
    reader.join(timeout=2)
    assert not reader.is_alive() and response == [(b"pong", 0)]
    client.close()
    worker.join(timeout=2)
    k32.CloseHandle(handle)
    assert not worker.is_alive()
    assert not errors
