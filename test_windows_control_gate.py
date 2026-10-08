import json
import io
import os
import queue
import ctypes
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from windows_control_gate import (BOUNDARIES, BoundedChild, DurableConsumptionJournal,
                                  ProtocolGate, Reject, WindowsControlProxy,
                                  _inherited_private_acl_facts_valid,
                                  boundaries_digest_ok, diagnose_result_shape,
                                  parse_frame, parse_result)


WORKSPACE = r"C:\\project\\public-source"
JOB1 = "00000000-0000-4000-8000-000000000001"
JOB2 = "00000000-0000-4000-8000-000000000002"
CAPS = {"experimentalApi": False, "requestAttestation": False, "explicitGatewayOauth": True}
CLIENT = {"name": "feige-parent", "title": "Feige project control", "version": "1"}


def test_inherited_journal_acl_accepts_only_exact_user_system_inheritance():
    user, system = "current-user-test", "SYSTEM"
    expected = [(0, 0x10, 0x001F01FF, user), (0, 0x10, 0x001F01FF, system)]
    assert _inherited_private_acl_facts_valid(user, user, False, expected, system)
    invalid = [
        (user, user, True, expected),
        ("other-owner", user, False, expected),
        (user, user, False, [*expected, (0, 0x10, 0x001F01FF, "other-user")]),
        (user, user, False, [(0, 0x10, 0x001F01FF, user), (0, 0x10, 0x00120089, system)]),
        (user, user, False, [(0, 0, 0x001F01FF, user), expected[1]]),
        (user, user, False, [(1, 0x10, 0x001F01FF, user), expected[1]]),
        (user, user, False, [expected[0], expected[0]]),
    ]
    assert all(not _inherited_private_acl_facts_valid(*case, system_sid=system) for case in invalid)


def rpc(i, method, params):
    return {"id": i, "method": method, "params": params}


def init_params():
    return {"clientInfo": CLIENT, "capabilities": CAPS}


def thread_params(workspace=WORKSPACE, **updates):
    p = {"cwd": workspace, "sandbox": "read-only", "approvalPolicy": "never",
         "ephemeral": True, "developerInstructions": BOUNDARIES}
    p.update(updates)
    return p


def turn_params(gate, prompt="inspect public source", message_id=JOB1):
    return {"threadId": gate.thread_id, "clientUserMessageId": message_id,
            "input": [{"type": "text", "text": prompt, "text_elements": []}],
            "outputSchema": {"type": "object"}}


def ready_gate():
    gate = ProtocolGate(WORKSPACE)
    gate.parent_request(rpc(1, "initialize", init_params()))
    gate.parent_request({"method": "initialized", "params": {}})
    gate.parent_request(rpc(2, "thread/start", thread_params()))
    gate.app_response("thread/start", {"cwd": WORKSPACE, "approvalPolicy": "never",
                                       "sandbox": {"type": "readOnly", "networkAccess": False},
                                       "thread": {"id": "owned-thread"}})
    return gate


def test_boundary_hash_and_frame_duplicate_rejection():
    assert boundaries_digest_ok()
    with pytest.raises(Reject, match="JSON_DUPLICATE_KEY"):
        parse_frame(b'{"id":1,"id":2}')


@pytest.mark.parametrize("method", ["command/exec", "account/read", "thread/resume", "thread/list", "config/read"])
def test_denies_non_allowlisted_method(method):
    gate = ProtocolGate(WORKSPACE)
    with pytest.raises(Reject, match="METHOD_DENIED"):
        gate.parent_request(rpc(1, method, {}))


@pytest.mark.parametrize("change", [
    {"cwd": r"C:\\private"}, {"config": {"model_provider": "x"}},
    {"modelProvider": "x"}, {"sandbox": "workspace-write"},
    {"developerInstructions": "similar but not exact"}, {"approvalPolicy": "on-request"},
])
def test_thread_start_rejects_override_fields(change):
    gate = ProtocolGate(WORKSPACE)
    with pytest.raises(Reject, match="THREAD_START_INVALID"):
        gate.parent_request(rpc(1, "thread/start", thread_params(**change)))


@pytest.mark.parametrize("requested,expected", [(None, "default"), ("fast", "fast"),
                                                   ("default", "default")])
def test_thread_start_service_tier_is_narrow_and_defaulted(requested, expected):
    gate = ProtocolGate(WORKSPACE)
    params = thread_params()
    if requested is not None:
        params["serviceTier"] = requested
    request = rpc(1, "thread/start", params)
    assert gate.parent_request(request) == "thread/start"
    assert request["params"]["serviceTier"] == expected


@pytest.mark.parametrize("requested", [None, "priority", "background", "FAST", 1, True, {}])
def test_thread_start_rejects_unapproved_service_tier(requested):
    gate = ProtocolGate(WORKSPACE)
    params = thread_params(serviceTier=requested)
    with pytest.raises(Reject, match="THREAD_START_INVALID"):
        gate.parent_request(rpc(1, "thread/start", params))


def test_wrong_native_guard_is_not_rewritten():
    gate = ProtocolGate(WORKSPACE)
    gate.parent_request(rpc(1, "thread/start", thread_params()))
    with pytest.raises(Reject, match="NATIVE_SANDBOX_RESPONSE_INVALID"):
        gate.app_response("thread/start", {"cwd": WORKSPACE, "approvalPolicy": "never",
                                           "sandbox": {"type": "readOnly", "networkAccess": True},
                                           "thread": {"id": "owned-thread"}})


def test_tool_item_and_second_distinct_task_on_same_thread():
    gate = ready_gate()
    gate.parent_request(rpc(3, "turn/start", turn_params(gate)))
    gate.app_response("turn/start", {"turn": {"id": "turn-1"}})
    assert gate.app_message({"method": "item/completed", "params": {
        "threadId": "owned-thread", "turnId": "turn-1", "item": {"type": "commandExecution"}}}) is None
    assert gate.app_message({"method": "item/completed", "params": {
        "threadId": "owned-thread", "turnId": "turn-1", "item": {
            "type": "agentMessage", "phase": "final_answer", "text":
            '{"schema":"feige-windows-codex-task-result/v1","status":"COMPLETED","reason":"NONE","metrics":{"ok":true}}'}}}) is None
    assert gate.app_message({"method": "turn/completed", "params": {
        "threadId": "owned-thread", "turn": {"id": "turn-1", "status": "completed"}}}) == "completed"
    with pytest.raises(Reject, match="TASK_ALREADY_CONSUMED"):
        gate.parent_request(rpc(4, "turn/start", turn_params(gate)))
    # A different public task is permitted only after the first matching settlement.
    gate.parent_request(rpc(5, "turn/start", turn_params(gate, "summarize source tree", JOB2)))
    gate.app_response("turn/start", {"turn": {"id": "turn-2"}})
    assert gate.turn_id == "turn-2"


@pytest.mark.parametrize("prior_state", ["COMPLETED", "OUTCOME_UNKNOWN"])
def test_consumed_duplicate_emits_fixed_correlated_error_without_mutating_record(prior_state):
    import hashlib

    prompt = "same already consumed public task"
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    row = {"state": prior_state, "prompt_sha256": digest, "job_id": JOB1}

    class Journal:
        def record_unknown(self, text, job_id, sandbox):
            if hashlib.sha256(text.encode("utf-8")).hexdigest() == digest:
                raise Reject("TASK_ALREADY_CONSUMED")
            raise AssertionError("unexpected task body")

    class Child:
        sent = []
        def send(self, message):
            self.sent.append(message)

    output = io.BytesIO()
    proxy = WindowsControlProxy(["unused"], WORKSPACE, "unused", io.BytesIO(), output,
                                journal_override=Journal())
    proxy.gate = ready_gate()
    proxy.child = Child()
    request = rpc(7, "turn/start", turn_params(proxy.gate, prompt, JOB2))
    with pytest.raises(Reject, match="TASK_ALREADY_CONSUMED"):
        proxy._forward_parent(request)
    proxy._remember_error("TASK_ALREADY_CONSUMED")
    proxy._write_rejection(request["id"], "TASK_ALREADY_CONSUMED")
    response = json.loads(proxy.write_queue.get_nowait())
    assert response == {"id": 7, "error": {"code": -32000, "message": "TASK_ALREADY_CONSUMED"}}
    assert proxy.child.sent == []
    assert row == {"state": prior_state, "prompt_sha256": digest, "job_id": JOB1}


def test_first_diagnostic_wins_over_later_eof_and_cleanup_errors():
    proxy = WindowsControlProxy(["unused"], WORKSPACE, "unused", io.BytesIO(), io.BytesIO(),
                                journal_override=object())
    assert proxy._remember_error("TASK_ALREADY_CONSUMED") == "TASK_ALREADY_CONSUMED"
    assert proxy._remember_error("NATIVE_EOF") == "TASK_ALREADY_CONSUMED"
    assert proxy._remember_error("raw private exception text") == "TASK_ALREADY_CONSUMED"


def test_uncorrelated_parent_eof_produces_no_fabricated_rpc_response():
    output = io.BytesIO()
    proxy = WindowsControlProxy(["unused"], WORKSPACE, "unused", io.BytesIO(), output,
                                journal_override=object())
    proxy._read_parent()
    assert proxy.events.get_nowait() == ("parent_eof", None)
    assert output.getvalue() == b""


def test_native_rpc_error_is_replaced_with_fixed_message():
    output = io.BytesIO()
    proxy = WindowsControlProxy(["unused"], WORKSPACE, "unused", io.BytesIO(), output,
                                journal_override=object())
    proxy.pending_rpc[3] = "thread/start"
    with pytest.raises(Reject, match="NATIVE_RPC_FAILED"):
        proxy._native_message({"id": 3, "error": {"code": -1, "message": "private payload"}})
    response = json.loads(proxy.write_queue.get_nowait())
    assert response == {"id": 3, "error": {"code": -32000, "message": "NATIVE_RPC_FAILED"}}
    assert "private payload" not in json.dumps(response)


def test_plain_text_final_completes_without_json_result_schema():
    gate = ready_gate()
    params = turn_params(gate)
    params.pop("outputSchema")
    gate.parent_request(rpc(3, "turn/start", params))
    gate.app_response("turn/start", {"turn": {"id": "turn-text"}})
    assert gate.app_message({"method": "item/completed", "params": {
        "threadId": "owned-thread", "turnId": "turn-text",
        "item": {"type": "agentMessage", "phase": "final_answer", "text": "OK"}}}) is None
    assert gate.final_text == "OK"
    assert gate.app_message({"method": "turn/completed", "params": {
        "threadId": "owned-thread", "turn": {"id": "turn-text", "status": "completed"}}}) == "completed"
    assert gate.busy is False


def test_proxy_removes_legacy_output_schema_before_native_turn_start():
    from windows_control_gate import WindowsControlProxy

    class Journal:
        def record_unknown(self, prompt, job_id, sandbox):
            return __import__("hashlib").sha256(prompt.encode("utf-8")).hexdigest()

    class Child:
        def __init__(self): self.sent = []
        def send(self, message): self.sent.append(message)

    output = io.BytesIO()
    proxy = WindowsControlProxy([sys.executable], WORKSPACE, r"C:\journal",
                                 io.BytesIO(), output, fake_app_server_for_test=True,
                                 journal_override=Journal())
    proxy.gate = ready_gate()
    proxy.child = Child()
    request = rpc(3, "turn/start", turn_params(proxy.gate))
    proxy._forward_parent(request)
    assert "outputSchema" in request["params"]
    assert "outputSchema" not in proxy.child.sent[0]["params"]
    assert proxy.gate.output_schema is None


def test_wrong_thread_turn_and_approval_escalation():
    gate = ready_gate()
    gate.parent_request(rpc(3, "turn/start", turn_params(gate)))
    gate.app_response("turn/start", {"turn": {"id": "turn-1"}})
    assert gate.app_message({"method": "turn/completed", "params": {
        "threadId": "other-thread", "turn": {"id": "turn-1", "status": "completed"}}}) is None
    assert gate.app_message({"method": "turn/completed", "params": {
        "threadId": "owned-thread", "turn": {"id": "other-turn", "status": "completed"}}}) is None
    assert gate.app_message({"id": 77, "method": "item/commandExecution/requestApproval",
                             "params": {"threadId": "owned-thread"}}) == "decline"
    assert gate.app_message({"id": 78, "method": "unknown/approval", "params": {}}) == "unsupported"
    assert gate.busy


def test_interrupt_ack_does_not_settle_turn():
    gate = ready_gate()
    gate.parent_request(rpc(3, "turn/start", turn_params(gate)))
    gate.app_response("turn/start", {"turn": {"id": "turn-1"}})
    gate.parent_request(rpc(4, "turn/interrupt", {"threadId": "owned-thread", "turnId": "turn-1"}))
    # An RPC result/ack is not a turn/completed notification.
    gate.app_response("turn/interrupt", {})
    assert gate.busy
    assert gate.app_message({"method": "turn/completed", "params": {
        "threadId": "owned-thread", "turn": {"id": "turn-1", "status": "interrupted"}}}) == "interrupted"


def test_result_schema_strictly_limits_metrics():
    valid = {"schema": "feige-windows-codex-task-result/v1", "status": "COMPLETED",
             "reason": "NONE", "metrics": {"ok": True, "count": 4}}
    assert parse_result(json.dumps(valid), {"ok": "boolean", "count": "count"}) == valid
    valid["metrics"]["secret"] = "value"
    with pytest.raises(Reject, match="RESULT_INVALID"):
        parse_result(json.dumps(valid), {"ok": "boolean", "count": "count"})


def test_result_schema_accepts_valid_blocked_status_and_reason():
    blocked = {"schema": "feige-windows-codex-task-result/v1", "status": "BLOCKED",
               "reason": "VERIFICATION_FAILED", "metrics": {"ok": False}}
    assert parse_result(json.dumps(blocked), {"ok": "boolean"}) == blocked
    blocked["reason"] = "NONE"
    with pytest.raises(Reject, match="RESULT_INVALID"):
        parse_result(json.dumps(blocked), {"ok": "boolean"})


def test_result_diagnostic_is_redacted_and_distinguishes_shape_categories():
    metrics = {"ok": "boolean"}
    blocked = {"schema": "feige-windows-codex-task-result/v1", "status": "BLOCKED",
               "reason": "VERIFICATION_FAILED", "metrics": {"ok": False}}
    diagnosis = diagnose_result_shape(json.dumps(blocked), metrics)
    assert diagnosis["valid_result"] is True
    assert diagnosis["diagnostic_code"] == "NONE"
    assert "schema" not in diagnosis and "reason" not in diagnosis

    missing = dict(blocked)
    missing.pop("reason")
    diagnosis = diagnose_result_shape(json.dumps(missing), metrics)
    assert diagnosis["diagnostic_code"] == "FINAL_FIELD_SET_INVALID"
    assert diagnosis["missing_field_count"] == 1

    bad_type = dict(blocked, metrics={"ok": 1})
    diagnosis = diagnose_result_shape(json.dumps(bad_type), metrics)
    assert diagnosis["diagnostic_code"] == "FINAL_METRIC_TYPE_INVALID"

    bad_status_type = dict(blocked, status=[])  # Non-string values are classified without retention.
    diagnosis = diagnose_result_shape(json.dumps(bad_status_type), metrics)
    assert diagnosis["diagnostic_code"] == "FINAL_FIELD_TYPE_INVALID"

    duplicate = '{"schema":"x","schema":"y"}'
    diagnosis = diagnose_result_shape(duplicate, metrics)
    assert diagnosis["diagnostic_code"] == "JSON_DUPLICATE_KEY"


def test_private_canary_diagnostic_writer_accepts_redacted_result_and_metrics(monkeypatch):
    diagnostic_module = pytest.importorskip("native_canary_diagnostic")
    root = Path(os.getcwd())
    monkeypatch.setattr(diagnostic_module, "_set_private_acl", lambda path: None)
    monkeypatch.setattr(diagnostic_module, "_verify_private_acl", lambda path, expected_flags=0: None)
    writer = diagnostic_module.PrivateDiagnosticWriter(str(root))
    writer.path = root / ("diag-test-" + JOB1 + ".private.jsonl")
    monkeypatch.setattr(writer, "_flush_root", lambda: None)
    blocked = {"schema": "feige-windows-codex-task-result/v1", "status": "BLOCKED",
               "reason": "VERIFICATION_FAILED", "metrics": {"ok": False}}
    shape = diagnose_result_shape(json.dumps(blocked), {"ok": "boolean"})
    writer.append("TURN_SETTLED", final_schema=shape, task_status="BLOCKED",
                  task_reason="VERIFICATION_FAILED", turn_completed=True,
                  tool_item_count=1, tool_marker_observed=True,
                  tool_metrics={"public_source_read": True, "tool_calls_observed": 1})
    record = json.loads(writer.path.read_text())
    assert record["final_schema"]["diagnostic_code"] == "NONE"
    assert record["tool_metrics"] == {"public_source_read": True, "tool_calls_observed": 1}
    assert "metrics" not in record
    writer.path.unlink()


def test_private_read_guard_is_waived_by_revised_contract():
    assert ProtocolGate(WORKSPACE).private_read_guard_available() is True


def test_journal_write_once_and_settlement_record(monkeypatch):
    import windows_control_gate as module
    import stat
    from types import SimpleNamespace
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    root = Path(os.getcwd()) / "journal-root-for-fake"
    monkeypatch.setattr(DurableConsumptionJournal, "_verify_directory_acl", lambda self: None)
    monkeypatch.setattr(module, "_verify_private_acl", lambda path, expected_flags=0: None)
    monkeypatch.setattr(module, "_set_private_acl", lambda path: None)
    journal = DurableConsumptionJournal(str(root))
    monkeypatch.setattr(journal, "_flush_directory", lambda: None)
    files, handles, fsyncs = {}, {}, []
    next_fd = [100]
    class FakeStream:
        def __init__(self, key, fd): self.key, self.fd = key, fd
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def write(self, data): files[self.key].extend(data); return len(data)
        def flush(self): return None
        def fileno(self): return self.fd
    def fake_open(path, flags, mode=0):
        key = str(path)
        if flags & os.O_EXCL:
            if key in files: raise FileExistsError()
            files[key] = bytearray()
        elif key not in files:
            raise FileNotFoundError()
        handle = next_fd[0]; next_fd[0] += 1; handles[handle] = key
        return handle
    monkeypatch.setattr(module.os, "open", fake_open)
    monkeypatch.setattr(module.os, "fdopen", lambda fd, mode, closefd=True: FakeStream(handles[fd], fd))
    monkeypatch.setattr(module.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=len(files[handles[fd]])))
    monkeypatch.setattr(module.os, "fsync", lambda fd: fsyncs.append(fd))
    digest = journal.record_unknown("read-only canary request", JOB1, "read-only")
    with pytest.raises(Reject, match="TASK_ALREADY_CONSUMED"):
        journal.record_unknown("read-only canary request", JOB2, "read-only")
    journal.mark_completed(digest)
    rows = bytes(files[str(root / f"job-{digest}.private.json")]).decode("utf-8").splitlines()
    assert json.loads(rows[0])["state"] == "OUTCOME_UNKNOWN"
    assert json.loads(rows[1])["state"] == "COMPLETED"
    assert len(fsyncs) == 2


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_bounded_child_jsonl_and_kill_on_close_job_object():
    code = "import json,sys; [print(json.dumps({'id':m.get('id'),'result':{'ok':True}}),flush=True) for m in map(json.loads,sys.stdin)]"
    child = BoundedChild([sys.executable, "-u", "-c", code], os.getcwd(), wall_seconds=5)
    child.send({"id": 1, "method": "initialize", "params": {}})
    kind, value = child.receive()
    assert kind == "stdout" and value == {"id": 1, "result": {"ok": True}}
    pid = child.proc.pid
    child.close()
    assert child.proc.poll() is not None


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_bounded_child_deadline_and_output_caps():
    slow = BoundedChild([sys.executable, "-u", "-c", "import time; time.sleep(5)"],
                        os.getcwd(), wall_seconds=1)
    with pytest.raises(Reject, match="CONTROL_TIMEOUT"):
        slow.receive()
    slow.close()

    noisy = BoundedChild([sys.executable, "-u", "-c",
                          "import sys; sys.stdout.write('x'*10000);sys.stdout.flush()"],
                         os.getcwd(), wall_seconds=5, output_limit=4096)
    with pytest.raises(Reject, match="OUTPUT_LIMIT"):
        noisy.receive()
    noisy.close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_bounded_child_frame_and_pending_input_caps():
    oversized = BoundedChild([sys.executable, "-u", "-c",
                              "import sys;sys.stdout.buffer.write(b'x'*257+b'\\n');sys.stdout.flush()"],
                             os.getcwd(), wall_seconds=5, frame_limit=256)
    with pytest.raises(Reject, match="FRAME_LIMIT"):
        oversized.receive()
    oversized.close()

    no_reader = BoundedChild([sys.executable, "-u", "-c", "import time;time.sleep(5)"],
                             os.getcwd(), wall_seconds=1, pending_limit=256)
    with pytest.raises(Reject, match="PENDING_STDIN_LIMIT"):
        no_reader.send({"text": "x" * 300})
    no_reader.close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_bounded_child_combined_stdout_stderr_cap():
    code = "import sys;sys.stdout.write('x'*2500);sys.stdout.flush();sys.stderr.write('y'*2500);sys.stderr.flush()"
    child = BoundedChild([sys.executable, "-u", "-c", code], os.getcwd(),
                         wall_seconds=5, output_limit=4096)
    with pytest.raises(Reject, match="OUTPUT_LIMIT"):
        child.receive()
    child.close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_bounded_child_pending_stdin_backpressure_times_out():
    child = BoundedChild([sys.executable, "-u", "-c", "import time;time.sleep(5)"],
                         os.getcwd(), wall_seconds=1, pending_limit=65_536)
    try:
        with pytest.raises(Reject, match="CONTROL_TIMEOUT"):
            for _ in range(10):
                child.send({"text": "x" * 30_000})
    finally:
        child.close()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_job_object_close_kills_child_tree():
    from windows_control_gate import _k32
    code = ("import subprocess,sys,time,json; "
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
            "print(json.dumps({'pid':p.pid}),flush=True);time.sleep(60)")
    child = BoundedChild([sys.executable, "-u", "-c", code], os.getcwd(), wall_seconds=10)
    try:
        kind, value = child.receive()
        assert kind == "stdout" and isinstance(value.get("pid"), int)
        grandchild_pid = value["pid"]
    finally:
        child.close()
    handle = _k32.OpenProcess(0x00100000, False, grandchild_pid)
    if handle:
        try:
            assert _k32.WaitForSingleObject(handle, 0) == 0
        finally:
            _k32.CloseHandle(handle)
    else:
        assert ctypes.get_last_error() in (6, 87)


class QueueReader:
    def __init__(self):
        self.items = queue.Queue()
        self.buffer = bytearray()

    def feed(self, data):
        self.items.put(data)

    def close(self):
        self.items.put(None)

    def readline(self, limit):
        while True:
            at = self.buffer.find(b"\n")
            if at >= 0:
                result = bytes(self.buffer[:at + 1])
                del self.buffer[:at + 1]
                return result
            if len(self.buffer) >= limit:
                return bytes(self.buffer[:limit])
            item = self.items.get()
            if item is None:
                if self.buffer:
                    result = bytes(self.buffer)
                    self.buffer.clear()
                    return result
                return b""
            self.buffer.extend(item)


class CaptureWriter:
    def __init__(self):
        self.data = bytearray()
        self.initialize_response = threading.Event()
        self.thread_response = threading.Event()
        self.turn_completed = threading.Event()

    def write(self, value):
        self.data.extend(value)
        try:
            msg = json.loads(value)
            if msg.get("id") == 1:
                self.initialize_response.set()
            elif msg.get("id") == 2:
                self.thread_response.set()
        except Exception:
            pass
        if b'"method":"turn/completed"' in self.data:
            self.turn_completed.set()
        return len(value)

    def flush(self):
        return None


FAKE_APP_SERVER = r'''import json,sys
thread=None
def send(v): print(json.dumps(v,separators=(",",":")),flush=True)
for line in sys.stdin:
 m=json.loads(line); method=m.get("method"); p=m.get("params",{}); mid=m.get("id")
 if method=="initialize": send({"id":mid,"result":{"protocolVersion":"fake"}})
 elif method=="initialized": pass
 elif method=="thread/start":
  thread="fake-owned-thread"
  send({"id":mid,"result":{"cwd":p["cwd"],"approvalPolicy":"never","sandbox":{"type":"readOnly","networkAccess":False},"thread":{"id":thread}}})
 elif method=="turn/start":
  turn="fake-owned-turn"
  send({"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"threadId":thread}})
  approval=json.loads(sys.stdin.readline())
  assert approval["result"]["decision"]=="decline"
  send({"method":"item/completed","params":{"threadId":thread,"turnId":turn,"item":{"type":"commandExecution","id":"tool-1"}}})
  final={"schema":"feige-windows-codex-task-result/v1","status":"COMPLETED","reason":"NONE","metrics":{"ok":True}}
  send({"method":"item/completed","params":{"threadId":thread,"turnId":turn,"item":{"type":"agentMessage","phase":"final_answer","text":json.dumps(final,separators=(",",":"))}}})
  send({"method":"turn/completed","params":{"threadId":thread,"turn":{"id":turn,"status":"completed"}}})
  send({"id":mid,"result":{"turn":{"id":turn}}})
 elif method=="turn/interrupt": send({"id":mid,"result":{}})
'''


@pytest.mark.skipif(os.name != "nt", reason="requires Windows native child / Job Object")
def test_fake_subprocess_proxy_duplex_tool_approval_and_journal_settle():
    root = Path(os.getcwd())
    workspace = os.getcwd()
    parent_in, parent_out = QueueReader(), CaptureWriter()
    class FakeJournal:
        def __init__(self):
            self.entries = []
        def record_unknown(self, prompt, job_id, sandbox):
            digest = __import__("hashlib").sha256(prompt.encode("utf-8")).hexdigest()
            if any(row["prompt_sha256"] == digest for row in self.entries):
                raise Reject("TASK_ALREADY_CONSUMED")
            self.entries.append({"state": "OUTCOME_UNKNOWN", "prompt_sha256": digest,
                                 "job_id": job_id, "sandbox": sandbox})
            return digest
        def mark_completed(self, digest):
            row = next(item for item in self.entries if item["prompt_sha256"] == digest)
            row["state"] = "COMPLETED"
    fake_journal = FakeJournal()
    proxy = WindowsControlProxy([sys.executable, "-u", "-c", FAKE_APP_SERVER], workspace,
                                str(root), parent_in, parent_out, fake_app_server_for_test=True,
                                journal_override=fake_journal)
    runner = threading.Thread(target=proxy.run, daemon=True)
    runner.start()
    def feed(request):
        parent_in.feed(json.dumps(request, separators=(",", ":")).encode() + b"\n")
    feed(rpc(1, "initialize", init_params()))
    assert parent_out.initialize_response.wait(5)
    feed({"method": "initialized", "params": {}})
    feed(rpc(2, "thread/start", thread_params(workspace=workspace)))
    assert parent_out.thread_response.wait(5)
    feed(rpc(3, "turn/start", {
        "threadId": "fake-owned-thread", "clientUserMessageId": JOB1,
        "input": [{"type": "text", "text": "fake integration task", "text_elements": []}],
        "outputSchema": {"type": "object", "additionalProperties": False,
            "required": ["schema", "status", "reason", "metrics"], "properties": {
                "schema": {"type": "string"}, "status": {"type": "string"},
                "reason": {"type": "string"}, "metrics": {"type": "object",
                    "additionalProperties": False, "required": ["ok"],
                    "properties": {"ok": {"type": "boolean"}}}}}}))
    assert parent_out.turn_completed.wait(10)
    parent_in.close()
    runner.join(10)
    assert not runner.is_alive()
    output = [json.loads(line) for line in bytes(parent_out.data).splitlines()]
    assert any(x.get("result", {}).get("thread", {}).get("id") == "fake-owned-thread" for x in output)
    assert any(x.get("method") == "turn/completed" for x in output)
    assert fake_journal.entries[0]["state"] == "COMPLETED"


def test_production_dispatcher_uses_native_session(monkeypatch):
    import windows_control_gate as module
    calls = []

    class Session:
        def __init__(self, *args):
            calls.append(args)

        def run(self):
            calls.append("run")

    monkeypatch.setattr(module, "WindowsControlProxy", Session)
    argv = [r"C:\codex.exe", "app-server", "--listen", "stdio://"]
    parent_in, parent_out = io.BytesIO(), io.BytesIO()
    module.run_native_control(argv, WORKSPACE, r"C:\private\journal", parent_in, parent_out)
    assert calls == [(argv, WORKSPACE, r"C:\private\journal", parent_in, parent_out), "run"]


def test_production_dispatcher_rejects_overrides_and_extra_arguments():
    from windows_control_gate import run_native_control
    with pytest.raises(Reject, match="NATIVE_CONTROL_ARGUMENTS_INVALID"):
        run_native_control()
    with pytest.raises(Reject, match="NATIVE_CONTROL_ARGUMENTS_INVALID"):
        run_native_control([], "workspace", "journal", io.BytesIO(), io.BytesIO(), unexpected=True)


def test_proxy_drops_native_events_without_owned_thread():
    output = CaptureWriter()
    proxy = WindowsControlProxy([sys.executable, "-u", "-c", "pass"], os.getcwd(), os.getcwd(),
                                io.BytesIO(), output, fake_app_server_for_test=True,
                                journal_override=object())
    proxy._native_message({"method": "item/completed", "params": {"item": {"type": "agentMessage"}}})
    proxy._native_message({"method": "thread/started", "params": {"threadId": "someone-else"}})
    assert not output.data
    assert proxy.write_queue.empty()


def test_parent_output_queue_is_bounded_and_deadline_expires():
    proxy = WindowsControlProxy([sys.executable, "-u", "-c", "pass"], os.getcwd(), os.getcwd(),
                                io.BytesIO(), io.BytesIO(), fake_app_server_for_test=True,
                                journal_override=object())
    proxy.connection_deadline = time.monotonic() + 0.1
    for _ in range(4):
        proxy.write_queue.put_nowait(b"pending")
    with pytest.raises(Reject, match="CONTROL_TIMEOUT"):
        proxy._write({"method": "test"})
