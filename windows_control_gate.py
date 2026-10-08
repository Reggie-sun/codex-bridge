"""Windows Codex prompt-control transport and protocol gate.

The exact forced command dispatches to this bounded app-server proxy. Native
Codex built-in tools remain available. The thread reports read-only sandbox,
approval-never, and network-disabled policy; OS-level tool isolation is not
claimed as verified. Private-root reads are permitted by the accepted contract.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any
from pathlib import Path
import uuid

COMMAND = "feige-codex-control/v1"
SCHEMA = "feige-windows-codex-task-result/v1"
BOUNDARIES = (
    "Work only on the bound project task. Use shell/filesystem tools as needed. "
    "No nested agents, credentials, private platform payloads, Cookie/storage, "
    "account/config changes, background processes, desktop/browser actions or sends. "
    "Preserve unrelated edits and unknown-outcome journals. No git push or deployment. "
    "Return only the requested structured result; do not put private data in metrics."
)
BOUNDARIES_SHA256 = "66705de6a3ef45d9a64627b3e1c4aa723726d7c340f880f6106c444aa820a027"
METHODS = frozenset({"initialize", "initialized", "thread/start", "turn/start", "turn/interrupt"})
MAX_FRAME = 1_048_576
MAX_TASK = 16_384
MAX_PENDING = 65_536
MAX_OUTPUT = 16 * 1024 * 1024
WALL_SECONDS = 900
_QUEUE_CHUNK = 4096
REMOTE_REJECT_CODES = frozenset({
    "TASK_ALREADY_CONSUMED", "RPC_ID_REUSED", "CONTROL_TIMEOUT", "CONTROL_CLOSED",
    "FRAME_LIMIT", "PENDING_STDIN_LIMIT", "OUTPUT_LIMIT", "NATIVE_EOF",
    "NATIVE_RPC_FAILED", "NATIVE_RESPONSE_INVALID", "THREAD_START_INVALID",
    "TURN_START_INVALID", "TURN_FAILED", "FINAL_INVALID", "FINAL_MISSING",
    "RESULT_INVALID", "RESULT_SCHEMA_INVALID", "PROTOCOL_REJECTED",
})


class Reject(ValueError):
    """Safe fixed error codes only; never include request or tool payloads."""


if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.OpenThread.restype = wintypes.HANDLE
    _k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _k32.GetFileAttributesW.restype = wintypes.DWORD
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.LocalFree.argtypes = [wintypes.HLOCAL]
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                  ctypes.POINTER(wintypes.DWORD)]
    _adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    _adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _adv.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    _adv.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           wintypes.DWORD, ctypes.c_void_p]
    _adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BasicLimit), ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

class _ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD)]


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    value = wintypes.LPWSTR()
    if not _adv.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    try:
        return value.value or ""
    finally:
        _k32.LocalFree(value)


def _current_user_sid() -> str:
    token = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    try:
        needed = wintypes.DWORD()
        _adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise Reject("JOURNAL_ACL_UNVERIFIED")
        buffer = ctypes.create_string_buffer(needed.value)
        if not _adv.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise Reject("JOURNAL_ACL_UNVERIFIED")
        sid = ctypes.c_void_p.from_buffer(buffer).value
        if not sid:
            raise Reject("JOURNAL_ACL_UNVERIFIED")
        sid_ptr = ctypes.c_void_p(sid)
        return _sid_to_string(sid_ptr)
    finally:
        _k32.CloseHandle(token)


def _verify_private_acl(path: Path, expected_flags: int = 0) -> None:
    if os.name != "nt":
        raise Reject("WINDOWS_ACL_REQUIRED")
    attributes = _k32.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF or attributes & 0x400:
        raise Reject("JOURNAL_PATH_INVALID")
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = _adv.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                      ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                      ctypes.byref(descriptor))
    if error or not owner.value or not dacl.value or not descriptor.value:
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not _adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise Reject("JOURNAL_ACL_UNVERIFIED")
        if not control.value & 0x1000:
            raise Reject("JOURNAL_ACL_INVALID")
        user = _current_user_sid()
        owner_sid = _sid_to_string(owner)
        allowed = {user, "S-1-5-18"}
        class _AclSize(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                        ("AclBytesFree", wintypes.DWORD)]
        info = _AclSize()
        if not _adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2) or info.AceCount != 2:
            raise Reject("JOURNAL_ACL_INVALID")
        seen = set()
        for index in range(info.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not _adv.GetAce(dacl, index, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                raise Reject("JOURNAL_ACL_UNVERIFIED")
            addr = ace_ptr.value
            raw = ctypes.cast(ace_ptr, ctypes.POINTER(ctypes.c_ubyte))
            ace_type, ace_flags = raw[0], raw[1]
            mask = ctypes.c_uint32.from_address(addr + 4).value
            sid_ptr = ctypes.c_void_p(addr + 8)
            sid = _sid_to_string(sid_ptr)
            if ace_type != 0 or ace_flags != expected_flags or mask != 0x001F01FF or sid not in allowed:
                raise Reject("JOURNAL_ACL_INVALID")
            seen.add(sid)
        if owner_sid != user or seen != allowed:
            raise Reject("JOURNAL_ACL_INVALID")
    except Reject:
        raise
    except Exception:
        raise Reject("JOURNAL_ACL_UNVERIFIED") from None
    finally:
        if descriptor.value:
            _k32.LocalFree(descriptor)


def _inherited_private_acl_facts_valid(owner_sid: str, user_sid: str,
                                      dacl_protected: bool,
                                      aces: list[tuple[int, int, int, str]],
                                      system_sid: str = "S-1-5-18") -> bool:
    """Accept only a two-ACE file DACL inherited from a separately verified parent."""
    allowed = {user_sid, system_sid}
    return (
        owner_sid == user_sid
        and dacl_protected is False
        and len(aces) == 2
        and {ace[3] for ace in aces} == allowed
        and len({ace[3] for ace in aces}) == 2
        and all(ace[0] == 0 and ace[1] == 0x10 and ace[2] == 0x001F01FF for ace in aces)
    )


def _verify_inherited_private_file_acl(path: Path, protected_parent: Path, *,
                                       parent_error: str = "JOURNAL_ACL_INVALID",
                                       file_error: str = "JOURNAL_ACL_INVALID") -> None:
    """Verify a newly created journal file inheriting only the protected journal DACL.

    The parent must retain the normal protected private-directory ACL. The child
    must have exactly inherited user/SYSTEM full-control ACEs and no other ACEs.
    This narrow case avoids rewriting the ACL on the parent or existing files.
    """
    if os.name != "nt":
        raise Reject("WINDOWS_ACL_REQUIRED")
    try:
        _verify_private_acl(protected_parent, expected_flags=3)
    except Reject as exc:
        if exc.args and exc.args[0] == "JOURNAL_ACL_INVALID":
            raise Reject(parent_error) from None
        raise
    attributes = _k32.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF or attributes & 0x400:
        raise Reject("JOURNAL_PATH_INVALID")
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = _adv.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                      ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                      ctypes.byref(descriptor))
    if error or not owner.value or not dacl.value or not descriptor.value:
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not _adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise Reject("JOURNAL_ACL_UNVERIFIED")

        class _AclSize(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                        ("AclBytesFree", wintypes.DWORD)]

        info = _AclSize()
        if not _adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise Reject("JOURNAL_ACL_UNVERIFIED")
        aces = []
        for index in range(info.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not _adv.GetAce(dacl, index, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                raise Reject("JOURNAL_ACL_UNVERIFIED")
            raw = ctypes.cast(ace_ptr, ctypes.POINTER(ctypes.c_ubyte))
            mask = ctypes.c_uint32.from_address(ace_ptr.value + 4).value
            sid = _sid_to_string(ctypes.c_void_p(ace_ptr.value + 8))
            aces.append((int(raw[0]), int(raw[1]), int(mask), sid))
        if not _inherited_private_acl_facts_valid(
                _sid_to_string(owner), _current_user_sid(), bool(control.value & 0x1000), aces):
            raise Reject(file_error)
    except Reject:
        raise
    except Exception:
        raise Reject("JOURNAL_ACL_UNVERIFIED") from None
    finally:
        if descriptor.value:
            _k32.LocalFree(descriptor)


def _set_private_acl(path: Path, inherit_to_children: bool = False) -> None:
    if os.name != "nt":
        raise Reject("WINDOWS_ACL_REQUIRED")
    user_string = _current_user_sid()
    user_sid = ctypes.c_void_p()
    if not _adv.ConvertStringSidToSidW(user_string, ctypes.byref(user_sid)):
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    system_sid = ctypes.c_void_p()
    if not _adv.ConvertStringSidToSidW("S-1-5-18", ctypes.byref(system_sid)):
        raise Reject("JOURNAL_ACL_UNVERIFIED")
    acl_buffer = ctypes.create_string_buffer(1024)
    try:
        if not _adv.InitializeAcl(acl_buffer, len(acl_buffer), 2):
            raise Reject("JOURNAL_ACL_SET_FAILED")
        flags = 0x3 if inherit_to_children else 0
        for sid in (user_sid, system_sid):
            if not _adv.AddAccessAllowedAceEx(acl_buffer, 2, flags, 0x001F01FF, sid):
                raise Reject("JOURNAL_ACL_SET_FAILED")
        info = 0x00000001 | 0x00000004 | 0x80000000
        error = _adv.SetNamedSecurityInfoW(str(path), 1, info, user_sid, None, acl_buffer, None)
        if error:
            raise Reject("JOURNAL_ACL_SET_FAILED")
        _verify_private_acl(path, expected_flags=flags)
    finally:
        _k32.LocalFree(user_sid)
        _k32.LocalFree(system_sid)


class KillOnCloseJob:
    """Own one suspended child process tree with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    def __init__(self, process: subprocess.Popen[bytes]):
        if os.name != "nt":
            raise Reject("WINDOWS_JOB_OBJECT_REQUIRED")
        self.handle = _k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise Reject("JOB_OBJECT_CREATE_FAILED")
        self.process = process
        try:
            info = _ExtendedLimit()
            info.BasicLimitInformation.LimitFlags = 0x00002000
            if not _k32.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise Reject("JOB_OBJECT_CONFIG_FAILED")
            if not _k32.AssignProcessToJobObject(self.handle, wintypes.HANDLE(process._handle)):
                raise Reject("JOB_OBJECT_ASSIGN_FAILED")
            self._resume_primary_thread(process.pid)
        except Exception:
            self.close()
            if process.poll() is None:
                _k32.TerminateProcess(wintypes.HANDLE(process._handle), 1)
            process.wait()
            raise

    @staticmethod
    def _resume_primary_thread(pid: int) -> None:
        snapshot = _k32.CreateToolhelp32Snapshot(0x00000004, 0)
        if snapshot == wintypes.HANDLE(-1).value:
            raise Reject("JOB_OBJECT_THREAD_LOOKUP_FAILED")
        entry = _ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        thread_handle = None
        try:
            ok = _k32.Thread32First(snapshot, ctypes.byref(entry))
            while ok:
                if entry.th32OwnerProcessID == pid:
                    thread_handle = _k32.OpenThread(0x0002, False, entry.th32ThreadID)
                    break
                ok = _k32.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            _k32.CloseHandle(snapshot)
        if not thread_handle:
            raise Reject("JOB_OBJECT_THREAD_LOOKUP_FAILED")
        try:
            if _k32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                raise Reject("JOB_OBJECT_RESUME_FAILED")
        finally:
            _k32.CloseHandle(thread_handle)

    def close(self) -> None:
        if getattr(self, "handle", None):
            _k32.CloseHandle(self.handle)
            self.handle = None


class _ByteCounter:
    def __init__(self, limit: int):
        self.limit, self.value = limit, 0
        self.lock = threading.Lock()

    def add(self, count: int) -> None:
        with self.lock:
            self.value += count
            if self.value > self.limit:
                raise Reject("OUTPUT_LIMIT")


class DurableConsumptionJournal:
    """Per-prompt write-once journal; fail closed unless root/file ACLs are exact."""
    def __init__(self, root: str):
        if os.name != "nt":
            raise Reject("WINDOWS_ACL_REQUIRED")
        self.root = Path(root)
        self._verify_directory_acl()

    def _verify_directory_acl(self) -> None:
        # The installer creates and ACLs this directory. Runtime never relaxes it.
        _verify_private_acl(self.root, expected_flags=0x3)

    def record_unknown(self, prompt: str, job_id: str, sandbox: str) -> str:
        if not _text(prompt, MAX_TASK) or not _text(job_id, 128):
            raise Reject("JOURNAL_INPUT_INVALID")
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        path = self.root / ("job-" + digest + ".private.json")
        payload = json.dumps({"schema": "feige-codex-control-job/v1", "state": "OUTCOME_UNKNOWN",
                              "job_id": job_id, "prompt_sha256": digest, "sandbox": sandbox,
                              "automatic_retries": 0}, separators=(",", ":")).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise Reject("TASK_ALREADY_CONSUMED") from None
        except OSError:
            raise Reject("JOURNAL_WRITE_FAILED") from None
        fd_open = True
        try:
            _set_private_acl(path)
            stream_file = os.fdopen(fd, "wb", closefd=True)
            fd_open = False
            with stream_file as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._flush_directory()
        except Exception:
            # Keep a created journal as OUTCOME_UNKNOWN; never delete/reuse it.
            raise Reject("JOURNAL_DURABILITY_UNVERIFIED") from None
        finally:
            if fd_open:
                try:
                    os.close(fd)
                except OSError:
                    pass
        return digest

    def mark_completed(self, prompt_sha256: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", prompt_sha256):
            raise Reject("JOURNAL_STATE_INVALID")
        path = self.root / ("job-" + prompt_sha256 + ".private.json")
        flags = os.O_WRONLY | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd_open = True
        try:
            fd = os.open(path, flags)
            info = os.fstat(fd)
            if not __import__("stat").S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Reject("JOURNAL_FILE_INVALID")
            if info.st_size > 4096:
                raise Reject("JOURNAL_FILE_INVALID")
            _verify_private_acl(path, expected_flags=0)
            stream_file = os.fdopen(fd, "ab", closefd=True)
            fd_open = False
            with stream_file as stream:
                stream.write(b'{"state":"COMPLETED"}\n')
                stream.flush()
                os.fsync(stream.fileno())
            self._flush_directory()
        except Reject:
            raise
        except OSError:
            raise Reject("JOURNAL_STATE_WRITE_FAILED") from None
        finally:
            if fd_open and 'fd' in locals():
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _flush_directory(self) -> None:
        # Windows directory handles may reject FlushFileBuffers; if so, fail closed.
        handle = _k32.CreateFileW(str(self.root), 0xC0000000, 0x00000007, None, 3,
                                  0x02000000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise Reject("JOURNAL_DIRECTORY_OPEN_FAILED")
        try:
            if not _k32.FlushFileBuffers(handle):
                raise Reject("JOURNAL_DIRECTORY_FLUSH_FAILED")
        finally:
            _k32.CloseHandle(handle)


class BoundedChild:
    """Windows app-server stdio with bounded frames, streams, deadline and child-tree cleanup."""
    def __init__(self, argv: list[str], cwd: str, wall_seconds: int = WALL_SECONDS,
                 output_limit: int = MAX_OUTPUT, frame_limit: int = MAX_FRAME,
                 pending_limit: int = MAX_PENDING):
        if os.name != "nt" or not argv or not os.path.isabs(argv[0]):
            raise Reject("NATIVE_LAUNCH_INVALID")
        self.deadline = time.monotonic() + min(wall_seconds, WALL_SECONDS)
        self.frame_limit, self.pending_limit = min(frame_limit, MAX_FRAME), min(pending_limit, MAX_PENDING)
        self.output_count = _ByteCounter(min(output_limit, MAX_OUTPUT))
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=4)
        self.pending = bytearray()
        self.diagnostic_counts = {"native_stdin_bytes": 0, "native_stdout_bytes": 0,
                                  "native_stderr_bytes": 0}
        self.pending_lock = threading.Lock()
        self.write_cv = threading.Condition(self.pending_lock)
        self.closed = False
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        try:
            child_env = os.environ.copy()
            child_env.pop("FEIGE_CONTROL_DIAGNOSTICS", None)
            self.proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=False, bufsize=0,
                                         creationflags=flags, env=child_env)
            self.job = KillOnCloseJob(self.proc)
        except Reject:
            raise
        except Exception:
            raise Reject("NATIVE_LAUNCH_FAILED") from None
        self.threads = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._drain_stderr, daemon=True),
            threading.Thread(target=self._write_stdin, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def _emit(self, value: tuple[str, Any]) -> None:
        while not self.closed:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                self.events.put(value, timeout=min(0.1, remaining))
                return
            except queue.Full:
                continue

    @staticmethod
    def _diagnostic(stage: str, size: int) -> None:
        if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1":
            sys.stderr.write("FEIGE_" + stage + " " +
                             json.dumps({"bytes": int(size)}, separators=(",", ":")) + "\n")

    def _read_stdout(self) -> None:
        buf = bytearray()
        try:
            while not self.closed:
                chunk = self.proc.stdout.read(_QUEUE_CHUNK)
                if not chunk:
                    if buf:
                        raise Reject("FRAME_TRUNCATED")
                    self._emit(("eof", None))
                    return
                self.diagnostic_counts["native_stdout_bytes"] += len(chunk)
                self._diagnostic("NATIVE_STDOUT_READ", len(chunk))
                self.output_count.add(len(chunk))
                buf.extend(chunk)
                while True:
                    end = buf.find(b"\n")
                    if end < 0:
                        if len(buf) > self.frame_limit:
                            raise Reject("FRAME_LIMIT")
                        break
                    if end > self.frame_limit:
                        raise Reject("FRAME_LIMIT")
                    raw = bytes(buf[:end])
                    del buf[:end + 1]
                    self._emit(("stdout", parse_frame(raw)))
        except Reject as error:
            self._emit(("error", str(error)))
        except Exception:
            self._emit(("error", "NATIVE_STDOUT_FAILED"))

    def _drain_stderr(self) -> None:
        try:
            while not self.closed:
                chunk = self.proc.stderr.read(_QUEUE_CHUNK)
                if not chunk:
                    return
                self.diagnostic_counts["native_stderr_bytes"] += len(chunk)
                self._diagnostic("NATIVE_STDERR_READ", len(chunk))
                # Stderr is discarded, never logged or forwarded.
                self.output_count.add(len(chunk))
        except Reject as error:
            self._emit(("error", str(error)))
        except Exception:
            self._emit(("error", "NATIVE_STDERR_FAILED"))

    def _write_stdin(self) -> None:
        try:
            while not self.closed:
                with self.write_cv:
                    while not self.pending and not self.closed:
                        self.write_cv.wait(timeout=0.1)
                    if self.closed:
                        return
                    chunk = bytes(self.pending[:_QUEUE_CHUNK])
                written = self.proc.stdin.write(chunk)
                if written is None or written <= 0:
                    raise Reject("NATIVE_STDIN_FAILED")
                self.diagnostic_counts["native_stdin_bytes"] += written
                self._diagnostic("NATIVE_STDIN_WRITE", written)
                self.proc.stdin.flush()
                with self.write_cv:
                    del self.pending[:written]
                    self.write_cv.notify_all()
        except Exception:
            if not self.closed:
                self._emit(("error", "NATIVE_STDIN_FAILED"))

    def send(self, message: dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > self.frame_limit + 1:
            raise Reject("FRAME_LIMIT")
        if len(raw) > self.pending_limit:
            raise Reject("PENDING_STDIN_LIMIT")
        with self.write_cv:
            while len(self.pending) + len(raw) > self.pending_limit:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise Reject("CONTROL_TIMEOUT")
                self.write_cv.wait(timeout=min(0.1, remaining))
            self.pending.extend(raw)
            self.write_cv.notify_all()

    def receive(self) -> tuple[str, Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Reject("CONTROL_TIMEOUT")
        try:
            kind, value = self.events.get(timeout=min(0.1, remaining))
        except queue.Empty:
            if self.proc.poll() is not None:
                raise Reject("NATIVE_EOF")
            if time.monotonic() >= self.deadline:
                raise Reject("CONTROL_TIMEOUT")
            return self.receive()
        if kind == "error":
            raise Reject(value)
        if kind == "eof":
            raise Reject("NATIVE_EOF")
        return kind, value

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        with self.write_cv:
            self.write_cv.notify_all()
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.job.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except Exception:
                pass

    def __enter__(self) -> "BoundedChild":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _metric_kinds(schema: dict[str, Any]) -> dict[str, str]:
    if not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise Reject("OUTPUT_SCHEMA_INVALID")
    props = schema.get("properties")
    if not isinstance(props, dict) or set(props) != {"schema", "status", "reason", "metrics"}:
        raise Reject("OUTPUT_SCHEMA_INVALID")
    metrics = props["metrics"]
    if not isinstance(metrics, dict) or metrics.get("type") != "object" or metrics.get("additionalProperties") is not False:
        raise Reject("OUTPUT_SCHEMA_INVALID")
    fields = metrics.get("properties")
    required = metrics.get("required")
    if not isinstance(fields, dict) or not 1 <= len(fields) <= 32 or set(required or ()) != set(fields):
        raise Reject("OUTPUT_SCHEMA_INVALID")
    kinds: dict[str, str] = {}
    for name, prop in fields.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) or not isinstance(prop, dict):
            raise Reject("OUTPUT_SCHEMA_INVALID")
        if prop.get("type") == "boolean":
            kinds[name] = "boolean"
        elif (prop.get("type") == "integer" and prop.get("minimum") == 0
              and prop.get("maximum") == 1_000_000):
            kinds[name] = "count"
        else:
            raise Reject("OUTPUT_SCHEMA_INVALID")
    return kinds


class WindowsControlProxy:
    """Bounded JSON-RPC proxy for the fixed production dispatch and fake tests.

    Fake mode is used by local tests; production mode uses the same protocol
    gate, bounded child, and durable journal with the caller's private settings.
    """
    def __init__(self, argv: list[str], workspace: str, journal_root: str,
                 parent_in: Any, parent_out: Any, *, fake_app_server_for_test: bool = False,
                 child_factory: Any = BoundedChild, journal_override: Any = None):
        self.argv, self.workspace, self.journal_root = argv, workspace, journal_root
        self.parent_in, self.parent_out, self.child_factory = parent_in, parent_out, child_factory
        self.gate = ProtocolGate(workspace)
        self.journal = journal_override if journal_override is not None else DurableConsumptionJournal(journal_root)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)
        self.write_queue: queue.Queue[bytes | None] = queue.Queue(maxsize=4)
        self.pending_rpc: dict[Any, str] = {}
        self.pending_bytes = 0
        self.pending_lock = threading.Lock()
        self.connection_deadline = time.monotonic() + WALL_SECONDS
        self.prompt_sha256: str | None = None
        self.child: BoundedChild | None = None
        self.closed = threading.Event()
        self.diagnostic_error = "NONE"
        self.diagnostic_lock = threading.Lock()
        self.diagnostic_child_exit_code: int | None = None
        self.diagnostic_parent_location = "NONE"

    def _remember_error(self, code: Any) -> str:
        """Keep the first fixed diagnostic; cleanup must never replace it."""
        value = (code if isinstance(code, str) and code.isupper() and len(code) <= 64
                 and code.replace("_", "").isalnum() else "PROXY_REJECTED")
        with self.diagnostic_lock:
            if self.diagnostic_error == "NONE":
                self.diagnostic_error = value
            return self.diagnostic_error

    def _write_rejection(self, request_id: Any, code: Any) -> None:
        """Send a payload-free correlated JSON-RPC error for fixed known rejects."""
        if (isinstance(request_id, bool) or not isinstance(request_id, (str, int))
                or (isinstance(request_id, str) and (not request_id or len(request_id) > 128))):
            return
        fixed = code if isinstance(code, str) and code in REMOTE_REJECT_CODES else "PROTOCOL_REJECTED"
        self._write({"id": request_id, "error": {"code": -32000, "message": fixed}})

    def _timed_put(self, q: queue.Queue[Any], value: Any) -> None:
        while not self.closed.is_set():
            remaining = self.connection_deadline - time.monotonic()
            if remaining <= 0:
                raise Reject("CONTROL_TIMEOUT")
            try:
                q.put(value, timeout=min(0.1, remaining))
                return
            except queue.Full:
                continue
        raise Reject("CONTROL_CLOSED")

    def _read_parent(self) -> None:
        stage = "READLINE"
        try:
            while not self.closed.is_set():
                raw = self.parent_in.readline(MAX_FRAME + 2)
                if not raw:
                    self._timed_put(self.events, ("parent_eof", None))
                    return
                stage = "FRAME_CHECK"
                if len(raw) > MAX_FRAME + 1 or not raw.endswith(b"\n"):
                    raise Reject("FRAME_LIMIT")
                if len(raw) > MAX_PENDING:
                    raise Reject("PENDING_STDIN_LIMIT")
                stage = "JSON_PARSE"
                message = parse_frame(raw[:-1])
                stage = "QUEUE"
                self._timed_put(self.events, ("parent", message))
        except Reject as error:
            self._remember_error(str(error))
            self._timed_put(self.events, ("error", str(error)))
        except Exception as error:
            if not self.closed.is_set():
                error_type = type(error).__name__.upper()
                category = (error_type if error_type.isalnum() and len(error_type) <= 48
                            else "OTHER_ERROR")
                trace = error.__traceback__
                last = None
                while trace is not None:
                    last = trace
                    trace = trace.tb_next
                if last is not None:
                    fn = last.tb_frame.f_code.co_name
                    line = last.tb_lineno
                    if fn.isidentifier() and 0 < line < 10000:
                        self.diagnostic_parent_location = f"{fn}:{line}"
                self._remember_error("PARENT_" + stage + "_" + category)
                self._timed_put(self.events, ("error", self.diagnostic_error))

    def _pump_child(self) -> None:
        assert self.child
        try:
            while not self.closed.is_set():
                kind, value = self.child.receive()
                self._timed_put(self.events, ("native", value))
        except Reject as error:
            if not self.closed.is_set():
                self._timed_put(self.events, ("error", str(error)))

    def _write_parent(self) -> None:
        try:
            while True:
                raw = self.write_queue.get()
                if raw is None:
                    return
                self.parent_out.write(raw)
                self.parent_out.flush()
                with self.pending_lock:
                    self.pending_bytes -= len(raw)
        except Exception:
            if not self.closed.is_set():
                self._timed_put(self.events, ("error", "PARENT_STDOUT_FAILED"))

    def _forward_parent(self, message: dict[str, Any]) -> None:
        method = self.gate.parent_request(message)
        if method == "initialized":
            self.child.send(message)
            return
        request_id = message["id"]
        if request_id in self.pending_rpc:
            raise Reject("RPC_ID_REUSED")
        if method == "turn/start":
            params = message["params"]
            self.prompt_sha256 = self.journal.record_unknown(
                params["input"][0]["text"], params["clientUserMessageId"], "read-only")
        self.pending_rpc[request_id] = method
        if method == "turn/start":
            native_message = {**message, "params": dict(message["params"])}
            native_message["params"].pop("outputSchema", None)
            self.child.send(native_message)
        else:
            self.child.send(message)

    def _write(self, message: dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > MAX_FRAME + 1:
            raise Reject("FRAME_LIMIT")
        with self.pending_lock:
            if self.pending_bytes + len(raw) > MAX_OUTPUT:
                raise Reject("OUTPUT_LIMIT")
            self.pending_bytes += len(raw)
        self._timed_put(self.write_queue, raw)

    def _native_message(self, message: dict[str, Any]) -> None:
        if "id" in message and "method" not in message:
            request_id = message.get("id")
            method = self.pending_rpc.pop(request_id, None)
            if method is None:
                return
            if "error" in message:
                self._write_rejection(request_id, "NATIVE_RPC_FAILED")
                raise Reject("NATIVE_RPC_FAILED")
            result = message.get("result")
            self.gate.app_response(method, result)
            self._write(message)  # Preserve the native response fields exactly.
            if method == "turn/start":
                early, self.gate.early_events = self.gate.early_events or [], []
                for item in early:
                    self._notification(item)
            return
        method, params = message.get("method"), message.get("params", {})
        if "id" in message and isinstance(method, str):
            decision = self.gate.app_message(message)
            if decision == "decline":
                self.child.send({"id": message["id"], "result": {"decision": "decline"}})
            else:
                self.child.send({"id": message["id"], "error": {"code": -32601, "message": "Unsupported request"}})
            return
        if not self.gate.thread_id or not isinstance(params, dict) or params.get("threadId") != self.gate.thread_id:
            return
        if method in ("item/completed", "turn/completed"):
            status = self.gate.app_message(message)
            if self.gate.turn_id is None and self.gate.busy:
                return
            if not self.gate.busy and status is None:
                return
            turn_id = params.get("turnId")
            if method == "turn/completed":
                turn_value = params.get("turn")
                turn_id = turn_value.get("id") if isinstance(turn_value, dict) else None
            if turn_id != self.gate.turn_id:
                return
            if status == "completed":
                if not self.prompt_sha256 or self.gate.final_text is None:
                    raise Reject("FINAL_MISSING")
                self.journal.mark_completed(self.prompt_sha256)
                self.prompt_sha256 = None
            self._write(message)
            return
        # Only turn-scoped completion/item notifications are part of the contract.

    def _notification(self, message: dict[str, Any]) -> None:
        # Re-run a buffered early notification after turn/start returns its owned ID.
        self._native_message(message)

    def run(self) -> None:
        writer_thread = None
        try:
            self.child = self.child_factory(self.argv, self.workspace)
            threads = [threading.Thread(target=self._read_parent, daemon=True),
                       threading.Thread(target=self._pump_child, daemon=True),
                       threading.Thread(target=self._write_parent, daemon=True)]
            writer_thread = threads[-1]
            for thread in threads:
                thread.start()
            while True:
                remaining = self.connection_deadline - time.monotonic()
                if remaining <= 0:
                    raise Reject("CONTROL_TIMEOUT")
                try:
                    kind, value = self.events.get(timeout=min(0.1, remaining))
                except queue.Empty:
                    continue
                if kind == "error":
                    self._remember_error(value)
                    raise Reject(value)
                if kind == "parent_eof":
                    return
                if kind == "parent":
                    try:
                        self._forward_parent(value)
                    except Reject as error:
                        self._remember_error(str(error))
                        self._write_rejection(value.get("id"), str(error))
                        raise
                elif kind == "native":
                    self._native_message(value)
        except Reject as error:
            self._remember_error(str(error))
            raise
        except Exception:
            self._remember_error("PROXY_INTERNAL_ERROR")
            raise
        finally:
            self.closed.set()
            if self.child:
                self.diagnostic_child_exit_code = self.child.proc.poll()
                self.child.close()
            try:
                self.write_queue.put(None, timeout=0.5)
            except queue.Full:
                pass
            if writer_thread is not None:
                writer_thread.join(timeout=0.5)


def run_native_control(*args: Any, **kwargs: Any) -> None:
    """Run one owned native app-server connection through the strict JSONL gate."""
    if kwargs or len(args) != 5:
        raise Reject("NATIVE_CONTROL_ARGUMENTS_INVALID")
    argv, workspace, journal_root, parent_in, parent_out = args
    proxy = WindowsControlProxy(argv, workspace, journal_root, parent_in, parent_out)
    try:
        proxy.run()
    finally:
        if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1":
            counts = (proxy.child.diagnostic_counts if proxy.child is not None else
                      {"native_stdin_bytes": 0, "native_stdout_bytes": 0,
                       "native_stderr_bytes": 0})
            sys.stderr.write("FEIGE_NATIVE_IO " + json.dumps(counts, separators=(",", ":")) + "\n")
            sys.stderr.write("FEIGE_NATIVE_RESULT " + json.dumps({
                "gate_error": proxy.diagnostic_error,
                "child_exit_code_before_cleanup": proxy.diagnostic_child_exit_code,
                "parent_error_location": proxy.diagnostic_parent_location,
            }, separators=(",", ":")) + "\n")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise Reject("JSON_DUPLICATE_KEY")
        out[key] = value
    return out


def parse_frame(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_FRAME:
        raise Reject("FRAME_LIMIT")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Reject("JSON_INVALID")))
    except Reject:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise Reject("JSON_INVALID") from None
    if not isinstance(value, dict):
        raise Reject("JSON_INVALID")
    return value


def _rpc_id(value: Any) -> bool:
    return (type(value) is int and value >= 0) or (isinstance(value, str) and 0 < len(value) <= 128)


def _text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= limit


@dataclass
class ProtocolGate:
    """Strict request/response checks for the fixed Parent protocol.

    The revised contract allows private-root reads. Native read-only sandbox,
    tool-network isolation, workspace binding, and journal guards still require
    independent verification.
    """
    workspace: str
    thread_id: str | None = None
    turn_id: str | None = None
    busy: bool = False
    output_schema: dict[str, Any] | None = None
    final_count: int = 0
    early_events: list[dict[str, Any]] | None = None
    consumed_job_ids: set[str] | None = None
    consumed_prompt_hashes: set[str] | None = None
    final_text: str | None = None

    def __post_init__(self) -> None:
        if not self.workspace or "\x00" in self.workspace:
            raise Reject("WORKSPACE_INVALID")
        self.early_events = []
        self.consumed_job_ids = set()
        self.consumed_prompt_hashes = set()

    def parent_request(self, msg: dict[str, Any]) -> str:
        method = msg.get("method")
        if method not in METHODS:
            raise Reject("METHOD_DENIED")
        if method == "initialized":
            if set(msg) - {"method", "params"} or msg.get("params", {}) != {}:
                raise Reject("INITIALIZED_INVALID")
            return method
        if set(msg) != {"id", "method", "params"} or not _rpc_id(msg["id"]) or not isinstance(msg["params"], dict):
            raise Reject("REQUEST_INVALID")
        p = msg["params"]
        if method == "initialize":
            expected = {"clientInfo": {"name": "feige-parent", "title": "Feige project control", "version": "1"},
                        "capabilities": {"experimentalApi": False, "requestAttestation": False,
                                         "explicitGatewayOauth": True}}
            if p != expected:
                raise Reject("INITIALIZE_INVALID")
        elif method == "thread/start":
            required = {"cwd", "sandbox", "approvalPolicy", "ephemeral", "developerInstructions"}
            allowed = required | {"serviceTier"}
            tier = p.get("serviceTier", "default")
            if (set(p) not in (required, allowed) or not isinstance(tier, str)
                    or tier not in {"default", "fast"}
                    or p.get("cwd") != self.workspace or p.get("sandbox") != "read-only"
                    or p.get("approvalPolicy") != "never" or p.get("ephemeral") is not True
                    or p.get("developerInstructions") != BOUNDARIES or self.thread_id is not None):
                raise Reject("THREAD_START_INVALID")
            # Native app-server supports this exact request field. Default is pinned
            # explicitly; Fast is a bounded opt-in. Preserve native response verbatim.
            p["serviceTier"] = tier
        elif method == "turn/start":
            required = {"threadId", "clientUserMessageId", "input"}
            if (set(p) not in (required, required | {"outputSchema"})
                    or (p.get("outputSchema") is not None and not isinstance(p.get("outputSchema"), dict))
                    or p.get("threadId") != self.thread_id or not self.thread_id
                    or self.busy or not _text(p.get("clientUserMessageId"), 128)
                    or not isinstance(p.get("input"), list) or len(p["input"]) != 1
                    or not isinstance(p["input"][0], dict)
                    or set(p["input"][0]) != {"type", "text", "text_elements"}
                    or p["input"][0].get("type") != "text" or not _text(p["input"][0].get("text"), MAX_TASK)
                    or p["input"][0].get("text_elements") != []):
                raise Reject("TURN_START_INVALID")
            prompt_hash = hashlib.sha256(p["input"][0]["text"].encode("utf-8")).hexdigest()
            try:
                uuid.UUID(p["clientUserMessageId"])
            except (ValueError, AttributeError, TypeError):
                raise Reject("TURN_START_INVALID") from None
            if p["clientUserMessageId"] in self.consumed_job_ids or prompt_hash in self.consumed_prompt_hashes:
                raise Reject("TASK_ALREADY_CONSUMED")
            self.consumed_job_ids.add(p["clientUserMessageId"])
            self.consumed_prompt_hashes.add(prompt_hash)
            # Older output schemas forced business JSON. Prompt-control v2 accepts native final text.
            self.output_schema = None
            self.busy, self.turn_id, self.final_count = True, None, 0
            self.final_text = None
            self.early_events = []
        elif method == "turn/interrupt":
            if (set(p) != {"threadId", "turnId"} or not self.busy or not self.thread_id or not self.turn_id
                    or p.get("threadId") != self.thread_id or p.get("turnId") != self.turn_id):
                raise Reject("INTERRUPT_INVALID")
        return method

    def app_response(self, request_method: str, value: Any) -> None:
        if not isinstance(value, dict):
            raise Reject("NATIVE_RESPONSE_INVALID")
        if request_method == "thread/start":
            policy = value.get("sandbox")
            if (value.get("cwd") != self.workspace or value.get("approvalPolicy") != "never"
                    or not isinstance(policy, dict) or policy.get("type") != "readOnly"
                    or policy.get("networkAccess") is not False):
                raise Reject("NATIVE_SANDBOX_RESPONSE_INVALID")
            thread = value.get("thread")
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 256:
                raise Reject("NATIVE_THREAD_INVALID")
            self.thread_id = thread_id
        elif request_method == "turn/start":
            turn = value.get("turn")
            turn_id = turn.get("id") if isinstance(turn, dict) else None
            if not isinstance(turn_id, str) or not turn_id or len(turn_id) > 256:
                raise Reject("NATIVE_TURN_INVALID")
            self.turn_id = turn_id
        # Deliberately does not settle turn/interrupt from its RPC acknowledgement.

    def app_message(self, msg: dict[str, Any]) -> str | None:
        """Return decline for approval requests; report matching turn settlement."""
        method, params = msg.get("method"), msg.get("params", {})
        if "id" in msg and isinstance(method, str):
            if method in ("item/commandExecution/requestApproval", "item/fileChange/requestApproval"):
                return "decline"
            return "unsupported"
        if not isinstance(params, dict) or params.get("threadId") != self.thread_id or not self.busy:
            return None
        turn_id = params.get("turnId")
        if method == "turn/completed":
            turn_value = params.get("turn")
            turn_id = turn_value.get("id") if isinstance(turn_value, dict) else None
        if self.turn_id is None:
            if len(self.early_events or []) >= 128:
                raise Reject("EARLY_EVENT_LIMIT")
            self.early_events.append(msg)
            return None
        if turn_id != self.turn_id:
            return None
        if method == "item/completed":
            item = params.get("item")
            if not isinstance(item, dict):
                raise Reject("ITEM_INVALID")
            if item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
                if not _text(item.get("text"), MAX_FRAME) or self.final_count:
                    raise Reject("FINAL_INVALID")
                self.final_count += 1
                self.final_text = item["text"]
        if method == "turn/completed":
            turn = params.get("turn")
            if not isinstance(turn, dict) or turn.get("id") != self.turn_id:
                return None
            status = turn.get("status")
            if status not in ("completed", "interrupted"):
                raise Reject("TURN_FAILED")
            if status == "completed" and self.final_count != 1:
                raise Reject("FINAL_MISSING")
            self.busy = False
            return status
        return None

    def private_read_guard_available(self) -> bool:
        """Compatibility helper; private-read denial was waived by updated contract."""
        return True


def boundaries_digest_ok() -> bool:
    return hashlib.sha256(BOUNDARIES.encode("utf-8")).hexdigest() == BOUNDARIES_SHA256


def parse_result(raw: str, metrics: dict[str, str]) -> dict[str, Any]:
    value = parse_frame(raw.encode("utf-8"))
    if (set(value) != {"schema", "status", "reason", "metrics"} or value.get("schema") != SCHEMA
            or value.get("status") not in ("COMPLETED", "BLOCKED")
            or value.get("reason") not in ("NONE", "TASK_BLOCKED", "VERIFICATION_FAILED",
                                            "SOURCE_UNAVAILABLE", "NEEDS_EXTERNAL_INPUT", "OUT_OF_SCOPE")
            or (value["status"] == "COMPLETED") != (value["reason"] == "NONE")
            or not isinstance(value.get("metrics"), dict) or set(value["metrics"]) != set(metrics)):
        raise Reject("RESULT_INVALID")
    for key, kind in metrics.items():
        item = value["metrics"][key]
        if kind == "boolean" and type(item) is not bool:
            raise Reject("RESULT_INVALID")
        if kind == "count" and (type(item) is not int or not 0 <= item <= 1_000_000):
            raise Reject("RESULT_INVALID")
        if kind not in ("boolean", "count"):
            raise Reject("RESULT_SCHEMA_INVALID")
    return value


def diagnose_result_shape(raw: str, metrics: dict[str, str]) -> dict[str, Any]:
    """Return only fixed booleans/counts for offline diagnostics; never retain payload."""
    result: dict[str, Any] = {
        "final_text_present": bool(raw), "json_syntax_valid": False,
        "top_level_object": False, "required_field_set_exact": False,
        "missing_field_count": 0, "extra_field_count": 0,
        "schema_type_valid": False, "status_type_valid": False,
        "reason_type_valid": False, "top_level_types_valid": False,
        "schema_value_match": False, "status_enum_valid": False,
        "reason_enum_valid": False, "status_reason_relation_valid": False,
        "metrics_object": False, "metrics_field_set_exact": False,
        "missing_metric_count": 0, "extra_metric_count": 0,
        "metric_types_valid": False, "valid_result": False,
        "diagnostic_code": "FINAL_JSON_INVALID",
    }
    try:
        value = parse_frame(raw.encode("utf-8"))
    except Exception as error:
        code = str(error)
        if code in {"JSON_DUPLICATE_KEY", "JSON_INVALID", "FRAME_LIMIT"}:
            result["diagnostic_code"] = code
        return result
    result["json_syntax_valid"] = True
    result["top_level_object"] = isinstance(value, dict)
    expected = {"schema", "status", "reason", "metrics"}
    keys = set(value)
    result["required_field_set_exact"] = keys == expected
    result["missing_field_count"] = len(expected - keys)
    result["extra_field_count"] = len(keys - expected)
    result["schema_type_valid"] = isinstance(value.get("schema"), str)
    result["status_type_valid"] = isinstance(value.get("status"), str)
    result["reason_type_valid"] = isinstance(value.get("reason"), str)
    result["top_level_types_valid"] = all((result["schema_type_valid"],
                                           result["status_type_valid"],
                                           result["reason_type_valid"],
                                           isinstance(value.get("metrics"), dict)))
    result["schema_value_match"] = result["schema_type_valid"] and value.get("schema") == SCHEMA
    result["status_enum_valid"] = result["status_type_valid"] and value.get("status") in ("COMPLETED", "BLOCKED")
    result["reason_enum_valid"] = result["reason_type_valid"] and value.get("reason") in (
        "NONE", "TASK_BLOCKED", "VERIFICATION_FAILED", "SOURCE_UNAVAILABLE",
        "NEEDS_EXTERNAL_INPUT", "OUT_OF_SCOPE")
    result["status_reason_relation_valid"] = (
        result["status_enum_valid"] and result["reason_enum_valid"]
        and ((value.get("status") == "COMPLETED") == (value.get("reason") == "NONE")))
    metrics_value = value.get("metrics")
    result["metrics_object"] = isinstance(metrics_value, dict)
    metric_keys = set(metrics_value) if isinstance(metrics_value, dict) else set()
    result["metrics_field_set_exact"] = metric_keys == set(metrics)
    result["missing_metric_count"] = len(set(metrics) - metric_keys)
    result["extra_metric_count"] = len(metric_keys - set(metrics))
    types_valid = result["metrics_object"] and result["metrics_field_set_exact"]
    if types_valid:
        for name, kind in metrics.items():
            item = metrics_value[name]
            if kind == "boolean":
                types_valid = types_valid and type(item) is bool
            elif kind == "count":
                types_valid = types_valid and type(item) is int and 0 <= item <= 1_000_000
            else:
                types_valid = False
    result["metric_types_valid"] = bool(types_valid)
    result["valid_result"] = all((result["required_field_set_exact"],
                                   result["top_level_types_valid"],
                                   result["schema_value_match"],
                                   result["status_reason_relation_valid"],
                                   result["metrics_object"],
                                   result["metrics_field_set_exact"],
                                   result["metric_types_valid"]))
    if result["valid_result"]:
        result["diagnostic_code"] = "NONE"
    elif not result["required_field_set_exact"]:
        result["diagnostic_code"] = "FINAL_FIELD_SET_INVALID"
    elif not result["top_level_types_valid"]:
        result["diagnostic_code"] = "FINAL_FIELD_TYPE_INVALID"
    elif not result["schema_value_match"]:
        result["diagnostic_code"] = "FINAL_SCHEMA_VALUE_INVALID"
    elif not result["status_reason_relation_valid"]:
        result["diagnostic_code"] = "FINAL_STATUS_REASON_INVALID"
    elif not result["metrics_object"] or not result["metrics_field_set_exact"]:
        result["diagnostic_code"] = "FINAL_METRICS_FIELD_SET_INVALID"
    elif not result["metric_types_valid"]:
        result["diagnostic_code"] = "FINAL_METRIC_TYPE_INVALID"
    return result
