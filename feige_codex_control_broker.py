from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

from feige_codex_control_entry import CLIENT_EOF, PIPE_NAME
from windows_control_gate import (_current_user_sid, _verify_private_acl,
                                  _sid_to_string, run_native_control, Reject)

CONFIG_SCHEMA = "feige-codex-control-private-settings/v1"
CODEX_RELATIVE = (Path("npm") / "node_modules" / "@openai" / "codex" / "node_modules" /
                  "@openai" / "codex-win32-x64" / "vendor" / "x86_64-pc-windows-msvc" /
                  "bin" / "codex.exe")
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
SE_DACL_PROTECTED = 0x1000


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class _DuplexPipe:
    """Independent synchronous handles for concurrent gate reader/writer threads."""
    def __init__(self, reader, writer, peek_handle, owns_peek_handle=False):
        self.reader, self.writer = reader, writer
        self.peek_handle, self.owns_peek_handle = peek_handle, owns_peek_handle
        self.not_connected_since = None

    def read(self, size=-1):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k32.PeekNamedPipe.restype = wintypes.BOOL
        available = wintypes.DWORD()
        if not k32.PeekNamedPipe(wintypes.HANDLE(self.peek_handle), None, 0, None,
                                 ctypes.byref(available), None):
            error = ctypes.get_last_error()
            if error == 232 or (error == 233 and time.monotonic() -
                                (self.not_connected_since or time.monotonic()) < 0.25):
                if error == 233 and self.not_connected_since is None:
                    self.not_connected_since = time.monotonic()
                return None
            if error in (109, 233):
                return b""
            raise OSError(error, "PIPE_PEEK_FAILED")
        self.not_connected_since = None
        if not available.value:
            return None
        amount = available.value if size is None or size < 0 else min(available.value, size)
        return self.reader.read(amount)

    def write(self, data):
        return self.writer.write(data)

    def flush(self):
        return self.writer.flush()

    def close(self):
        for stream in (self.reader, self.writer):
            try:
                stream.close()
            except Exception:
                pass
        if self.owns_peek_handle:
            try:
                ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(self.peek_handle)
            except Exception:
                pass


def _configure_security_apis():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    adv.GetSecurityInfo.restype = wintypes.DWORD
    adv.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    adv.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                  ctypes.POINTER(wintypes.DWORD)]
    adv.GetSecurityDescriptorControl.restype = wintypes.BOOL
    adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    adv.GetAclInformation.restype = wintypes.BOOL
    adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetAce.restype = wintypes.BOOL
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES)]
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.ConnectNamedPipe.restype = wintypes.BOOL
    k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k32.DisconnectNamedPipe.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                    ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                    wintypes.BOOL, wintypes.DWORD]
    k32.DuplicateHandle.restype = wintypes.BOOL
    return adv, k32


def _verify_pipe_security(handle, user_sid: str) -> bool:
    checks = _pipe_security_checks(handle, user_sid)
    return _pipe_security_valid(checks)


def _pipe_security_valid(checks):
    mask_checks = {"generic_all_masks", "file_all_access_masks"}
    return (all(value is True for key, value in checks.items() if key not in mask_checks) and
            (checks.get("generic_all_masks") is True or checks.get("file_all_access_masks") is True))


def _pipe_security_checks(handle, user_sid: str) -> dict:
    adv, _ = _configure_security_apis()
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    status = adv.GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if status or not owner.value or not dacl.value or not descriptor.value:
        return {"security_info_read": False, "security_info_error": int(status)}
    checks = {"security_info_read": True}
    try:
        import windows_control_gate as gate
        owner_text = _sid_to_string(owner)
        checks["owner_current_user"] = owner_text == user_sid
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            return {**checks, "descriptor_control_read": False}
        checks["dacl_protected"] = bool(control.value & SE_DACL_PROTECTED)
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        actual_dacl = ctypes.c_void_p()
        if not adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                             ctypes.byref(actual_dacl), ctypes.byref(defaulted)):
            return {**checks, "dacl_read": False}
        checks["dacl_read"] = True
        if not present.value or not actual_dacl.value:
            return {**checks, "dacl_present": False}
        class ACL_SIZE(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                        ("AclBytesFree", wintypes.DWORD)]
        info = ACL_SIZE()
        if not adv.GetAclInformation(actual_dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            return {**checks, "acl_info_read": False}
        checks["acl_info_read"] = True
        checks["exactly_two_aces"] = info.AceCount == 2
        got = set()
        ace_types = []
        masks = []
        for i in range(2):
            ace = ctypes.c_void_p()
            if not adv.GetAce(actual_dacl, i, ctypes.byref(ace)) or not ace.value:
                return {**checks, "ace_read": False}
            raw = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            mask = ctypes.cast(ace.value + 4, ctypes.POINTER(wintypes.DWORD)).contents.value
            sid_ptr = ctypes.c_void_p(ace.value + 8)
            ace_types.append((int(raw[0]), int(raw[1])))
            masks.append(int(mask))
            sid = ctypes.string_at(sid_ptr, adv.GetLengthSid(sid_ptr))
            got.add(sid)
        user_bytes = _sid_bytes(user_sid)
        system_bytes = _sid_bytes("S-1-5-18")
        checks["aces_allow_only"] = all(item == (0, 0) for item in ace_types)
        checks["generic_all_masks"] = all(item == 0x10000000 for item in masks)
        checks["file_all_access_masks"] = all(item == 0x001F01FF for item in masks)
        checks["principals_exact"] = got == {user_bytes, system_bytes}
        return checks
    except Exception:
        return {**checks, "descriptor_validation": False}
    finally:
        if descriptor.value:
            gate._k32.LocalFree(descriptor)


def _sid_bytes(sid_text: str) -> bytes:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sid = ctypes.c_void_p()
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertStringSidToSidW.restype = wintypes.BOOL
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    if not adv.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
        raise Reject("PIPE_SECURITY_VERIFY_FAILED")
    try:
        return ctypes.string_at(sid, adv.GetLengthSid(sid))
    finally:
        k32.LocalFree(sid)


class PipeStream:
    """Byte pipe adapter with a private half-close marker for SSH stdin EOF."""
    def __init__(self, stream):
        self.stream = stream
        self.pending = bytearray()
        self.eof = False
        self.diagnostic_counts = {"pipe_to_gate_bytes": 0, "gate_to_pipe_bytes": 0}

    @staticmethod
    def _diagnostic(stage, size):
        if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1":
            sys.stderr.write("FEIGE_" + stage + " " +
                             json.dumps({"bytes": int(size)}, separators=(",", ":")) + "\n")

    def readline(self, limit=-1):
        if limit <= 0:
            limit = 1 << 20
        while True:
            marker_at = self.pending.find(CLIENT_EOF)
            if marker_at >= 0:
                if marker_at == 0:
                    del self.pending[:len(CLIENT_EOF)]
                    self.eof = True
                    return b""
                data = bytes(self.pending[:marker_at])
                del self.pending[:marker_at]
            else:
                nl = self.pending.find(b"\n")
                if nl >= 0:
                    end = nl + 1
                    data = bytes(self.pending[:end])
                    del self.pending[:end]
                    return data[:limit]
                if self.eof:
                    if not self.pending:
                        return b""
                    data = bytes(self.pending[:limit])
                    del self.pending[:len(data)]
                    return data
                if len(self.pending) >= limit:
                    data = bytes(self.pending[:limit])
                    del self.pending[:limit]
                    return data
                try:
                    chunk = self.stream.read(min(64 * 1024, limit + len(CLIENT_EOF) - len(self.pending)))
                except OSError:
                    chunk = b""
                if chunk is None:
                    time.sleep(0.005)
                    continue
                if not chunk:
                    self.eof = True
                    continue
                self.diagnostic_counts["pipe_to_gate_bytes"] += len(chunk)
                self._diagnostic("BROKER_PIPE_READ", len(chunk))
                self.pending.extend(chunk)
                continue
            # A half-close marker follows all preceding bytes; return the final
            # line(s) intact so the existing protocol gate can validate them.
            nl = data.find(b"\n")
            if nl >= 0:
                end = nl + 1
                self.pending[:0] = data[end:]
                return data[:end]
            self.pending[:0] = data
            self.eof = True
            return self.readline(limit)

    def write(self, data):
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            count = self.stream.write(view[sent:])
            if count is None or count <= 0:
                raise OSError("SHORT_PIPE_WRITE")
            sent += count
        self.diagnostic_counts["gate_to_pipe_bytes"] += sent
        self._diagnostic("BROKER_PIPE_WRITE", sent)
        return sent

    def flush(self):
        return self.stream.flush()


def _ordinary_token_conditions() -> dict:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise Reject("BROKER_TOKEN_READ_FAILED")
    try:
        def info(info_class):
            needed = wintypes.DWORD()
            adv.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
            if not needed.value or needed.value > 65536:
                raise Reject("BROKER_TOKEN_READ_FAILED")
            data = ctypes.create_string_buffer(needed.value)
            if not adv.GetTokenInformation(token, info_class, data, needed.value, ctypes.byref(needed)):
                raise Reject("BROKER_TOKEN_READ_FAILED")
            return data
        def scalar(info_class):
            return int(ctypes.cast(info(info_class), ctypes.POINTER(wintypes.DWORD)).contents.value)
        user_data = info(1)
        user_sid = ctypes.cast(user_data, ctypes.POINTER(ctypes.c_void_p)).contents.value
        user_hash = hashlib.sha256(ctypes.string_at(user_sid, adv.GetLengthSid(user_sid))).hexdigest()
        integrity_data = info(25)
        integrity_sid = ctypes.cast(integrity_data, ctypes.POINTER(ctypes.c_void_p)).contents.value
        sid_bytes = ctypes.string_at(integrity_sid, adv.GetLengthSid(integrity_sid))
        count = sid_bytes[1]
        integrity_rid = int.from_bytes(sid_bytes[8 + 4 * (count - 1):12 + 4 * (count - 1)], "little")
        return {"read_status": "PASS", "type": scalar(8), "elevation_type": scalar(18),
                "is_elevated": bool(scalar(20)), "admin_enabled": bool(shell.IsUserAnAdmin()),
                "integrity_rid": integrity_rid, "user_hash": user_hash}
    finally:
        k32.CloseHandle(token)


def _ordinary_child_conditions() -> dict:
    root = str(Path(__file__).resolve().parent)
    code = r'''import ctypes,json,hashlib
from ctypes import wintypes
a=ctypes.WinDLL("advapi32",use_last_error=True); k=ctypes.WinDLL("kernel32",use_last_error=True); s=ctypes.WinDLL("shell32",use_last_error=True)
a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]; a.OpenProcessToken.restype=wintypes.BOOL
a.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]; a.GetTokenInformation.restype=wintypes.BOOL
a.GetLengthSid.argtypes=[ctypes.c_void_p]; a.GetLengthSid.restype=wintypes.DWORD; k.GetCurrentProcess.restype=wintypes.HANDLE
h=wintypes.HANDLE()
if not a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(h)): raise SystemExit(2)
def info(n):
 z=wintypes.DWORD(); a.GetTokenInformation(h,n,None,0,ctypes.byref(z))
 if not z.value or z.value>65536: raise SystemExit(3)
 b=ctypes.create_string_buffer(z.value)
 if not a.GetTokenInformation(h,n,b,z.value,ctypes.byref(z)): raise SystemExit(4)
 return b
def scalar(n): return int(ctypes.cast(info(n),ctypes.POINTER(wintypes.DWORD)).contents.value)
u=info(1); us=ctypes.cast(u,ctypes.POINTER(ctypes.c_void_p)).contents.value
ih=info(25); isid=ctypes.cast(ih,ctypes.POINTER(ctypes.c_void_p)).contents.value
raw=ctypes.string_at(isid,a.GetLengthSid(isid)); c=raw[1]; rid=int.from_bytes(raw[8+4*(c-1):12+4*(c-1)],"little")
print(json.dumps({"read_status":"PASS","type":scalar(8),"elevation_type":scalar(18),"is_elevated":bool(scalar(20),),"admin_enabled":bool(s.IsUserAnAdmin()),"integrity_rid":rid,"user_hash":hashlib.sha256(ctypes.string_at(us,a.GetLengthSid(us))).hexdigest()},separators=(",",":")))
'''
    try:
        result = subprocess.run([sys.executable, "-c", code], cwd=root,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            shell=False, timeout=10, check=False)
    except Exception:
        raise Reject("BROKER_CHILD_TOKEN_PROBE_FAILED") from None
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise Reject("BROKER_CHILD_TOKEN_PROBE_FAILED")
    try:
        child = json.loads(result.stdout.decode("utf-8"))
    except Exception:
        raise Reject("BROKER_CHILD_TOKEN_PROBE_FAILED") from None
    parent_hash = _ordinary_token_conditions().get("user_hash")
    checks = {"read_pass": child.get("read_status") == "PASS",
              "primary_type": child.get("type") == 1,
              "not_elevated": child.get("is_elevated") is False,
              "admin_disabled": child.get("admin_enabled") is False,
              "medium_integrity": child.get("integrity_rid") == 0x2000,
              "elevation_type_known": child.get("elevation_type") in (1, 3),
              "same_user": child.get("user_hash") == parent_hash}
    if not all(checks.values()):
        error = Reject("BROKER_CHILD_TOKEN_NOT_ORDINARY")
        error.checks = checks
        raise error
    return {"same_user": True, "ordinary": True, "integrity_rid": child["integrity_rid"]}


def _load_runtime():
    conditions = _ordinary_token_conditions()
    if (conditions.get("read_status") != "PASS" or conditions.get("type") != 1 or
        conditions.get("is_elevated") is not False or conditions.get("admin_enabled") is not False or
        conditions.get("integrity_rid") != 0x2000 or conditions.get("elevation_type") not in (1, 3)):
        raise Reject("BROKER_REQUIRES_ORDINARY_MEDIUM_TOKEN")
    root = Path(__file__).resolve().parent
    _verify_private_acl(root, expected_flags=3)
    settings_path = root / "settings.private.json"
    _verify_private_acl(settings_path, expected_flags=0)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    if not isinstance(settings, dict) or set(settings) != {"schema", "workspace", "journal_root", "workspace_source_sha256"}:
        raise Reject("PRIVATE_SETTINGS_INVALID")
    if settings.get("schema") != CONFIG_SCHEMA:
        raise Reject("PRIVATE_SETTINGS_INVALID")
    workspace = settings.get("workspace")
    journal_root = settings.get("journal_root")
    if not isinstance(workspace, str) or not os.path.isabs(workspace):
        raise Reject("PRIVATE_SETTINGS_INVALID")
    if not isinstance(journal_root, str) or not os.path.isabs(journal_root):
        raise Reject("PRIVATE_SETTINGS_INVALID")
    source_sha256 = settings.get("workspace_source_sha256")
    if (not isinstance(source_sha256, str) or len(source_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in source_sha256)):
        raise Reject("PRIVATE_SETTINGS_INVALID")
    source = Path(workspace) / "app.py"
    if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != source_sha256:
        raise Reject("WORKSPACE_BINDING_INVALID")
    journals = Path(journal_root)
    _verify_private_acl(journals, expected_flags=3)
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise Reject("CODEX_PATH_INVALID")
    codex = Path(appdata) / CODEX_RELATIVE
    if not codex.is_file():
        raise Reject("CODEX_PATH_INVALID")
    child_conditions = _ordinary_child_conditions()
    return str(codex), workspace, str(journals), conditions, child_conditions


def _create_server_pipe():
    if os.name != "nt":
        raise Reject("WINDOWS_NAMED_PIPE_REQUIRED")
    adv, k32 = _configure_security_apis()
    user_sid = _current_user_sid()
    sddl = f"O:{user_sid}G:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)"
    descriptor = ctypes.c_void_p()
    size = wintypes.DWORD()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
        raise Reject("PIPE_SECURITY_CREATE_FAILED")
    try:
        attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        handle = k32.CreateNamedPipeW(PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 64 * 1024, 64 * 1024, 0, ctypes.byref(attrs))
    finally:
        k32.LocalFree(descriptor)
    if not handle or handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error == 5:
            raise Reject("PIPE_CREATE_ACCESS_DENIED")
        if error == 231:
            raise Reject("PIPE_NAME_ALREADY_IN_USE")
        raise Reject("PIPE_CREATE_FAILED")
    checks = _pipe_security_checks(handle, user_sid)
    if not _pipe_security_valid(checks):
        k32.CloseHandle(handle)
        error = Reject("PIPE_SECURITY_VERIFY_FAILED")
        error.checks = checks
        raise error
    return handle, k32


def _stream_from_handle(handle):
    import msvcrt
    _, k32 = _configure_security_apis()
    process = k32.GetCurrentProcess()
    read_handle, write_handle = wintypes.HANDLE(), wintypes.HANDLE()
    try:
        if not k32.DuplicateHandle(process, handle, process, ctypes.byref(read_handle), 0, False, 0x2):
            raise Reject("PIPE_HANDLE_DUPLICATE_FAILED")
        if not k32.DuplicateHandle(process, handle, process, ctypes.byref(write_handle), 0, False, 0x2):
            raise Reject("PIPE_HANDLE_DUPLICATE_FAILED")
        read_raw_handle = int(read_handle.value)
        read_fd = msvcrt.open_osfhandle(read_raw_handle, os.O_RDONLY | os.O_BINARY)
        read_handle = wintypes.HANDLE()
        write_fd = msvcrt.open_osfhandle(int(write_handle.value), os.O_WRONLY | os.O_BINARY)
        write_handle = wintypes.HANDLE()
        return _DuplexPipe(os.fdopen(read_fd, "rb", buffering=0),
                           os.fdopen(write_fd, "wb", buffering=0), int(handle), False)
    except Exception:
        if read_handle.value:
            k32.CloseHandle(read_handle)
        if write_handle.value:
            k32.CloseHandle(write_handle)
        raise


def serve_connection(pipe_stream, argv, workspace, journal_root, runner=run_native_control):
    stream = PipeStream(pipe_stream)
    try:
        return runner(argv, workspace, journal_root, stream, stream)
    finally:
        if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1":
            sys.stderr.write("FEIGE_BROKER_IO " +
                json.dumps(stream.diagnostic_counts, separators=(",", ":")) + "\n")


def main() -> int:
    if len(sys.argv) != 1:
        return 64
    handle = None
    stream = None
    k32 = None
    try:
        codex, workspace, journal_root, conditions, child_conditions = _load_runtime()
        ready_reported = False
        while True:
            handle, k32 = _create_server_pipe()
            stream = _stream_from_handle(handle)
            if not ready_reported:
                print(json.dumps({"schema": "feige-codex-control-broker/v1", "status": "READY",
                                  "ordinary_token": True, "integrity_rid": conditions["integrity_rid"],
                                  "ordinary_same_user_child": child_conditions["same_user"],
                                  "pipe_acl_verified": True, "remote_clients_rejected": True,
                                  "same_user_local_clients_allowed": True}, separators=(",", ":")), flush=True)
                ready_reported = True
            try:
                connected = bool(k32.ConnectNamedPipe(handle, None))
                if not connected and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                    raise Reject("PIPE_CONNECT_FAILED")
                serve_connection(stream, [str(codex), "-c", 'model="gpt-6.1-sol"',
                                          "-c", 'model_reasoning_effort="high"',
                                          "app-server", "--listen", "stdio://"],
                                 workspace, journal_root)
            except Reject:
                pass
            except Exception:
                pass
            finally:
                try: k32.DisconnectNamedPipe(handle)
                except Exception: pass
                try: stream.close()
                except Exception: pass
                try: k32.CloseHandle(handle)
                except Exception: pass
                handle, stream, k32 = None, None, None
    except KeyboardInterrupt:
        return 0
    except Reject as error:
        sys.stderr.write(str(error) + "\n")
        return 1
    except Exception:
        sys.stderr.write("BROKER_FAILED\n")
        return 1
    finally:
        if handle and k32:
            try: k32.DisconnectNamedPipe(handle)
            except Exception: pass
            try: k32.CloseHandle(handle)
            except Exception: pass
        if stream:
            try: stream.close()
            except Exception: pass


if __name__ == "__main__":
    raise SystemExit(main())

