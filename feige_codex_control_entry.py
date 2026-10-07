from __future__ import annotations

import ctypes
import os
import sys
import threading
import time

PIPE_NAME = r"\\.\pipe\feige-codex-control-v1"
PIPE_WAIT_MS = 15000
COPY_CHUNK = 64 * 1024
FIXED_COMMAND = "feige-codex-control/v1"
CLIENT_EOF = b"\x00FEIGE-CONTROL-EOF-V1\x00"


def _pipe_api_diagnostic(stage, succeeded, error_kind="win32", error_code=None):
    """Emit only fixed pipe API stage names and numeric errors when diagnostics are enabled."""
    if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") != "1":
        return
    if stage not in {"wait_named_pipe", "create_file", "duplicate_read", "duplicate_write",
                     "open_osfhandle_read", "open_osfhandle_write", "fdopen_read", "fdopen_write"}:
        return
    value = {"stage": stage, "ok": bool(succeeded)}
    if not succeeded:
        value["error_kind"] = error_kind if error_kind in {"win32", "errno", "unavailable"} else "unavailable"
        value["error_code"] = error_code if type(error_code) is int and 0 <= error_code <= 0xFFFFFFFF else None
    try:
        import json
        sys.stderr.write("FEIGE_ENTRY_PIPE_API " + json.dumps(value, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _numeric_exception_code(error):
    winerror = getattr(error, "winerror", None)
    if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF:
        return "win32", winerror
    err = getattr(error, "errno", None)
    if type(err) is int and 0 <= err <= 0xFFFFFFFF:
        return "errno", err
    return "unavailable", None


class _DuplexPipe:
    """Separate synchronous read/write handles to avoid per-handle I/O serialization."""
    def __init__(self, reader, writer, peek_handle):
        self.reader, self.writer, self.peek_handle = reader, writer, peek_handle
        self.last_peek_error = 0
        self.not_connected_since = None

    def read(self, size=-1):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.PeekNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        k32.PeekNamedPipe.restype = ctypes.c_int
        available = ctypes.c_uint32()
        if not k32.PeekNamedPipe(self.peek_handle, None, 0, None, ctypes.byref(available), None):
            error = ctypes.get_last_error()
            self.last_peek_error = error
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
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            k32.CloseHandle(ctypes.c_void_p(self.peek_handle))
        except Exception:
            pass


def _connect_pipe():
    if os.name != "nt":
        raise RuntimeError("WINDOWS_PIPE_REQUIRED")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    k32.WaitNamedPipeW.restype = ctypes.c_int
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p]
    k32.CreateFileW.restype = ctypes.c_void_p
    if not k32.WaitNamedPipeW(PIPE_NAME, PIPE_WAIT_MS):
        error = ctypes.get_last_error()
        _pipe_api_diagnostic("wait_named_pipe", False, "win32", error)
        raise RuntimeError("CONTROL_BROKER_UNAVAILABLE")
    _pipe_api_diagnostic("wait_named_pipe", True)
    handle = k32.CreateFileW(PIPE_NAME, 0x80000000 | 0x40000000, 0, None, 3, 0x80, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        _pipe_api_diagnostic("create_file", False, "win32", error)
        raise RuntimeError("CONTROL_BROKER_CONNECT_FAILED_" + str(error))
    _pipe_api_diagnostic("create_file", True)
    import msvcrt
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                                    ctypes.c_int, ctypes.c_uint32]
    k32.DuplicateHandle.restype = ctypes.c_int
    current = k32.GetCurrentProcess()
    read_handle, write_handle = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        for stage, target in (("duplicate_read", ctypes.byref(read_handle)),
                              ("duplicate_write", ctypes.byref(write_handle))):
            if not k32.DuplicateHandle(current, handle, current, target, 0, False, 0x2):
                error = ctypes.get_last_error()
                _pipe_api_diagnostic(stage, False, "win32", error)
                raise RuntimeError("CONTROL_PIPE_DUPLICATE_FAILED")
            _pipe_api_diagnostic(stage, True)
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        read_raw_handle = int(read_handle.value)
        try:
            read_fd = msvcrt.open_osfhandle(read_raw_handle, os.O_RDONLY | os.O_BINARY)
        except Exception as error:
            kind, code = _numeric_exception_code(error)
            _pipe_api_diagnostic("open_osfhandle_read", False, kind, code)
            raise
        _pipe_api_diagnostic("open_osfhandle_read", True)
        read_handle = ctypes.c_void_p()
        try:
            write_fd = msvcrt.open_osfhandle(int(write_handle.value), os.O_WRONLY | os.O_BINARY)
        except Exception as error:
            kind, code = _numeric_exception_code(error)
            _pipe_api_diagnostic("open_osfhandle_write", False, kind, code)
            raise
        _pipe_api_diagnostic("open_osfhandle_write", True)
        write_handle = ctypes.c_void_p()
        try:
            reader = os.fdopen(read_fd, "rb", buffering=0)
        except Exception as error:
            kind, code = _numeric_exception_code(error)
            _pipe_api_diagnostic("fdopen_read", False, kind, code)
            raise
        _pipe_api_diagnostic("fdopen_read", True)
        try:
            writer = os.fdopen(write_fd, "wb", buffering=0)
        except Exception as error:
            kind, code = _numeric_exception_code(error)
            _pipe_api_diagnostic("fdopen_write", False, kind, code)
            raise
        _pipe_api_diagnostic("fdopen_write", True)
        return _DuplexPipe(reader, writer, int(handle))
    except Exception:
        for duplicate in (read_handle, write_handle):
            if duplicate.value:
                k32.CloseHandle(duplicate)
        try:
            k32.CloseHandle(handle)
        except Exception:
            pass
        raise


def _write_all(stream, data):
    view = memoryview(data)
    sent = 0
    while sent < len(view):
        count = stream.write(view[sent:])
        if count is None or count <= 0:
            raise OSError("SHORT_PIPE_WRITE")
        sent += count


def _read_available(stream, limit):
    """Read currently available bytes from buffered SSH stdin without waiting
    for a full 64 KiB chunk. BufferedReader.read(n) may wait for n bytes or EOF;
    JSON-RPC peers intentionally keep stdin open while awaiting each response.
    """
    read1 = getattr(stream, "read1", None)
    return read1(limit) if callable(read1) else stream.read(limit)


def _diagnostic_count(stage, byte_count):
    if os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1":
        import json
        sys.stderr.write("FEIGE_" + stage + " " +
                         json.dumps({"bytes": int(byte_count)}, separators=(",", ":")) + "\n")


def _relay(stdin, stdout, pipe, wall_seconds=900, diagnostic_counts=None):
    deadline = time.monotonic() + wall_seconds
    done = threading.Event()
    errors = []

    def input_worker():
        try:
            while not done.is_set() and time.monotonic() < deadline:
                data = _read_available(stdin, COPY_CHUNK)
                if not data:
                    _write_all(pipe, CLIENT_EOF)
                    pipe.flush()
                    _diagnostic_count("PIPE_CLIENT_EOF_SENT", 1)
                    return
                if diagnostic_counts is not None:
                    diagnostic_counts["ssh_stdin_bytes"] += len(data)
                _diagnostic_count("PIPE_CLIENT_STDIN_READ", len(data))
                _write_all(pipe, data)
                pipe.flush()
                if diagnostic_counts is not None:
                    diagnostic_counts["pipe_write_bytes"] += len(data)
                _diagnostic_count("PIPE_CLIENT_PIPE_WRITE", len(data))
        except Exception:
            if not done.is_set():
                errors.append("PIPE_WRITE_FAILED")
                done.set()

    def output_worker():
        try:
            while not done.is_set() and time.monotonic() < deadline:
                data = pipe.read(COPY_CHUNK)
                if data is None:
                    time.sleep(0.005)
                    continue
                if not data:
                    done.set()
                    return
                if diagnostic_counts is not None:
                    diagnostic_counts["pipe_read_bytes"] += len(data)
                _diagnostic_count("PIPE_CLIENT_PIPE_READ", len(data))
                _write_all(stdout, data)
                stdout.flush()
                if diagnostic_counts is not None:
                    diagnostic_counts["ssh_stdout_bytes"] += len(data)
                _diagnostic_count("PIPE_CLIENT_STDOUT_WRITE", len(data))
        except Exception:
            if not done.is_set():
                errors.append("PIPE_READ_FAILED")
                done.set()

    workers = [threading.Thread(target=input_worker, daemon=True),
               threading.Thread(target=output_worker, daemon=True)]
    for worker in workers:
        worker.start()
    while not done.wait(0.1):
        if time.monotonic() >= deadline:
            errors.append("CONTROL_TIMEOUT")
            done.set()
    try:
        pipe.close()
    except Exception:
        pass
    for worker in workers:
        worker.join(timeout=0.5)
    return errors[0] if errors else None


def main() -> int:
    if len(sys.argv) != 1:
        return 64
    if os.environ.get("SSH_ORIGINAL_COMMAND") != FIXED_COMMAND:
        sys.stderr.write("FIXED_COMMAND_REQUIRED\n")
        return 64
    pipe = None
    try:
        pipe = _connect_pipe()
        diagnostic = os.environ.get("FEIGE_CONTROL_DIAGNOSTICS") == "1"
        counts = {"ssh_stdin_bytes": 0, "pipe_write_bytes": 0,
                  "pipe_read_bytes": 0, "ssh_stdout_bytes": 0}
        error = _relay(sys.stdin.buffer, sys.stdout.buffer, pipe,
                       diagnostic_counts=counts if diagnostic else None)
        if diagnostic:
            import json
            sys.stderr.write("FEIGE_PIPE_CLIENT " + json.dumps(counts, separators=(",", ":")) + "\n")
        if error:
            sys.stderr.write(error + "\n")
            return 1
        return 0
    except Exception as error:
        reason = str(error)
        if reason not in {"WINDOWS_PIPE_REQUIRED", "CONTROL_BROKER_UNAVAILABLE",
                          "CONTROL_BROKER_CONNECT_FAILED"}:
            reason = "CONTROL_PIPE_FAILED"
        sys.stderr.write(reason + "\n")
        return 1
    finally:
        if pipe is not None:
            try:
                pipe.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
