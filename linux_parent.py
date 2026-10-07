"""Transport-neutral Linux selector adapter. This module never opens connections.

Use only after a separately authorized, private installation/identity preflight.
The existing parent owns bounded transport, RPC correlation and durable no-replay.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PureWindowsPath

from windows_control_gate import BOUNDARIES, Reject

MODEL = "gpt-6.1-sol"
EFFORT = "high"
CLI_VERSION = "0.160.0"
COMPONENTS = (
    "feige_codex_control_broker.py", "feige_codex_control_entry.py", "windows_control_gate.py",
)


def normalize_service_tier(service_tier: str | None = None) -> str:
    if service_tier is None:
        return "default"
    if not isinstance(service_tier, str) or service_tier not in ("default", "fast"):
        raise Reject("PARENT_SERVICE_TIER_INVALID")
    return service_tier


def verify_selector_receipt(receipt: dict) -> str:
    """Additional source-freshness gate, NOT a substitute for private ACL/auth checks.

    Call before opening a transport. No receipt values appear in error messages.
    A historical receipt cannot authorize the new selector just by being v2.
    """
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "feige-windows-codex-prompt-control-install/v2"
            or receipt.get("status") != "INSTALLED"
            or receipt.get("codex_cli_version") != CLI_VERSION):
        raise Reject("PARENT_INSTALL_INVALID")
    workspace = receipt.get("workspace")
    if (not isinstance(workspace, str) or not PureWindowsPath(workspace).is_absolute()
            or any(ord(c) < 32 for c in workspace) or ".." in PureWindowsPath(workspace).parts):
        raise Reject("PARENT_WORKSPACE_INVALID")
    hashes = receipt.get("source_sha256s")
    if not isinstance(hashes, dict):
        raise Reject("PARENT_SOURCE_BINDINGS_MISSING")
    root = Path(__file__).resolve().parent
    try:
        match = all(hashes.get(name) == hashlib.sha256((root / name).read_bytes()).hexdigest()
                    for name in COMPONENTS)
    except OSError:
        raise Reject("PARENT_PACKAGE_UNAVAILABLE") from None
    if not match:
        raise Reject("PARENT_SELECTOR_NOT_INSTALLED")
    return workspace


class LinuxThreadStart:
    """Only default/fast is caller-selectable; cwd comes from the verified receipt."""
    def __init__(self, receipt: dict, *, service_tier: str | None = None):
        self._tier = normalize_service_tier(service_tier)
        self._workspace = verify_selector_receipt(receipt)
        self._state = "READY"

    def params(self) -> dict:
        """Call once after initialize/initialized on the owned connection.

        Failure/EOF leaves this object consumed. This is NOT a durable attempt
        ledger: the host parent must record consumption before opening transport.
        """
        if self._state != "READY":
            raise Reject("PARENT_THREAD_START_ALREADY_CONSUMED")
        self._state = "OUTCOME_UNKNOWN"
        return {"cwd": self._workspace, "sandbox": "read-only", "approvalPolicy": "never",
                "ephemeral": True, "developerInstructions": BOUNDARIES,
                "serviceTier": self._tier}

    def validate_response(self, result: dict) -> str:
        """Validate a correlated thread/start result without rewriting native data."""
        if self._state != "OUTCOME_UNKNOWN":
            raise Reject("PARENT_THREAD_START_NOT_PENDING")
        # A failed response validation must not be retried with another response.
        self._state = "REJECTED"
        if not isinstance(result, dict):
            raise Reject("PARENT_THREAD_RESPONSE_INVALID")
        policy = result.get("sandbox")
        if (result.get("cwd") != self._workspace or result.get("approvalPolicy") != "never"
                or not isinstance(policy, dict) or policy.get("type") != "readOnly"
                or policy.get("networkAccess") is not False):
            raise Reject("PARENT_NATIVE_GUARD_MISMATCH")
        if result.get("model") != MODEL or result.get("reasoningEffort") != EFFORT:
            raise Reject("PARENT_MODEL_SELECTION_MISMATCH")
        if "serviceTier" not in result:
            raise Reject("PARENT_SERVICE_TIER_UNVERIFIED")
        actual = result["serviceTier"]
        # CLI 0.160.0: fast requests map to priority. Explicit standard routing
        # has no service tier (null); also accept the explicit default sentinel.
        if not (actual == "priority" if self._tier == "fast" else actual in (None, "default")):
            raise Reject("PARENT_SERVICE_TIER_MISMATCH")
        thread = result.get("thread")
        identity = thread.get("id") if isinstance(thread, dict) else None
        if not isinstance(identity, str) or not identity or len(identity) > 256:
            raise Reject("PARENT_THREAD_RESPONSE_INVALID")
        self._state = "VERIFIED"
        return identity
