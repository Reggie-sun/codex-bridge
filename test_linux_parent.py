import copy
import hashlib
import json
from pathlib import Path

import pytest

from linux_parent import (COMPONENTS, LinuxThreadStart, normalize_service_tier,
                          parse_fixed_rpc_error, verify_selector_receipt)
from windows_control_gate import ProtocolGate, Reject


def receipt():
    root = Path(__file__).resolve().parent
    return {"schema": "feige-windows-codex-prompt-control-install/v2", "status": "INSTALLED",
            "workspace": r"C:\public-project", "codex_cli_version": "0.160.0",
            "source_sha256s": {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in COMPONENTS}}


def native(tier):
    return {"cwd": receipt()["workspace"], "approvalPolicy": "never",
            "sandbox": {"type": "readOnly", "networkAccess": False},
            "model": "gpt-6.1-sol", "reasoningEffort": "high", "serviceTier": tier,
            "thread": {"id": "owned-thread"}}


@pytest.mark.parametrize("requested,actual", [(None, None), ("default", None), ("default", "default"), ("fast", "priority")])
def test_parent_and_real_gate_roundtrip(requested, actual):
    parent = LinuxThreadStart(receipt(), service_tier=requested)
    gate = ProtocolGate(receipt()["workspace"])
    request = {"id": 2, "method": "thread/start", "params": parent.params()}
    assert set(request["params"]) == {"cwd", "sandbox", "approvalPolicy", "ephemeral", "developerInstructions", "serviceTier"}
    assert request["params"]["serviceTier"] == (requested or "default")
    gate.parent_request(request)
    response = native(actual)
    before = copy.deepcopy(response)
    gate.app_response("thread/start", response)
    assert parent.validate_response(response) == "owned-thread"
    assert response == before
    with pytest.raises(Reject, match="ALREADY_CONSUMED"):
        parent.params()


@pytest.mark.parametrize("value", ["priority", "flex", "FAST", "", False, 0, {}, []])
def test_only_two_request_values(value):
    with pytest.raises(Reject, match="SERVICE_TIER_INVALID"):
        normalize_service_tier(value)


@pytest.mark.parametrize("field,value", [("model", "other"), ("reasoningEffort", "low"),
    ("serviceTier", "fast"), ("serviceTier", None), ("cwd", r"C:\other"),
    ("approvalPolicy", "on-request"), ("sandbox", {"type": "readOnly", "networkAccess": True})])
def test_native_mismatch_never_rewritten_or_retried(field, value):
    parent = LinuxThreadStart(receipt(), service_tier="fast")
    parent.params()
    result = native("priority"); result[field] = value
    before = copy.deepcopy(result)
    with pytest.raises(Reject):
        parent.validate_response(result)
    assert result == before
    with pytest.raises(Reject, match="NOT_PENDING"):
        parent.validate_response(native("priority"))


def test_missing_tier_is_not_null_standard():
    parent = LinuxThreadStart(receipt()); parent.params()
    result = native(None); del result["serviceTier"]
    with pytest.raises(Reject, match="UNVERIFIED"):
        parent.validate_response(result)


def test_standard_does_not_inherit_fast():
    parent = LinuxThreadStart(receipt()); parent.params()
    with pytest.raises(Reject, match="SERVICE_TIER_MISMATCH"):
        parent.validate_response(native("priority"))


@pytest.mark.parametrize("component", COMPONENTS)
def test_stale_or_missing_component_receipt_denied(component):
    value = receipt(); value["source_sha256s"][component] = "0" * 64
    with pytest.raises(Reject, match="SELECTOR_NOT_INSTALLED"):
        LinuxThreadStart(value)
    del value["source_sha256s"][component]
    with pytest.raises(Reject, match="SELECTOR_NOT_INSTALLED"):
        LinuxThreadStart(value)


@pytest.mark.parametrize("field,value", [("schema", "v1"), ("status", "UNVERIFIED"),
    ("codex_cli_version", "0.159.0"), ("workspace", "relative"), ("workspace", "C:\\public\\..\\private")])
def test_receipt_rejected_without_echoing_private_values(field, value):
    data = receipt(); data[field] = value
    with pytest.raises(Reject) as error:
        verify_selector_receipt(data)
    assert str(error.value).startswith("PARENT_")
    assert str(value) not in str(error.value)


@pytest.mark.parametrize("kwarg", ["model", "config", "modelProvider", "cwd", "sandbox", "approvalPolicy"])
def test_no_arbitrary_overrides(kwarg):
    with pytest.raises(TypeError):
        LinuxThreadStart(receipt(), **{kwarg: "override"})


def test_public_build_is_strict_json_and_matches_files():
    root = Path(__file__).resolve().parent
    build = json.loads((root / "PUBLIC_BUILD.json").read_text())
    assert all(hashlib.sha256((root / n).read_bytes()).hexdigest() == h for n, h in build["files"].items())


def test_correlated_fixed_rejection_preserves_no_replay_state():
    parent = LinuxThreadStart(receipt())
    parent.params()
    error = {"id": 9, "error": {"code": -32000, "message": "TASK_ALREADY_CONSUMED"}}
    assert parent.validate_error_response(error, 9) == "TASK_ALREADY_CONSUMED"
    with pytest.raises(Reject, match="ALREADY_CONSUMED"):
        parent.params()
    with pytest.raises(Reject, match="NOT_PENDING"):
        parent.validate_error_response(error, 9)


@pytest.mark.parametrize("message,expected", [
    ({"id": 8, "error": {"code": -32000, "message": "TASK_ALREADY_CONSUMED"}}, 9),
    ({"id": 9, "error": {"code": -32000, "message": "private prompt text"}}, 9),
    ({"id": 9, "error": {"code": -32000, "message": "TASK_ALREADY_CONSUMED", "data": "x"}}, 9),
    ({"id": 9, "error": {"code": -1, "message": "TASK_ALREADY_CONSUMED"}}, 9),
])
def test_malformed_or_unmatched_remote_errors_are_not_echoed(message, expected):
    with pytest.raises(Reject, match="REMOTE_ERROR_INVALID"):
        parse_fixed_rpc_error(message, expected)
