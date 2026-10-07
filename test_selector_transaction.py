from __future__ import annotations

import json
import hashlib
from pathlib import Path
import uuid

import pytest

from selector_transaction import SelectorTransaction


class FakeOps:
    def __init__(self):
        self.acls = {}
        self.replace_count = 0
        self.fail_before = None
        self.fail_after = None
        self.fail_stage = False

    def read(self, path):
        return path.read_bytes()

    def verify_acl(self, path):
        if path.exists() and path.parent.name == "journals":
            self.acls.setdefault(path, "existing-dacl")
        if not path.exists() or self.acls.get(path) != "existing-dacl":
            raise RuntimeError("ACL_NOT_PRESERVED")

    def write_stage(self, path, payload):
        if self.fail_stage:
            self.fail_stage = False
            raise RuntimeError("INJECT_STAGE_FAILURE")
        path.write_bytes(payload)
        self.acls[path] = "existing-dacl"

    def flush_file(self, path):
        if not path.exists():
            raise RuntimeError("INJECT_FLUSH_MISSING_FILE")

    def flush_directory(self, path):
        if not path.is_dir():
            raise RuntimeError("INJECT_FLUSH_MISSING_DIR")

    def replace(self, target, stage, backup):
        self.replace_count += 1
        if self.fail_before == self.replace_count:
            raise RuntimeError("INJECT_PRE_REPLACE_FAILURE")
        backup.write_bytes(target.read_bytes())
        self.acls[backup] = self.acls[target]
        target.write_bytes(stage.read_bytes())
        # Models ReplaceFileW preserving the target DACL on the new file.
        self.acls[target] = self.acls[target]
        stage.unlink()
        self.acls.pop(stage, None)
        if self.fail_after == self.replace_count:
            raise RuntimeError("INJECT_POST_REPLACE_FAILURE")

    def unlink(self, path):
        path.unlink()
        self.acls.pop(path, None)


def fixture():
    root = Path(__file__).resolve().parent / ".selector-test-fixture" / uuid.uuid4().hex
    control = root / "control"
    journals = control / "journals"
    journals.mkdir(parents=True, exist_ok=True)
    a = control / "a.py"
    receipt = root / "receipt.json"
    a.write_bytes(b"old-a")
    receipt.write_bytes(b"old-r")
    ops = FakeOps()
    ops.acls[a] = ops.acls[receipt] = ops.acls[journals] = "existing-dacl"
    tx = SelectorTransaction(control, journals, ops)
    targets = {"a.py": a, "receipt.json": receipt}
    payloads = {"a.py": b"new-a", "receipt.json": b"new-r"}
    return tx, ops, control, journals, targets, payloads


def unique_journal(journals, label):
    return journals / f"selector-txn-{label}-{uuid.uuid4().hex}.jsonl"


def test_success_leaves_hash_verified_persistent_backups_and_journal():
    tx, ops, control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "success")
    result = tx.apply(targets, payloads, journal)
    assert targets["a.py"].read_bytes() == b"new-a"
    assert targets["receipt.json"].read_bytes() == b"new-r"
    assert all(path.exists() for path in map(Path, result["backups"]))
    assert ops.acls[targets["a.py"]] == ops.acls[targets["receipt.json"]] == "existing-dacl"
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    assert records[-1]["event"] == "COMMITTED"
    prepared = records[0]["manifest"]
    assert all("target" not in item for item in prepared["entries"])


@pytest.mark.parametrize("failure", ["before_second", "after_second"])
def test_replace_failure_rolls_back_all_targets_and_preserves_backup(failure):
    tx, ops, _control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "failure")
    if failure == "before_second":
        ops.fail_before = 2
    else:
        ops.fail_after = 2
    with pytest.raises(RuntimeError, match="INJECT_.*REPLACE_FAILURE"):
        tx.apply(targets, payloads, journal)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"
    assert ops.acls[targets["a.py"]] == ops.acls[targets["receipt.json"]] == "existing-dacl"
    assert any(path.name.startswith("selector-backup-") for path in journals.iterdir())
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    assert records[-1]["event"] == "ROLLBACK_COMPLETE"


def test_stage_failure_has_no_target_changes():
    tx, ops, _control, journals, targets, payloads = fixture()
    ops.fail_stage = True
    with pytest.raises(RuntimeError, match="INJECT_STAGE_FAILURE"):
        tx.apply(targets, payloads, unique_journal(journals, "stage-failure"))
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_recovery_from_crash_boundary_after_replace():
    tx, ops, _control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "crash")
    ops.fail_after = 1
    with pytest.raises(RuntimeError):
        tx.apply(targets, payloads, journal)
    # The injected exception path already recovered; a second recovery is idempotent.
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    manifest = records[0]["manifest"]
    tx.recover(manifest, journal, targets)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_journal_write_failure_after_replace_rolls_back():
    tx, _ops, _control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "journal-failure")
    append = tx._append

    def fail_replaced(path, record):
        if record.get("event") == "REPLACED":
            raise RuntimeError("INJECT_JOURNAL_FAILURE")
        append(path, record)

    tx._append = fail_replaced
    with pytest.raises(RuntimeError, match="INJECT_JOURNAL_FAILURE"):
        tx.apply(targets, payloads, journal)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_hash_binding_callback_failure_rolls_back_before_commit():
    tx, _ops, _control, journals, targets, payloads = fixture()
    with pytest.raises(RuntimeError, match="TRANSACTION_BINDING_CHECK_FAILED"):
        tx.apply(targets, payloads, unique_journal(journals, "binding-failure"),
                 verify_all=lambda: False)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_torn_final_record_recovery_uses_hashes():
    tx, ops, _control, journals, targets, _payloads = fixture()
    journal = journals / f"selector-txn-torn-{uuid.uuid4().hex}.jsonl"
    txid = uuid.uuid4().hex
    backup = journals / f"selector-backup-{txid}-a.py.bak"
    backup.write_bytes(b"old-a")
    ops.acls[backup] = "existing-dacl"
    targets["a.py"].write_bytes(b"new-a")
    entries = [{"name": "a.py", "old_sha256": hashlib.sha256(b"old-a").hexdigest(),
                "new_sha256": hashlib.sha256(b"new-a").hexdigest(), "backup": backup.name},
               {"name": "receipt.json", "old_sha256": hashlib.sha256(b"old-r").hexdigest(),
                "new_sha256": hashlib.sha256(b"new-r").hexdigest(),
                "backup": f"selector-backup-{txid}-receipt.json.bak"}]
    manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": txid,
                "entries": entries}
    journal.write_text(json.dumps({"event": "PREPARED", "manifest": manifest}) + "\n")
    with journal.open("ab") as stream:
        stream.write(b'{"event":"REPLACED"')
    ops.acls[journal] = "existing-dacl"
    tx.recover_existing(targets)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_unexpected_target_hash_fails_closed():
    tx, _ops, _control, journals, targets, payloads = fixture()
    journal = journals / f"selector-txn-unknown-target-{uuid.uuid4().hex}.jsonl"
    # A test fixture with an altered original after staging preflight must abort.
    append = tx._append
    changed = False

    def alter_after_prepare(path, record):
        nonlocal changed
        append(path, record)
        if record.get("event") == "PREPARED" and not changed:
            targets["a.py"].write_bytes(b"unexpected")
            changed = True

    tx._append = alter_after_prepare
    with pytest.raises(RuntimeError, match="TARGET_CHANGED_AFTER_PREFLIGHT|RECOVERY_TARGET_HASH_UNKNOWN"):
        tx.apply(targets, payloads, journal)
