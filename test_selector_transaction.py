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
        self.partial_move_at = None
        self.restore_missing_denied = False
        self.fail_journal_acl = False
        self.journal_acl_error = "JOURNAL_ACL_REJECTED"
        self.fail_stage = False

    def read(self, path):
        return path.read_bytes()

    def create_journal(self, path):
        with path.open("xb") as stream:
            stream.flush()
        self.acls[path] = "existing-dacl"

    def verify_acl(self, path):
        if self.fail_journal_acl and path.name.startswith("selector-txn-"):
            raise RuntimeError(self.journal_acl_error)
        if path.exists() and path.parent.name == "journals":
            self.acls.setdefault(path, "existing-dacl")
        if not path.exists() or self.acls.get(path) != "existing-dacl":
            raise RuntimeError("ACL_NOT_PRESERVED")

    def verify_same_acl(self, left, right):
        if self.acls.get(left) != self.acls.get(right):
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
        if self.partial_move_at == self.replace_count:
            # ReplaceFileW ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 disposition:
            # old target is at backup, replacement remains at stage, target absent.
            target.unlink()
            self.acls.pop(target, None)
            raise OSError(1177, "simulated")
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

    def restore_missing(self, target, backup):
        if self.restore_missing_denied:
            raise OSError(5, "simulated")
        target.write_bytes(backup.read_bytes())
        self.acls[target] = self.acls[backup]


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


def test_incomplete_transaction_superseded_by_later_verified_commit_is_settled_not_rolled_back():
    tx, ops, _control, journals, targets, payloads = fixture()
    old_bytes = {name: path.read_bytes() for name, path in targets.items()}
    txid = "a" * 32
    entries = []
    for name, target in targets.items():
        backup_name = f"selector-backup-{txid}-{name}.bak"
        entries.append({"name": name, "old_sha256": hashlib.sha256(old_bytes[name]).hexdigest(),
                        "new_sha256": hashlib.sha256(payloads[name]).hexdigest(),
                        "backup": backup_name, "stage": f".selector-stage-{txid}-{name}"})
        backup = journals / backup_name
        backup.write_bytes(old_bytes[name])
        ops.acls[backup] = ops.acls[target]
        target.write_bytes(payloads[name])
    manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": txid,
                "entries": entries}
    incomplete = unique_journal(journals, "a-incomplete")
    tx._append(incomplete, {"event": "PREPARED", "manifest": manifest})
    tx._append(incomplete, {"event": "REPLACED", "name": entries[0]["name"]})

    committed_id = "b" * 32
    committed_entries = []
    for entry in entries:
        backup_name = f"selector-backup-{committed_id}-{entry['name']}.bak"
        backup = journals / backup_name
        backup.write_bytes(old_bytes[entry["name"]])
        ops.acls[backup] = ops.acls[targets[entry["name"]]]
        committed_entries.append({**entry, "backup": backup_name})
    committed = {"schema": "feige-selector-transaction/v1", "transaction_id": committed_id,
                 "entries": committed_entries}
    later = unique_journal(journals, "z-committed")
    tx._append(later, {"event": "PREPARED", "manifest": committed})
    for entry in entries:
        tx._append(later, {"event": "REPLACED", "name": entry["name"]})
    tx._append(later, {"event": "COMMITTED"})

    recovered = tx.recover_existing(targets)
    assert str(incomplete) in recovered
    assert {name: path.read_bytes() for name, path in targets.items()} == payloads
    assert json.loads(incomplete.read_text().splitlines()[-1])["event"] == "SUPERSEDED_BY_COMMITTED"


def test_terminal_transaction_with_different_scope_is_ignored_by_future_full_scan():
    tx, ops, control, journals, targets, payloads = fixture()
    assert tx.apply(targets, payloads, unique_journal(journals, "narrow"))
    extra = control / "extra.py"
    extra.write_bytes(b"extra")
    ops.acls[extra] = ops.acls[targets["a.py"]]
    full_scope = {**targets, "extra.py": extra}
    assert tx.recover_existing(full_scope) == []
    assert targets["a.py"].read_bytes() == payloads["a.py"]
    assert extra.read_bytes() == b"extra"


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
    with pytest.raises(RuntimeError, match="INJECT_STAGE_FAILURE") as error:
        tx.apply(targets, payloads, unique_journal(journals, "stage-failure"))
    assert getattr(error.value, "transaction_rollback_complete", False) is True
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"


def test_journal_owner_acl_failure_stops_before_prepared_or_target_writes():
    tx, ops, _control, journals, targets, payloads = fixture()
    ops.fail_journal_acl = True
    journal = unique_journal(journals, "owner-acl-rejected")
    with pytest.raises(RuntimeError, match="TRANSACTION_JOURNAL_FILE_ACL_INVALID") as error:
        tx.apply(targets, payloads, journal)
    assert error.value.validation_failure == "JOURNAL_ACL_VALIDATION_EXCEPTION"
    assert journal.exists() and journal.read_bytes() == b""
    assert targets["a.py"].read_bytes() == b"old-a"
    assert targets["receipt.json"].read_bytes() == b"old-r"
    assert not list(journals.glob("selector-backup-*.bak"))


def test_journal_parent_acl_failure_is_reported_as_fixed_parent_stage():
    tx, ops, _control, journals, targets, payloads = fixture()
    ops.fail_journal_acl = True
    ops.journal_acl_error = "TRANSACTION_JOURNAL_PARENT_ACL_INVALID"
    journal = unique_journal(journals, "parent-acl-rejected")
    with pytest.raises(RuntimeError, match="TRANSACTION_JOURNAL_PARENT_ACL_INVALID") as error:
        tx.apply(targets, payloads, journal)
    assert error.value.validation_failure == "TRANSACTION_JOURNAL_PARENT_ACL_INVALID"
    assert journal.read_bytes() == b""
    assert targets["a.py"].read_bytes() == b"old-a"


def test_empty_unprepared_journal_is_preserved_and_does_not_block_recovery():
    tx, ops, _control, journals, targets, _payloads = fixture()
    ops.fail_journal_acl = True
    journal = unique_journal(journals, "empty-unprepared")
    journal.write_bytes(b"")
    ops.acls[journal] = "existing-dacl"
    before = journal.read_bytes()
    assert tx.recover_existing(targets) == []
    assert journal.read_bytes() == before == b""
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


def test_replacefile_partial_move_missing_target_is_restored_from_bound_backup():
    tx, ops, _control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "partial-move")
    ops.partial_move_at = 2
    with pytest.raises(OSError, match="simulated"):
        tx.apply(targets, payloads, journal)
    assert targets["receipt.json"].read_bytes() == b"old-r"
    assert targets["a.py"].read_bytes() == b"old-a"
    receipt_backup = next(journals.glob("selector-backup-*-receipt.json.bak"))
    assert receipt_backup.read_bytes() == b"old-r"
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    assert records[-1]["event"] == "ROLLBACK_COMPLETE"


def test_missing_target_restore_access_denied_preserves_stage_and_backups():
    tx, ops, control, journals, targets, payloads = fixture()
    journal = unique_journal(journals, "partial-move-denied")
    ops.partial_move_at = 2
    ops.restore_missing_denied = True
    with pytest.raises(RuntimeError, match="TRANSACTION_RECOVERY_INCOMPLETE"):
        tx.apply(targets, payloads, journal)
    assert not targets["receipt.json"].exists()
    receipt_backup = next(journals.glob("selector-backup-*-receipt.json.bak"))
    assert receipt_backup.read_bytes() == b"old-r"
    stage = next(control.glob(".selector-stage-*-receipt.json"))
    assert stage.read_bytes() == b"new-r"
    assert [json.loads(line) for line in journal.read_text().splitlines()][-1]["event"] != "ROLLBACK_COMPLETE"


def test_real_windows_replacefile_and_missing_target_restore_in_private_scratch():
    if __import__("os").name != "nt":
        pytest.skip("Windows API required")
    installer = pytest.importorskip("install_service_tier_selector_private")
    Win32StageError, WindowsFileOps = installer.Win32StageError, installer.WindowsFileOps
    import shutil

    import os
    root = Path(os.environ.get("TEMP", r"C:\Users\27451\AppData\Local\Temp")) / ("feige-native-api-" + uuid.uuid4().hex)
    root.mkdir(parents=True)

    try:
        journals = root / "journals"
        journals.mkdir()
        target = root / "target.bin"
        stage = root / ".stage.bin"
        seed = journals / "seed.bin"
        backup = journals / "selector-backup-scratch-target.bin"
        seed.write_bytes(b"old-secretless")
        ops = WindowsFileOps(journals)
        # Isolate native file operations from production ACL policy while
        # retaining the same CreateFileW security-descriptor path.
        ops.verify_acl = lambda _path: None
        ops.restore_missing(target, seed)
        assert target.read_bytes() == b"old-secretless"
        target.unlink()

        target.write_bytes(b"old-secretless")
        stage.write_bytes(b"new-secretless")
        try:
            ops.replace(target, stage, backup)
        except Win32StageError as exc:
            if exc.code == 5:
                pytest.skip("execution sandbox denies ReplaceFileW rename on scratch path")
            raise
        assert target.read_bytes() == b"new-secretless"
        assert backup.read_bytes() == b"old-secretless"

        # Model the documented partial disposition after a successful API call.
        target.unlink()
        ops.restore_missing(target, backup)
        assert target.read_bytes() == b"old-secretless"
        assert backup.read_bytes() == b"old-secretless"
    finally:
        shutil.rmtree(root, ignore_errors=True)


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


def test_incomplete_journal_with_all_old_targets_is_marked_restored_not_replayed():
    tx, ops, _control, journals, targets, _payloads = fixture()
    journal = unique_journal(journals, "already-restored")
    txid = uuid.uuid4().hex
    entries = []
    for name, target in targets.items():
        old = target.read_bytes()
        backup_name = f"selector-backup-{txid}-{name}.bak"
        backup = journals / backup_name
        backup.write_bytes(old)
        ops.acls[backup] = ops.acls[target]
        entries.append({"name": name, "old_sha256": hashlib.sha256(old).hexdigest(),
                        "new_sha256": hashlib.sha256(b"new-" + name.encode()).hexdigest(),
                        "backup": backup_name})
    manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": txid,
                "entries": entries}
    journal.write_text(json.dumps({"event": "PREPARED", "manifest": manifest}) + "\n"
                       + json.dumps({"event": "REPLACED", "name": "a.py"}) + "\n")
    ops.acls[journal] = "existing-dacl"

    assert tx.recover_existing(targets) == [str(journal)]
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    assert rows[-1] == {"event": "RESTORED_STATE_VERIFIED", "transaction_id": txid,
                        "target_count": len(targets)}
    assert all(target.read_bytes().startswith(b"old-") for target in targets.values())
    # Subsequent scans verify the explicit marker and leave the old WAL intact.
    before = journal.read_bytes()
    assert tx.recover_existing(targets) == []
    assert journal.read_bytes() == before
    targets["a.py"].write_bytes(b"unexpected")
    with pytest.raises(RuntimeError, match="RESTORED_STATE_VERIFICATION_FAILED"):
        tx.recover_existing(targets)


def test_new_committed_transaction_supersedes_an_older_restored_marker():
    tx, ops, _control, journals, targets, payloads = fixture()
    prior_id = "a" * 32
    prior_entries = []
    current_old = {}
    for name, target in targets.items():
        old = target.read_bytes()
        current_old[name] = old
        backup_name = f"selector-backup-{prior_id}-{name}.bak"
        backup = journals / backup_name
        backup.write_bytes(old)
        ops.acls[backup] = ops.acls[target]
        prior_entries.append({"name": name, "old_sha256": hashlib.sha256(old).hexdigest(),
                              "new_sha256": hashlib.sha256(b"prior-new-" + name.encode()).hexdigest(),
                              "backup": backup_name})
    prior_manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": prior_id,
                      "entries": prior_entries}
    marker = journals / "selector-txn-a-restored-marker.jsonl"
    marker.write_text(json.dumps({"event": "PREPARED", "manifest": prior_manifest}) + "\n"
                      + json.dumps({"event": "RESTORED_STATE_VERIFIED"}) + "\n")
    ops.acls[marker] = "existing-dacl"

    next_id = "b" * 32
    next_entries = []
    for name, target in targets.items():
        backup_name = f"selector-backup-{next_id}-{name}.bak"
        backup = journals / backup_name
        backup.write_bytes(current_old[name])
        ops.acls[backup] = ops.acls[target]
        target.write_bytes(payloads[name])
        next_entries.append({"name": name,
                             "old_sha256": hashlib.sha256(current_old[name]).hexdigest(),
                             "new_sha256": hashlib.sha256(payloads[name]).hexdigest(),
                             "backup": backup_name})
    next_manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": next_id,
                     "entries": next_entries}
    committed = journals / "selector-txn-z-committed.jsonl"
    committed.write_text(json.dumps({"event": "PREPARED", "manifest": next_manifest}) + "\n"
                         + "".join(json.dumps({"event": "REPLACED", "name": e["name"]}) + "\n"
                                  for e in next_entries)
                         + json.dumps({"event": "COMMITTED"}) + "\n")
    ops.acls[committed] = "existing-dacl"

    assert tx.recover_existing(targets) == []
    assert all(target.read_bytes() == payloads[name] for name, target in targets.items())


def test_old_hashes_with_acl_mismatch_are_blocked_without_rollback_record():
    tx, ops, _control, journals, targets, _payloads = fixture()
    journal = unique_journal(journals, "restored-acl-mismatch")
    txid = uuid.uuid4().hex
    entries = []
    for name, target in targets.items():
        old = target.read_bytes()
        backup_name = f"selector-backup-{txid}-{name}.bak"
        backup = journals / backup_name
        backup.write_bytes(old)
        ops.acls[backup] = ops.acls[target]
        entries.append({"name": name, "old_sha256": hashlib.sha256(old).hexdigest(),
                        "new_sha256": hashlib.sha256(b"new-" + name.encode()).hexdigest(),
                        "backup": backup_name})
    manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": txid,
                "entries": entries}
    journal.write_text(json.dumps({"event": "PREPARED", "manifest": manifest}) + "\n")
    ops.acls[journal] = "existing-dacl"
    ops.acls[targets["a.py"]] = "different-dacl"

    with pytest.raises(RuntimeError, match="RESTORED_STATE_ACL_VERIFICATION_FAILED"):
        tx.recover_existing(targets)
    assert targets["a.py"].read_bytes() == b"old-a"
    assert [json.loads(line)["event"] for line in journal.read_text().splitlines()] == ["PREPARED"]


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
    with pytest.raises(RuntimeError, match="TRANSACTION_RECOVERY_INCOMPLETE"):
        tx.apply(targets, payloads, journal)
