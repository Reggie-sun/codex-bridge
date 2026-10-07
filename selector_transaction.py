"""Journaled update transaction for the fixed service-tier selector files."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Protocol


class TransactionOps(Protocol):
    def read(self, path: Path) -> bytes: ...
    def create_journal(self, path: Path) -> None: ...
    def write_stage(self, path: Path, payload: bytes) -> None: ...
    def replace(self, target: Path, stage: Path, backup: Path) -> None: ...
    def restore_missing(self, target: Path, backup: Path) -> None: ...
    def verify_acl(self, path: Path) -> None: ...
    def verify_same_acl(self, left: Path, right: Path) -> None: ...
    def flush_file(self, path: Path) -> None: ...
    def flush_directory(self, path: Path) -> None: ...
    def unlink(self, path: Path) -> None: ...


class TransactionRecoveryFailed(RuntimeError):
    """A failed rollback that must leave staged recovery material intact."""
    def __init__(self, message: str, stage: str = "RECOVERY", win32_error: int | None = None):
        super().__init__(message)
        self.stage = stage
        self.win32_error = win32_error


class TransactionJournalAclPreflightFailed(RuntimeError):
    """A new empty journal failed ACL validation before PREPARED or target changes."""
    def __init__(self, reason: str, validation_failure: str):
        super().__init__(reason)
        self.validation_failure = validation_failure


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SelectorTransaction:
    def __init__(self, control_root: Path, journal_root: Path, ops: TransactionOps):
        self.control_root = control_root
        self.journal_root = journal_root
        self.ops = ops

    def _append(self, journal: Path, item: dict) -> None:
        encoded = (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with journal.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self.ops.verify_acl(journal)
        self.ops.flush_directory(journal.parent)

    def recover_existing(self, targets: dict[str, Path]) -> list[str]:
        recovered = []
        for journal in sorted(self.journal_root.glob("selector-txn-*.jsonl")):
            # A failed pre-PREPARED creation can leave an empty file. It carries
            # no WAL data and is preserved; in particular, an elevated creator's
            # token-default owner must not block recovery of bound transactions.
            if journal.stat().st_size == 0:
                continue
            self.ops.verify_acl(journal)
            try:
                raw = self.ops.read(journal).decode("utf-8")
                lines = raw.splitlines(keepends=True)
                if lines and not lines[-1].endswith("\n"):
                    lines.pop()  # A torn final WAL record is resolved from target/backup hashes.
                records = [json.loads(line) for line in lines]
                prepared = next((record["manifest"] for record in records
                                 if record.get("event") == "PREPARED"), None)
                terminal = any(record.get("event") in ("COMMITTED", "ROLLBACK_COMPLETE",
                                                         "RESTORED_STATE_VERIFIED")
                                for record in records)
            except Exception:
                raise RuntimeError("TRANSACTION_JOURNAL_INVALID") from None
            if prepared is None:
                # Targets are never touched until a complete PREPARED record has
                # been flushed. Preserve but ignore a torn/empty pre-prepare WAL.
                continue
            names = [entry.get("name") for entry in prepared.get("entries", [])]
            if (prepared.get("schema") != "feige-selector-transaction/v1"
                    or len(names) != len(targets) or set(names) != set(targets)
                    or len(set(names)) != len(names)
                    or any(Path(entry.get("backup", "")).name != entry.get("backup")
                           or not entry.get("backup", "").startswith(
                               "selector-backup-" + str(prepared.get("transaction_id")) + "-")
                           for entry in prepared.get("entries", []))):
                raise RuntimeError("TRANSACTION_JOURNAL_SCOPE_INVALID")
            if terminal and any(record.get("event") == "RESTORED_STATE_VERIFIED"
                                for record in records):
                try:
                    self._verify_restored_state(prepared, targets)
                except RuntimeError:
                    if not self._committed_state_supersedes(prepared, targets, journal):
                        raise
                continue
            if not terminal:
                if self._is_restored_state(prepared, targets):
                    self._append(journal, {"event": "RESTORED_STATE_VERIFIED",
                                           "transaction_id": prepared["transaction_id"],
                                           "target_count": len(targets)})
                else:
                    self.recover(prepared, journal, targets)
                recovered.append(str(journal))
        return recovered

    def _committed_state_supersedes(self, restored: dict, targets: dict[str, Path],
                                    restored_journal: Path) -> bool:
        """Accept a later committed state only when it starts from this marker's old hashes."""
        restored_entries = restored.get("entries", [])
        restored_old = {entry.get("name"): entry.get("old_sha256")
                        for entry in restored_entries}
        if len(restored_old) != len(targets) or set(restored_old) != set(targets):
            return False
        for candidate in self.journal_root.glob("selector-txn-*.jsonl"):
            if candidate == restored_journal or candidate.stat().st_size == 0:
                continue
            try:
                self.ops.verify_acl(candidate)
                records = [json.loads(line) for line in
                           self.ops.read(candidate).decode("utf-8").splitlines()]
                if not any(record.get("event") == "COMMITTED" for record in records):
                    continue
                manifest = next((record.get("manifest") for record in records
                                 if record.get("event") == "PREPARED"), None)
                entries = manifest.get("entries", []) if isinstance(manifest, dict) else []
                names = [entry.get("name") for entry in entries]
                if (manifest.get("schema") != "feige-selector-transaction/v1"
                        or len(names) != len(targets) or set(names) != set(targets)
                        or len(set(names)) != len(names)):
                    continue
                if {entry["name"]: entry.get("old_sha256") for entry in entries} != restored_old:
                    continue
                valid = True
                for entry in entries:
                    target = targets[entry["name"]]
                    backup_name = entry.get("backup", "")
                    if (Path(backup_name).name != backup_name
                            or not backup_name.startswith(
                                "selector-backup-" + str(manifest.get("transaction_id")) + "-")):
                        valid = False
                        break
                    backup = self.journal_root / backup_name
                    if (not target.is_file() or not backup.is_file()
                            or digest(self.ops.read(target)) != entry.get("new_sha256")
                            or digest(self.ops.read(backup)) != entry.get("old_sha256")):
                        valid = False
                        break
                    self.ops.verify_acl(target)
                    self.ops.verify_acl(backup)
                    self.ops.verify_same_acl(target, backup)
                if valid:
                    return True
            except Exception:
                continue
        return False

    def _verify_restored_state(self, manifest: dict, targets: dict[str, Path]) -> None:
        try:
            verified = self._is_restored_state(manifest, targets)
        except Exception:
            raise RuntimeError("RESTORED_STATE_VERIFICATION_FAILED") from None
        if not verified:
            raise RuntimeError("RESTORED_STATE_VERIFICATION_FAILED")

    def _is_restored_state(self, manifest: dict, targets: dict[str, Path]) -> bool:
        """Recognize a completed prior rollback only from bound old hashes and ACLs."""
        entries = manifest.get("entries", [])
        if len(entries) != len(targets) or {e.get("name") for e in entries} != set(targets):
            return False
        verify_same_acl = getattr(self.ops, "verify_same_acl", None)
        if verify_same_acl is None:
            return False
        for entry in entries:
            target = targets[entry["name"]]
            backup = self.journal_root / entry["backup"]
            if (not target.is_file() or not backup.is_file()
                    or digest(self.ops.read(target)) != entry["old_sha256"]
                    or digest(self.ops.read(backup)) != entry["old_sha256"]):
                return False
            try:
                self.ops.verify_acl(target)
                self.ops.verify_acl(backup)
                verify_same_acl(target, backup)
            except Exception:
                raise RuntimeError("RESTORED_STATE_ACL_VERIFICATION_FAILED") from None
        return True

    def recover(self, manifest: dict, journal: Path, targets: dict[str, Path]) -> None:
        txid = manifest["transaction_id"]
        for entry in reversed(manifest["entries"]):
            target = targets[entry["name"]]
            current = digest(self.ops.read(target)) if target.exists() else None
            if current == entry["old_sha256"]:
                continue
            if current is not None and current != entry["new_sha256"]:
                raise RuntimeError("RECOVERY_TARGET_HASH_UNKNOWN")
            backup = self.journal_root / entry["backup"]
            old_bytes = self.ops.read(backup)
            if digest(old_bytes) != entry["old_sha256"]:
                raise RuntimeError("RECOVERY_BACKUP_HASH_MISMATCH")
            if current is None:
                self.ops.restore_missing(target, backup)
                self.ops.flush_file(target)
                self.ops.flush_directory(target.parent)
                if digest(self.ops.read(target)) != entry["old_sha256"]:
                    raise RuntimeError("ROLLBACK_HASH_MISMATCH")
                self.ops.verify_acl(target)
                self.ops.verify_same_acl(target, backup)
                self._append(journal, {"event": "ROLLED_BACK", "name": entry["name"]})
                continue
            stage = self.control_root / (".selector-restore-" + txid + "-" + entry["name"])
            displaced = self.journal_root / ("selector-displaced-" + txid + "-" + entry["name"])
            self.ops.write_stage(stage, old_bytes)
            self.ops.verify_acl(stage)
            self.ops.replace(target, stage, displaced)
            self.ops.flush_file(target)
            self.ops.flush_file(displaced)
            self.ops.flush_directory(target.parent)
            self.ops.flush_directory(self.journal_root)
            if digest(self.ops.read(target)) != entry["old_sha256"]:
                raise RuntimeError("ROLLBACK_HASH_MISMATCH")
            self.ops.verify_acl(target)
            self.ops.verify_same_acl(target, backup)
            self._append(journal, {"event": "ROLLED_BACK", "name": entry["name"]})
        self._append(journal, {"event": "ROLLBACK_COMPLETE"})

    def apply(self, targets: dict[str, Path], payloads: dict[str, bytes], journal: Path,
              verify_all=None) -> dict:
        if set(targets) != set(payloads) or not targets:
            raise RuntimeError("TRANSACTION_SET_INVALID")
        txid = uuid.uuid4().hex
        entries = []
        stages = {}
        for name, target in targets.items():
            self.ops.verify_acl(target)
            old = self.ops.read(target)
            new = payloads[name]
            entry = {
                "name": name,
                "old_sha256": digest(old),
                "new_sha256": digest(new),
                "backup": "selector-backup-" + txid + "-" + name + ".bak",
                "stage": ".selector-stage-" + txid + "-" + name,
            }
            entries.append(entry)
            stages[name] = self.control_root / entry["stage"]
        manifest = {"schema": "feige-selector-transaction/v1", "transaction_id": txid,
                    "entries": entries}
        self.ops.create_journal(journal)
        try:
            self.ops.verify_acl(journal)
            self.ops.flush_directory(self.journal_root)
        except Exception as exc:
            candidate = exc.args[0] if exc.args else None
            allowed = {
                "TRANSACTION_JOURNAL_PARENT_ACL_INVALID",
                "TRANSACTION_JOURNAL_FILE_ACL_INVALID",
                "JOURNAL_ACL_UNVERIFIED", "JOURNAL_ACL_INVALID",
                "JOURNAL_PATH_INVALID",
            }
            validation_failure = candidate if isinstance(candidate, str) and candidate in allowed \
                else "JOURNAL_ACL_VALIDATION_EXCEPTION"
            reason = (validation_failure if validation_failure.startswith("TRANSACTION_")
                      else "TRANSACTION_JOURNAL_FILE_ACL_INVALID")
            raise TransactionJournalAclPreflightFailed(
                reason, validation_failure) from None
        self._append(journal, {"event": "PREPARED", "manifest": manifest})
        preserve_stages = False
        try:
            for entry in entries:
                name = entry["name"]
                stage = stages[name]
                self.ops.write_stage(stage, payloads[name])
                self.ops.verify_acl(stage)
                if digest(self.ops.read(stage)) != entry["new_sha256"]:
                    raise RuntimeError("STAGE_HASH_MISMATCH")
            for entry in entries:
                target = targets[entry["name"]]
                stage = stages[entry["name"]]
                backup = self.journal_root / entry["backup"]
                if digest(self.ops.read(target)) != entry["old_sha256"]:
                    raise RuntimeError("TARGET_CHANGED_AFTER_PREFLIGHT")
                self.ops.replace(target, stage, backup)
                self.ops.flush_file(target)
                self.ops.flush_file(backup)
                self.ops.flush_directory(target.parent)
                self.ops.flush_directory(self.journal_root)
                self.ops.verify_acl(target)
                self.ops.verify_acl(backup)
                self.ops.verify_same_acl(target, backup)
                if digest(self.ops.read(target)) != entry["new_sha256"]:
                    raise RuntimeError("TARGET_HASH_MISMATCH")
                if digest(self.ops.read(backup)) != entry["old_sha256"]:
                    raise RuntimeError("BACKUP_HASH_MISMATCH")
                self._append(journal, {"event": "REPLACED", "name": entry["name"]})
            if verify_all is not None and not verify_all():
                raise RuntimeError("TRANSACTION_BINDING_CHECK_FAILED")
            self._append(journal, {"event": "COMMITTED"})
            return {"transaction_id": txid, "journal": str(journal),
                    "backups": [str(self.journal_root / e["backup"]) for e in entries],
                    "new_hashes": {e["name"]: e["new_sha256"] for e in entries}}
        except Exception as operation_error:
            # Inspect all targets, including the file whose ReplaceFile call may
            # have completed just before an exception/crash boundary.
            try:
                self.recover(manifest, journal, targets)
            except Exception as recovery_error:
                # A missing/unknown target can mean ReplaceFileW left the
                # replacement under its stage name. Preserve those bytes for
                # an explicitly coordinated recovery; never erase them here.
                preserve_stages = True
                code = getattr(recovery_error, "code", None)
                stage_name = getattr(recovery_error, "stage", "RECOVERY")
                raise TransactionRecoveryFailed(
                    "TRANSACTION_RECOVERY_INCOMPLETE", stage_name, code) from None
            # Keep the original public error type/message while exposing the
            # successfully completed rollback to the installer for safe status.
            try:
                operation_error.transaction_rollback_complete = True
            except Exception:
                pass
            raise operation_error
        finally:
            # Failed rollback may need the staged replacement to restore a
            # missing target. Successful commit/rollback still removes debris.
            if not preserve_stages:
                for stage in stages.values():
                    if stage.exists():
                        self.ops.unlink(stage)
