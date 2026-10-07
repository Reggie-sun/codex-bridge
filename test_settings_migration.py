import copy

import pytest

from feige_settings_migration import bind_workspace_source, SettingsMigrationError


PIN = "a" * 64
BASE = {"schema": "feige-codex-control-private-settings/v1",
        "workspace": r"D:\public\source", "journal_root": r"D:\private\journals"}


def test_migration_adds_only_verified_workspace_hash_and_preserves_existing_fields():
    original = copy.deepcopy(BASE)
    migrated = bind_workspace_source(original, original["workspace"], PIN, PIN)
    assert migrated == {**original, "workspace_source_sha256": PIN}
    assert original == BASE


@pytest.mark.parametrize("receipt_workspace", [r"D:\other", "relative", ""])
def test_migration_rejects_workspace_drift_without_echoing_values(receipt_workspace):
    with pytest.raises(SettingsMigrationError, match="SETTINGS_BINDING_MISMATCH") as err:
        bind_workspace_source(BASE, receipt_workspace, PIN, PIN)
    assert not receipt_workspace or receipt_workspace not in str(err.value)


def test_migration_rejects_stale_or_tampered_legacy_pin():
    with pytest.raises(SettingsMigrationError, match="WORKSPACE_SOURCE_PIN_MISMATCH"):
        bind_workspace_source(BASE, BASE["workspace"], "b" * 64, PIN)


def test_migration_rejects_existing_mismatched_hash_instead_of_overwriting():
    settings = {**BASE, "workspace_source_sha256": "b" * 64}
    with pytest.raises(SettingsMigrationError, match="EXISTING_WORKSPACE_SOURCE_PIN_MISMATCH"):
        bind_workspace_source(settings, settings["workspace"], PIN, PIN)


def test_migration_rejects_unknown_fields_and_invalid_hash_shape():
    with pytest.raises(SettingsMigrationError, match="SETTINGS_SCHEMA_FIELDS_INVALID"):
        bind_workspace_source({**BASE, "admin_override": True}, BASE["workspace"], PIN, PIN)
    with pytest.raises(SettingsMigrationError, match="WORKSPACE_SOURCE_PIN_MISMATCH"):
        bind_workspace_source(BASE, BASE["workspace"], "not-a-hash", PIN)


def test_repeated_migration_is_idempotent_when_existing_hash_matches():
    existing = {**BASE, "workspace_source_sha256": PIN}
    assert bind_workspace_source(existing, existing["workspace"], PIN, PIN) == existing
