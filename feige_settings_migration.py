"""Validate the local legacy workspace pin before adding it to private settings."""
from __future__ import annotations

import re


SCHEMA = "feige-codex-control-private-settings/v1"
LEGACY_FIELDS = {"schema", "workspace", "journal_root"}
BOUND_FIELDS = LEGACY_FIELDS | {"workspace_source_sha256"}


class SettingsMigrationError(ValueError):
    """Fixed diagnostic only; never includes private settings values."""


def bind_workspace_source(settings: dict, receipt_workspace: str,
                          legacy_pin: str, actual_app_sha256: str) -> dict:
    """Add the generic broker's hash after proving the old pin and workspace.

    No workspace or hash value appears in an exception. The caller must compute
    ``actual_app_sha256`` from the existing private workspace's ``app.py``.
    """
    if not isinstance(settings, dict) or set(settings) not in (LEGACY_FIELDS, BOUND_FIELDS):
        raise SettingsMigrationError("SETTINGS_SCHEMA_FIELDS_INVALID")
    if settings.get("schema") != SCHEMA:
        raise SettingsMigrationError("SETTINGS_SCHEMA_INVALID")
    workspace = settings.get("workspace")
    journal_root = settings.get("journal_root")
    if (not isinstance(workspace, str) or not workspace or workspace != receipt_workspace
            or not isinstance(journal_root, str) or not journal_root):
        raise SettingsMigrationError("SETTINGS_BINDING_MISMATCH")
    is_sha = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    if not is_sha(legacy_pin) or not is_sha(actual_app_sha256) or legacy_pin != actual_app_sha256:
        raise SettingsMigrationError("WORKSPACE_SOURCE_PIN_MISMATCH")
    existing = settings.get("workspace_source_sha256")
    if existing is not None and existing != actual_app_sha256:
        raise SettingsMigrationError("EXISTING_WORKSPACE_SOURCE_PIN_MISMATCH")
    migrated = dict(settings)
    migrated["workspace_source_sha256"] = actual_app_sha256
    return migrated
