"""Version-pinned Codex CLI service-tier response mapping."""


_KNOWN_0160_VALUES = {
    "fast": "priority",
    "priority": "priority",
    "flex": "flex",
    "default": "default",
}


def expected_response_tier(cli_version: str, configured_tier: str | None) -> str | None:
    """Resolve only mappings supported by the pinned Codex source version."""
    if not isinstance(configured_tier, str):
        return None
    if cli_version == "0.160.0":
        return _KNOWN_0160_VALUES.get(configured_tier)
    # Without version-matched source evidence, accept only already-canonical IDs.
    if configured_tier in ("priority", "flex", "default"):
        return configured_tier
    return None


def service_tier_matches(values: list[object], cli_version: str,
                         configured_tier: str = "fast") -> bool:
    expected = expected_response_tier(cli_version, configured_tier)
    return expected is not None and bool(values) and all(value == expected for value in values)
