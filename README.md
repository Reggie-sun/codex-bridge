# Codex Bridge

Codex Bridge is a Windows named-pipe relay and strict app-server JSON-RPC gate intended to pair with an authenticated Linux SSH parent. This repository is a public source package and reference implementation. It is **not a production-ready installation** and does not include a ready-to-enable SSH configuration.

## Current state

- Windows Codex CLI 0.160.0 and the older fixed-entry initialize/thread-start path were observed in a prior settled handshake: requested `fast`, native response `priority`. That run submitted no task and started no model turn. This is old-install evidence, not a test of the new selector.
- This package adds an optional thread-start service-tier selector. The new selector has not been installed on Windows or runtime-tested. `default` is the default request; `fast` is an opt-in request.
- The curated package's offline suite passes 65 tests; two platform/private-helper tests are skipped. A prior real named-pipe ACL integration attempt was blocked by Access Denied in the restricted execution environment.
- Native sandbox enforcement, protected-root unreadability, and current Linux-to-Windows cross-machine authentication are not established by these results.

## Design limits

The proxy accepts only `initialize`, `initialized`, `thread/start`, `turn/start`, and `turn/interrupt`. It binds each connection to one ephemeral thread, fixed workspace settings, read-only approval policy, and fixed developer instructions. The task result path is bounded and does not persist raw tool output. The Windows broker uses a local named pipe and the SSH-facing entry accepts one exact forced command.

The broker pins `gpt-6.1-sol` and reasoning effort `high`. `thread/start.serviceTier` accepts exactly `default` or `fast`; omission is normalized to `default`. The native response is passed through without rewriting. Codex CLI 0.160.0 source maps `fast` and `priority` request strings to the same internal `ServiceTier::Fast`, whose canonical response value is `priority`; see the official [config_types.rs implementation](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/protocol/src/config_types.rs#L3041-L3084). This proves the CLI's canonical naming behavior; it does not guarantee the service will fulfill a Fast request.

## Configuration

Copy `settings.example.json` to a private `settings.private.json` beside the broker only after replacing every placeholder. Store the workspace path and journal path in the local configuration; do not commit the private file or journal directory. The `app.py` hash is an explicit public-source binding for the sample code and must be computed for the intended public source tree.

The config template is not an installer. The Windows private installer must also preserve the existing file ACLs, keep durable backups, and use its recovery journal. Do not use the unfinished local installer until its Windows integration and offline fault-injection tests pass.

## Development

Runtime code uses the Python standard library and Windows APIs through `ctypes`. Offline tests use `pytest`:

```powershell
python -m pytest -q
```

The fake tests do not replace verification of Windows ACL behavior, native sandbox boundaries, or cross-machine authentication. Review [PROTOCOL.md](PROTOCOL.md) before adapting a Linux parent.

## Scope

This repository intentionally excludes machine-specific workspace hashes, accounts, SIDs, IP addresses, SSH keys/configuration, private receipts, diagnostics, journals, and business task payloads. The private Windows installation state remains separate from this public package.

