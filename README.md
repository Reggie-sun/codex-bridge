# Codex Bridge

Codex Bridge is a Windows named-pipe relay and strict app-server JSON-RPC gate intended to pair with an authenticated Linux SSH parent. This repository is a public source package and reference implementation. It is **not a production-ready installation** and does not include a ready-to-enable SSH configuration.

## Current state

- Windows Codex CLI 0.160.0 and the older fixed-entry initialize/thread-start path were observed in a prior settled handshake: requested `fast`, native response `priority`. That run submitted no task and started no model turn. This is old-install evidence, not a test of the new selector.
- This package adds an optional thread-start service-tier selector. The new selector has not been installed on Windows or runtime-tested. `default` is the default request; `fast` is an opt-in request.
- The package suite passes 114 tests; two are skipped (authorized Windows native integration and an omitted private diagnostic module). Windows native child/Job Object tests are not exercised by the fake suite. A prior real named-pipe ACL integration attempt was blocked by Access Denied in the restricted execution environment.
- Native sandbox enforcement, protected-root unreadability, and current Linux-to-Windows cross-machine authentication are not established by these results.

## Design limits

The proxy accepts only `initialize`, `initialized`, `thread/start`, `turn/start`, and `turn/interrupt`. It binds each connection to one ephemeral thread, fixed workspace settings, read-only approval policy, and fixed developer instructions. The task result path is bounded and does not persist raw tool output. The Windows broker uses a local named pipe and the SSH-facing entry accepts one exact forced command.

The broker pins `gpt-6.1-sol` and reasoning effort `high`. `thread/start.serviceTier` accepts exactly `default` or `fast`; omission is normalized to `default`. The native response is passed through without rewriting. Codex CLI 0.160.0 source maps `fast` and `priority` request strings to the same internal `ServiceTier::Fast`, whose canonical response value is `priority`; see the official [config_types.rs implementation](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/protocol/src/config_types.rs#L3041-L3084). This proves the CLI's canonical naming behavior; it does not guarantee the service will fulfill a Fast request.

## Configuration

Copy `settings.example.json` to a private `settings.private.json` beside the broker only after replacing every placeholder. Store the workspace path and journal path in the local configuration; do not commit the private file or journal directory. The `app.py` hash is an explicit public-source binding for the sample code and must be computed for the intended public source tree.

The config template is not an installer. The Windows private installer uses a journaled transaction for source files, settings, and receipt, and retains hash-verified backups. Before migrating settings, it requires the installed sources to match the existing private receipt, the old broker's pinned `app.py` hash to match the exact existing workspace, and the receipt workspace to match the private settings. It then adds only `workspace_source_sha256` and installs the byte-identical public broker. Migration rejects drift and preserves the existing workspace and journal-root values. New journals and transaction stage files accept inherited ACLs only when their parent remains protected and the file has exactly current-user and SYSTEM full-control inherited ACEs. Other objects retain the explicit protected-ACL check; no existing ACL is rewritten. A user-run elevated PowerShell scratch integration verified actual `ReplaceFileW`, the missing-target restore path, and exact ACL matching; the partial-replacement disposition was simulated by removing the scratch target while retaining its bound backup. The production preflight also passed under that user token, and the helper made no production writes or ACL changes. Production installation and private-settings migration remain unperformed.

An incomplete journal whose targets and backups all match the old hashes and exact ACL identities is explicitly marked `RESTORED_STATE_VERIFIED`; later scans revalidate that state. A hash or ACL mismatch stops recovery instead of replaying or silently ignoring the journal.

## Development

Runtime code uses the Python standard library and Windows APIs through `ctypes`. Offline tests use `pytest`:

```powershell
python -m pytest -q
```

The fake tests do not replace verification of Windows ACL behavior, native sandbox boundaries, or cross-machine authentication. Review [PROTOCOL.md](PROTOCOL.md) before adapting a Linux parent.

## Scope

This repository intentionally excludes machine-specific workspace hashes, accounts, SIDs, IP addresses, SSH keys/configuration, private receipts, diagnostics, journals, and business task payloads. The private Windows installation state remains separate from this public package.

## Linux parent integration

`linux_parent.py` is a transport-neutral adapter for the existing authenticated,
bounded Linux parent. It does not open SSH, install Windows files, start a model
turn, or replace the host parent's private-input validation and consumption ledger.
The only selectable option is `service_tier`: omit it for ordinary routing, or use
`"default"` / `"fast"`. Model and effort remain `gpt-6.1-sol` / `high`.

```python
from linux_parent import LinuxThreadStart

# receipt: loaded privately after the existing owner/0600, identity, key, host-pin,
# source restriction, wrapper/evidence and bound-workspace checks. Never log it.
selection = LinuxThreadStart(receipt)  # ordinary; explicit serviceTier="default"
# OR, for a separately authorized connection:
# selection = LinuxThreadStart(receipt, service_tier="fast")

# Only after deployment and live authorization: use the existing parent's durable
# once ledger, fixed SSH command and bounded initialize/initialized exchange.
params = selection.params()
# result = existing_parent._request("thread/start", params)
# owned_thread_id = selection.validate_response(result)
```

Construct the adapter **before opening any transport**. It refuses a v2 receipt
whose broker, entry or gate hashes differ from this checkout, including historical
model-pin receipts. This is a freshness check, not proof of installation or ACLs.
Do not create a receipt from the public build manifest. The `params()` result is
private wire data because it includes the bound workspace; do not print it.
Do not pass arbitrary model/config/provider/cwd/permission options.

Feed only the correlated native `thread/start` result to `validate_response`.
The adapter checks workspace and guards, exact model/effort, thread ID and tier;
it never rewrites native data. Fast requires `priority` on pinned CLI 0.160.0.
Ordinary accepts explicit `null` (no tier) or `default`; a missing field remains
unverified. Neither outcome proves backend service fulfillment. Failed/unknown
validation cannot be retried on the object. The host's durable no-replay ledger,
900s / 16MiB / 1MiB-frame / 64KiB-pending limits, and task settlement stay mandatory.

## Deployment pending

1. On Windows, run the private helper only after its read-only owner/ACL/source
   preflight passes. It fails closed on source, workspace, or receipt drift and
   uses `ReplaceFileW` with flags zero, retained backups, and rollback journal.
   An isolated authorized Windows run has verified ReplaceFileW and missing-target
   restoration on scratch files. The actual installation and private-settings
   migration remain pending.
2. The helper installs the broker, entry, and gate from the source hashes in
   `PUBLIC_BUILD.json`. It transactionally migrates only the private workspace
   hash field after proving it equals the old installed broker pin and the existing
   `app.py` bytes; all other private settings remain unchanged.
3. After an authorized local install/reload, privately deliver the full updated v2
   receipt with exact installed source bindings. Existing Linux/USB receipts are
   not a current-selector deployment proof.
4. Only with separate runtime authorization, verify ordinary/fast native responses
   through the actual entry, with zero turns/tools and no automatic retry. Prior
   successful prompt evidence and all UNKNOWN outcomes remain historical records.

This Linux change did not install, authenticate, handshake, run a model task,
contact another session, or replay any prior task.

