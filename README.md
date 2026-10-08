# Codex Bridge

Codex Bridge is a Windows named-pipe relay and strict app-server JSON-RPC gate intended to pair with an authenticated Linux SSH parent. This repository is a public source package and reference implementation. It is **not a production-ready installation** and does not include a ready-to-enable SSH configuration.

## Current state

- Windows Codex CLI 0.160.0 has the fixed service-tier selector and settings-schema correction installed. The two-target transaction updated only the broker and its matching source hash in the private v2 receipt; settings and ACLs were preserved. The receipt binds all installed source hashes, and the workspace source binding remains valid. The earlier five-target transaction and its retained backups were also verified.
- No broker READY result has been verified after the correction, and the selector has not been tested through the Linux-to-Windows path. A prior settled handshake requested `fast` and the native response was `priority`, but it predates this selector installation, submitted no task, and started no model turn.
- The package suite passes 121 tests; three are skipped (Windows-native integration cases unavailable in this public package). A real elevated five-target scratch transaction passed commit, rollback, missing-target restore, and strict ACL comparisons without writing production files. Windows native child/Job Object tests are not exercised by the fake suite.
- Native sandbox enforcement, protected-root unreadability, and current Linux-to-Windows cross-machine authentication are not established by these results.
- The older incomplete five-target journal is fully linked by matching old/new hashes and retained backup ACL evidence to a later five-target commit, followed by the two-target broker repair. It has no explicit supersession marker. This history does not block broker startup, but should be settled before a future full transaction recovery.

## Design limits

The proxy accepts only `initialize`, `initialized`, `thread/start`, `turn/start`, and `turn/interrupt`. It binds each connection to one ephemeral thread, fixed workspace settings, read-only approval policy, and fixed developer instructions. The task result path is bounded and does not persist raw tool output. The Windows broker uses a local named pipe and the SSH-facing entry accepts one exact forced command.

The broker pins `gpt-6.1-sol` and reasoning effort `high`. `thread/start.serviceTier` accepts exactly `default` or `fast`; omission is normalized to `default`. The native response is passed through without rewriting. Codex CLI 0.160.0 source maps `fast` and `priority` request strings to the same internal `ServiceTier::Fast`, whose canonical response value is `priority`; see the official [config_types.rs implementation](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/protocol/src/config_types.rs#L3041-L3084). This proves the CLI's canonical naming behavior; it does not guarantee the service will fulfill a Fast request.

## Configuration

Copy `settings.example.json` to a private `settings.private.json` beside the broker only after replacing every placeholder. Store the workspace path and journal path in the local configuration; do not commit the private file or journal directory. The `app.py` hash is an explicit public-source binding for the sample code and must be computed for the intended public source tree.

The config template is not an installer. The Windows private installer uses a journaled transaction for source files, settings, and receipt, and retains hash-verified backups. Before migrating settings, it requires the installed sources to match the existing private receipt, the old broker's pinned `app.py` hash to match the exact existing workspace, and the receipt workspace to match the private settings. It then adds only `workspace_source_sha256` and installs the byte-identical public broker. Migration rejects drift and preserves the existing workspace and journal-root values. New journals and transaction stage files accept inherited ACLs only when their parent remains protected and the file has exactly current-user and SYSTEM full-control inherited ACEs. The elevated installer supplies the current user's owner SID at `CREATE_NEW` while leaving the DACL to inherit from the parent. The completed Windows transaction was independently checked against the v2 receipt, committed journal, all five targets, retained backups, and exact ACL identities. No model, SSH, or broker restart occurred as part of that install.

An incomplete journal whose targets and backups all match the old hashes and exact ACL identities is explicitly marked `RESTORED_STATE_VERIFIED`; later scans revalidate that state. A hash or ACL mismatch stops recovery instead of replaying or silently ignoring the journal. Empty unprepared journals are preserved and ignored; diagnostic selection follows the newest journal with a valid prepared manifest rather than the most recently modified filename.

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

## Remaining Linux handoff

1. Update Linux Parent to the reviewed public branch and verify the Windows v2
   receipt's three component hashes against this package before enabling selector
   parameters. Do not treat the earlier pre-install handshake as current evidence.
2. After separate runtime authorization, perform one bounded fixed-entry handshake
   and check native `thread/start.serviceTier` responses for `default` and `fast`.
   Do not start a task or retry an unknown result automatically.

The schema correction did not start the broker, authenticate Linux, perform a new
handshake, run a model task, contact another session, or replay a prior task.
