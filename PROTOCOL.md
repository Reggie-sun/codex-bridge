# Restricted parent protocol

Each connection owns one native app-server child process and one ephemeral thread.

## Requests accepted

1. `initialize` with the fixed client identity and the fixed capability set.
2. `initialized` with empty params.
3. `thread/start` with fixed workspace, `sandbox: "read-only"`, `approvalPolicy: "never"`, `ephemeral: true`, and the exact built-in `developerInstructions` string.
4. `turn/start` for the connection-owned thread with one bounded public text task and a unique client message ID.
5. `turn/interrupt` for the connection-owned active turn.

`thread/start.serviceTier` is the sole optional selector: `"default"` or `"fast"`. If absent, the gate inserts `"default"` before forwarding. Other values are rejected. The selected value is a request; the gate does not rewrite the native response. The transport-neutral Linux adapter is covered by fake protocol tests; live selector support remains unverified.

For Codex CLI 0.160.0, official source `codex-rs/protocol/src/config_types.rs` at tag `rust-v0.160.0`, lines 3041–3084, defines the explicit standard request sentinel, maps both `fast` and `priority` to `ServiceTier::Fast`, and serializes that tier as `priority`: [pinned source lines](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/protocol/src/config_types.rs#L3041-L3084). This proves the CLI's canonical name mapping, not that the backend fulfills every Fast request. Separately, an earlier settled Windows handshake requested `fast` and returned `priority`; it submitted no task and started no model turn. The new optional selector has not been installed or runtime-tested.

The gate rejects other methods, account/config operations, shell requests, thread listing/resume, arbitrary cwd/config/provider/permission overrides, nested agents, and approval escalation. Do not broaden these fields or methods without updating both clients and the security review.

## Result settlement

The broker records task consumption before forwarding `turn/start`. A result is settled only when the matching final message and matching `turn/completed` are received. An interrupt acknowledgement does not settle a turn. Unknown outcomes are never replayed automatically.

## Fixed correlated rejections

When a parsed request is rejected before a native response, the gate may return
`{"id":<request-id>,"error":{"code":-32000,"message":"<FIXED_CODE>"}}`.
The envelope contains no exception text, task text, native error payload, or
diagnostic data. The Linux adapter accepts only a matching request ID, this exact
shape, code `-32000`, and a documented fixed code. A rejection is never a
successful result or a completion event. The parent retains its consumed/unknown
attempt record and must not retry the same body with a new ID. If there is no
correlated request ID (for example, transport EOF), the gate sends no fabricated
response; the attempt remains outcome unknown.

Native JSON-RPC errors are converted to fixed `NATIVE_RPC_FAILED` messages and
their native error bodies are not forwarded. The first fixed diagnostic is
retained across later EOF and cleanup failures.

## Limits

The source enforces bounded frames, task text, pending input, output, and wall time. See constants in `windows_control_gate.py`. Fake tests verify protocol rules, not operating-system sandbox enforcement or private-root denial.

## Linux response guard

`LinuxThreadStart` accepts only omitted/default/fast selection and derives cwd
from a privately validated, source-matched v2 receipt. It exposes no arbitrary
request overrides. The existing parent's RPC ID correlation and bounded transport
remain responsible for selecting the `thread/start` result. A missing model,
effort, tier or thread identity blocks progression; fields are not synthesized.
The native tier field is nullable in the pinned [ThreadStartResponse schema](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server-protocol/schema/json/v2/ThreadStartResponse.json).
Explicit null is treated as no selected tier for a standard request; an absent
field is not accepted as null. Fast requires the canonical `priority` response.
These are local acceptance checks, not OS isolation or provider SLA evidence.
