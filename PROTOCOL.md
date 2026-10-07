# Restricted parent protocol

Each connection owns one native app-server child process and one ephemeral thread.

## Requests accepted

1. `initialize` with the fixed client identity and the fixed capability set.
2. `initialized` with empty params.
3. `thread/start` with fixed workspace, `sandbox: "read-only"`, `approvalPolicy: "never"`, `ephemeral: true`, and the exact built-in `developerInstructions` string.
4. `turn/start` for the connection-owned thread with one bounded public text task and a unique client message ID.
5. `turn/interrupt` for the connection-owned active turn.

`thread/start.serviceTier` is the sole optional selector: `"default"` or `"fast"`. If absent, the gate inserts `"default"` before forwarding. Other values are rejected. The selected value is a request; the gate does not rewrite the native response. Current Linux parent support has not been verified.

For Codex CLI 0.160.0, official source `codex-rs/protocol/src/config_types.rs` at tag `rust-v0.160.0`, lines 3041–3084, defines the explicit standard request sentinel, maps both `fast` and `priority` to `ServiceTier::Fast`, and serializes that tier as `priority`: [pinned source lines](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/protocol/src/config_types.rs#L3041-L3084). This proves the CLI's canonical name mapping, not that the backend fulfills every Fast request. Separately, an earlier settled Windows handshake requested `fast` and returned `priority`; it submitted no task and started no model turn. The new optional selector has not been installed or runtime-tested.

The gate rejects other methods, account/config operations, shell requests, thread listing/resume, arbitrary cwd/config/provider/permission overrides, nested agents, and approval escalation. Do not broaden these fields or methods without updating both clients and the security review.

## Result settlement

The broker records task consumption before forwarding `turn/start`. A result is settled only when the matching final message and matching `turn/completed` are received. An interrupt acknowledgement does not settle a turn. Unknown outcomes are never replayed automatically.

## Limits

The source enforces bounded frames, task text, pending input, output, and wall time. See constants in `windows_control_gate.py`. Fake tests verify protocol rules, not operating-system sandbox enforcement or private-root denial.
