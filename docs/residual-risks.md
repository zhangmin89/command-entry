# Residual risks (stage 4, documented — accepted, not mitigated here)

## Accepted risk: no OS-level network isolation

The V2 exec_command route ran inside the Codex sandbox with network denial.
The pure-beta MCP route has no equivalent: business processes started by the
entry child have normal network access. Mitigation is monitoring only during
the observation week (firewall rule watching the server's outbound
connections — watching, not blocking). If exploitation is observed, the
escalation is a policy decision, not a code change.

## Accepted risk: write fence is policy-level only

`working_roots` constrains where operations may declare a `cwd`, but nothing
at the OS level stops a whitelisted program from writing outside those
roots. This is one grade weaker than the lost workspace-write sandbox and is
accepted per plan §2.

## Behavioral definitions (plan 0.1 / 0.4)

- Lock window: FileLocks cover the whole execution inside the entry child,
  identical to V2. Content changes between validation and execution fail the
  bound-file hash checks.
- Torn reads: each `read_text` call is one consistent `open()` snapshot
  (rename-safe); reads spanning concurrent in-place modifications are not
  globally consistent and the metadata says so.

## Accepted property: the stdio channel is serial

The exec server processes MCP requests one at a time over its stdio
connection. A blocking `wait` (up to `wait_budget_seconds`, default 30s)
occupies the connection: any `status` / `cancel` / `read_text` issued on
the SAME connection during that window queues behind it. This is not
mitigated by "the model cannot do anything else while waiting" — concurrent
queries on one connection still queue. Each Codex session spawns its own
server instance, so cross-session work is unaffected. Accepted for now;
revisit only if observation-week data shows real contention.

## binding.json is a deployment artifact

binding.json pins absolute paths and hashes of one machine's file set. It is
NOT source: every machine rebuilds it locally with
`scripts/build_binding.py` after any code/policy change. It is excluded
from git tracking (`git rm --cached` + .gitignore); the local file is kept,
never synced between machines.

## working_roots narrowing (this stage's debt payment)

The deployed policy must narrow `working_roots` from the template's drive
roots to the actual project directories before the observation week.
`read_roots` defaults to the same set and may be tightened independently.
Keep the server, policy, binding, logs and record roots outside every
workspace listed in `working_roots` — the cage keys stay out of the cage.

## AppContainer pre-study conclusion

**Not now.** Revisit only if both conditions hold during the observation
week: (a) outbound-connection monitoring shows business processes actually
reaching the network in ways that matter, and (b) the user judges the
residual risk worth the operational cost. AppContainer would restore a real
network fence but adds deployment complexity (identity/profile handling for
every whitelisted program). Decision deferred until there is data.
