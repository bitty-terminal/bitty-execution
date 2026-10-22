# bitty-execution

Execution supervisor extension crate (landed CTX-0003 in PR #7, independently
verified CTX-0004 on Issue #1). Core retains PTY/process authority; this crate
owns job lifetime, cancellation, process resources and recovery behind the
accepted W-132 contract.

Read [AGENTS](AGENTS.md). Task management lives in CarryCtx. Prerequisite:
W-132 / bitty-terminal-docs CTX-0088, Issue #171 (closed, contract accepted).
Core retains PTY/process authority; principals, generations, cancellation,
cgroups/OOM and recovery require approved contracts.

## Executable component boundary (bitty#2494)

The crate is also the installable `execution` native component. It is a stdio
coprocess in the DIR-030 shape: the host spawns `bitty-execution`, sends
length-prefixed frames on stdin, and reads frames from stdout. stderr carries
diagnostics only. The component wraps the same `JobRegistry` as the linked
library; it carries no installer, no download source, no capability policy,
and no platform discovery.

- Descriptor: [`bitty-component.toml`](bitty-component.toml) — name
  `execution`, version `0.0.1`, protocol `[1, 1]`, executable
  `bitty-execution`.
- Parser: `bitty_execution::component::descriptor` — closed `[component]`
  table, strict `X.Y.Z`, `[a-z][a-z0-9-]{0,31}` name, `bitty-<name>`
  executable, 64 lowercase hex digits, and a `validate_for_install` check
  that refuses the packaging placeholder digest.
- Server: `bitty_execution::component::server` — handshake, request dispatch,
  output streaming, typed terminate, retained-output reads, bounded shutdown.
- Binary: `bitty-execution` (no arguments serves; `--version`;
  `--check-manifest PATH`).

### Wire protocol v1

`frame = length:u32be payload[length]`, `payload = tag:u8 fields...`; integers
are big-endian, strings/bytes/list lengths are `u32be` and bounded. The frame
cap is 256 KiB and is checked from the four-byte header before any payload
read or allocation. Tags are fixed; unknown tags and trailing bytes fail
closed.

| Tag    | Message       | Direction | Fields                                                                                                                                            |
| ------ | ------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0x01` | `Hello`       | host→comp | `min:u16 max:u16 component:str version:str`                                                                                                       |
| `0x02` | `HelloAck`    | comp→host | `protocol:u16 component:str version:str`                                                                                                          |
| `0x10` | `Spawn`       | host→comp | `job:u64 program:str args:list<str> cwd:opt<str> env:u8 envs:list<(str,str)> kind:u8 io:u8 lifetime:u8 hard_ms:u32 idle_ms:u32 retention_ms:u32`  |
| `0x11` | `Terminate`   | host→comp | `job:u64 generation:u64 mode:u8 grace_ms:u32`                                                                                                     |
| `0x12` | `ReadOutput`  | host→comp | `request:u64 job:u64 stream:u8 tail_lines:u32 max_bytes:u32`                                                                                      |
| `0x3F` | `Shutdown`    | host→comp | none                                                                                                                                              |
| `0x20` | `Spawned`     | comp→host | `job:u64 generation:u64`                                                                                                                          |
| `0x21` | `Started`     | comp→host | `job:u64`                                                                                                                                         |
| `0x22` | `Output`      | comp→host | `job:u64 stream:u8 data:bytes`                                                                                                                    |
| `0x24` | `Exit`        | comp→host | `job:u64 outcome:u8 detail:i32 cancel:u8 clock:u8 scope:u8 oom:u8 gap:u8 stdout_total:u64 stdout_evicted:u64 stderr_total:u64 stderr_evicted:u64` |
| `0x25` | `Canceled`    | comp→host | `job:u64 outcome:u8`                                                                                                                              |
| `0x26` | `OutputView`  | comp→host | `request:u64 job:u64 stream:u8 data:bytes total:u64 dropped:u64 truncated:bool lines:u32`                                                         |
| `0x2F` | `Error`       | comp→host | `request:u64 kind:u8 message:str`                                                                                                                 |
| `0x3E` | `ShutdownAck` | comp→host | none                                                                                                                                              |

Properties the implementation enforces:

- **No ambient command surface.** Program, argv, cwd, environment, and
  deadlines appear only inside an explicit `Spawn`. No other message names a
  path, and error messages are bounded static diagnostics that never echo
  argv or paths.
- **PTY stays in Core.** `io = pty` / `kind = interactive` are reserved codes;
  the component refuses them with `Error { kind: unsupported }` because the v1
  protocol has no stdin channel and interactive PTY ownership belongs to the
  terminal primitive.
- **Typed results.** Spawn failures are `Exit { outcome: spawn_failed }`;
  terminate answers are a typed `Canceled` plus the terminal `Exit`; errors
  are typed (`invalid_request`, `budget`, `unsupported`, `unknown_job`,
  `stale_generation`, `protocol`, `internal`). A host cancel is never
  inferred from a signal number.
- **Bounded frames and jobs.** 64 tracked jobs (the shared
  `MAX_TRACKED_EXECUTIONS` ceiling), 16 KiB `Output` chunks, 240 KiB
  `OutputView` payloads, and bounded argv/env fields. Output writes are
  synchronous, so a host that stops reading applies pipe backpressure instead
  of growing an unbounded queue. Finished records stay readable for their
  `retention_ms` (default 60 s); a host spawning high volumes declares a
  shorter retention to free slots, because v1 has no explicit release verb.
- **Ordering.** `Spawned` is always the first frame for a job; output and
  `Exit` are gated on it. `Exit` closes the job in the writer, so a drain that
  outlives the bounded join cannot place bytes after the terminal frame.
- **Clean shutdown.** `Shutdown` or stdin EOF terminates every live job
  through the typed immediate cancel, waits up to 5 s for the supervisor to
  observe the state, writes `ShutdownAck` for an explicit `Shutdown`, and
  exits 0. Protocol violations exit 3.

### Packaging

```bash
just component-package       # build Linux x86_64 and pack dist/x86_64-unknown-linux-gnu.tar.gz
just component-package-test  # package-shape test without cargo, network, or R2
```

`scripts/package-component.sh` builds (or accepts `--binary`) one Rust target
and writes exactly `<target>.tar.gz`, `<target>.tar.gz.sha256`, and
`SHA256SUMS`. The archive contains exactly `bitty-component.toml` (with the
target binary's real digest) and `bitty-execution`
(`bitty-execution.exe` on Windows). It validates the canonical record, the
Cargo version, the target name, and every existing archive's version before
writing, so a mixed-version directory cannot be published. Only Linux x86_64
is built and tested in this task; #2491 owns the per-platform matrix and
catalog rows. No tag is created and nothing is uploaded to R2.

### Verification

```bash
just product                                  # fmt, clippy -D warnings, all tests
cargo test --test component_server --locked   # live protocol lifecycle
cargo test --test component_descriptor --locked
cargo test --test job_output_observer --locked
```

The live suite covers a real `/bin/sh` command (stdout/stderr frames and exit
status), typed cancellation, a hard deadline, retained-output reads, spawn
failure, unknown/stale ids, oversize-frame rejection, and a SIGKILLed
component whose host and already-spawned job survive. Set
`BITTY_EXECUTION_COMPONENT_BIN` to run the same suite against a packed
release binary.

### Remaining for the Core host client

- Resolve/install the descriptor, verify name/version/protocol/executable and
  the streamed SHA-256, and spawn the binary from its version directory.
- Own the handshake deadline, request ids, per-request deadlines, capability
  grants, consent, and safe-mode denial (none live in this component).
- Treat `Error`/EOF/exit-3 as `component_lost`, fail in-flight work, restart
  with the existing backoff policy, and place the component in its own
  process group/session so a component crash can be cleaned up by killing the
  group. A crashed component cannot kill the host, but its live jobs can
  outlive it until the host reaps the group.
- Run parity tests against the linked crate and remove the direct
  `bitty-runtime` dependency after parity.
- Add the remaining target matrix (#2491) and synchronize the canonical docs.

## Host spawn preparation

`JobRegistry::with_spawn_preparer` installs a host-owned `SpawnPreparer` that
runs once per pipe job after the supervisor builds the argv-first,
closed-environment command and before it spawns. The returned guard stays
alive across `Command::spawn`, which is the contract `pre_exec`-based
confinement needs; a preparation error fails the job closed as `SpawnFailed`
with no process created. Core uses this seam to keep its Landlock exec
confinement (CTX-1151) while the supervisor owns job identity and lifetime.
PTY jobs are excluded: interactive PTY ownership stays with the terminal
primitive.

`JobRegistry::with_output_observer` installs the streaming seam the component
uses: every drained stdout/stderr chunk reaches the observer after it enters
the bounded store, without changing store totals or job state.

## Delivery

Local phases CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 correspond to GitHub
Issues #4 -> #3 -> #2 -> #1. CTX-0003 landed the supervisor mechanism with
tests (PR #7, Closes #2) and CTX-0004 completed independent verification
(Issue #1). Bootstrap (CTX-0001, Issue #4) is closed via PR #8;
contract-readiness (CTX-0002, Issue #3) work is closed via the retried PR #10.
Executable-component work is CTX-0010 for bitty#2494.
