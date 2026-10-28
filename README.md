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

The crate also ships the `execution` native component binary (packaged, not
yet installable through Core's shared extension path; see Protocol and
installability below). It is a stdio coprocess in the DIR-030 shape: the host
spawns `bitty-execution`, sends length-prefixed frames on stdin, and reads
frames from stdout. stderr carries
diagnostics only. The component wraps the same `JobRegistry` as the linked
library; it carries no installer, no download source, no capability policy,
and no platform discovery.

- Descriptor: [`bitty-component.toml`](bitty-component.toml) — name
  `execution`, version `0.0.1`, protocol `[2, 2]`, executable
  `bitty-execution`.
- Parser: `bitty_execution::component::descriptor` — closed `[component]`
  table, strict `X.Y.Z`, `[a-z][a-z0-9-]{0,31}` name, `bitty-<name>`
  executable, 64 lowercase hex digits, and a `validate_for_install` check
  that refuses the packaging placeholder digest.
- Server: `bitty_execution::component::server` — handshake, request dispatch,
  output streaming, typed terminate, retained-output reads, bounded shutdown.
- Binary: `bitty-execution` (no arguments serves; `--version`;
  `--check-manifest PATH`).

### Wire protocol v2

`frame = length:u32be payload[length]`, `payload = tag:u8 fields...`; integers
are big-endian, strings/bytes/list lengths are `u32be` and bounded. The frame
cap is 256 KiB and is checked from the four-byte header before any payload
read or allocation. Tags are fixed; unknown tags and trailing bytes fail
closed.

`Error.request` has a v2 correlation contract: `0` is a
connection-level error, a high-bit-set value is a job error and carries the job
id in its remaining bits, and a high-bit-clear non-zero value is a
`ReadOutput` request id. The `job` field remains the stable host job id used
for lifecycle frames. This high-bit namespace is a semantic change from v1;
the descriptor and handshake therefore advertise v2 only. A v1-only host is
refused before work is accepted; the refusal is a v2 error frame whose kind
byte a v1 decoder reads as `component_lost`, not `protocol`, so a v1 host must
treat it as a lost component and never as a usable connection. The Core host
must negotiate v2 and decode the namespace before routing an error.

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
  the component refuses them with `Error { kind: unsupported }` because the
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
  shorter retention to free slots, because v2 has no explicit release verb.
- **Ordering.** `Spawned` is always the first frame for a job; output and
  `Exit` are gated on it. `Exit` closes the job in the writer, so a drain that
  outlives the bounded join cannot place bytes after the terminal frame.
- **Clean shutdown.** `Shutdown` or stdin EOF terminates every live job
  through the typed immediate cancel, waits up to 5 s for the supervisor to
  observe the state, writes `ShutdownAck` for an explicit `Shutdown`, and
  exits 0. Protocol violations exit 3. Shutdown waits at most 5 s for jobs,
  then the monitor join is bounded at 2 s; a monitor still blocked in an
  embedder-supplied writer is detached with its registry, gate, and writer
  references until that write returns or the peer closes the pipe. Registry
  drain joins are bounded at 5 s; a drain still blocked on an inherited output
  pipe is detached with its bounded output-store reference until EOF. A
  descendant that retains a pipe can therefore keep a drain thread alive after
  the leader exits. These are unresolved resource-lifetime risks for embedders;
  close the peer on shutdown and do not treat bounded joins as cancellation.

### Protocol and installability (issue #21)

`execution` speaks its own protocol v2 (above), not the `bitty-network-wire`
v1 ABI used by `net`, `storage`, and `a11y`. The descriptor stays
`protocol = [2, 2]`; declaring `[1, 1]` would be false, and a v1 host is
refused before work is accepted.

The component is therefore **not installable through Core's shared extension
path yet**. Core 0.0.30 contains a v2 client
(`bitty-runtime::execution_component`, protocol range 2..=2, resolving with
`resolve_search_for_protocol(..., 2)`), but the shared install and inventory
path still compares every descriptor with the shared `bitty-network-wire`
`PROTOCOL_VERSION = 1`: `bitty-terminal/src/component.rs` and
`component_seed.rs` refuse `[2, 2]` before staging, and `extension list`
reports `compatible:false`.

What Core needs before a catalog entry can list `execution`:

- select the component protocol per family in the install/ABI path (the
  execution family uses 2) instead of comparing every descriptor with the
  shared v1 constant;
- compute the inventory `compatible` flag with that same per-family protocol;
- record the second protocol family (tags, handshake range, and the
  `Error.request` namespace) in the canonical component-boundary document.

No Core change is made from this repository. The release gate `just protocol`
compares the descriptor with the linked codec and with Core's shared
`bitty-network-wire` ABI **as a pinned snapshot** (`rev = "c8710e0"` in
`Cargo.toml`), not with Core's live `Cargo.lock`. Bump that pin when assessing
a new Core release; the gate then fails if the codec range or the newly pinned
shared ABI moves. A real v1 `Hello` is refused and the process exits 3; a v2
decoder sees `Error { kind: protocol }`, while the pinned v1 decoder reads the
same kind byte as `component_lost` (code 7), not `protocol` (code 6). A v2
`Hello` completes `HelloAck { protocol: 2 }`.

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
just protocol                                 # descriptor/ABI release gate (issue #21)
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

### Core host client status

Core 0.0.30 contains the client at `bitty-runtime::execution_component`
(pinned to this repository's `36404ab`): it resolves with
`resolve_search_for_protocol(..., 2)`, verifies the executable digest, spawns
the binary in its own process group on Unix, owns the handshake/request
deadlines, and decodes the v2 `Error.request` namespace. A v1-only `Hello` is
refused and exits 3, never accepted as a v1 connection; a v1 decoder observes
that refusal as `component_lost` (code 7), so it must not be used against this
component.

Remaining for a release:

- the shared install/inventory ABI gate described above (v1 vs the execution
  family's v2) must select the per-family protocol before `install`/`add` can
  stage this component;
- the remaining target matrix (#2491);
- canonical documentation synchronization for the v2 family.

Core still keeps the linked `JobRegistry` as a fallback; removing the direct
dependency follows rollout and parity. A crashed component cannot kill the
host, but its live jobs can outlive it until the host reaps the process group.

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
