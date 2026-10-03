# bitty-execution

Execution supervisor extension crate (landed CTX-0003, independently verified CTX-0004). Core retains PTY/process authority; this crate owns job lifetime, cancellation, process resources and recovery behind the accepted W-132 contract.

Read [AGENTS](AGENTS.md) and [TODO](TODO.md). Prerequisite: W-132 / bitty-terminal-docs CTX-0088, Issue #171. Core retains PTY/process authority; principals, generations, cancellation, cgroups/OOM and recovery require approved contracts.

## Delivery

Local phases CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 correspond to GitHub Issues #4 -> #3 -> #2 -> #1. All four phases are complete: bootstrap, accepted contract, landed supervisor mechanism with tests, and independent verification with Core W-140 parity.
