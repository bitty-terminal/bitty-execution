# bitty-execution

Execution supervisor extension crate (landed CTX-0003 in PR #7, independently verified CTX-0004 on Issue #1). Core retains PTY/process authority; this crate owns job lifetime, cancellation, process resources and recovery behind the accepted W-132 contract.

Read [AGENTS](AGENTS.md). Task management lives in CarryCtx. Prerequisite: W-132 / bitty-terminal-docs CTX-0088, Issue #171 (closed, contract accepted). Core retains PTY/process authority; principals, generations, cancellation, cgroups/OOM and recovery require approved contracts.

## Delivery

Local phases CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 correspond to GitHub Issues #4 -> #3 -> #2 -> #1. CTX-0003 landed the supervisor mechanism with tests (PR #7, Closes #2) and CTX-0004 completed independent verification (Issue #1). Bootstrap (CTX-0001, Issue #4) and contract-readiness (CTX-0002, Issue #3) work is present; GitHub closeout is tracked in Issues #4 and #3.
