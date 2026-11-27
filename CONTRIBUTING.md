# Contributing to GUAP

1. Every crate in `guap` must keep `#![forbid(unsafe_code)]` and compile cleanly offline (`cargo test --workspace --offline` and `cargo clippy --workspace --all-targets --offline -- -D warnings`).
2. All 52 clean-room rules in `guap-e2e --r4-check` must pass with zero violations.
3. Mutating capabilities must never bypass the `ApprovalCard` human sign-off gate.
