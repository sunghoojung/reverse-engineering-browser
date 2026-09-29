# Origin Trace Rust backend

This crate is the replacement for the Python Origin Trace control plane. The
current executable serves the application assets and the bounded, read-only
health, event, artifact, and signal-profile APIs. It deliberately does not
proxy unported routes back to Python: an unavailable route returns `501`, so
migration gaps remain visible.

```sh
make origin-trace-backend
cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml
```

`make ui` remains on the production Python server until write actions, worker
supervision, Origin Trace projection, and the live CDP state machine pass the
same compatibility fixtures. The native Brave broker and artifact receiver are
not part of this crate.
