# Zanzibar

`zanzibar` provides Worka's storage-neutral relationship and schema types plus
an `AnvilRebacEngine` backed by Anvil's authorization APIs.

Applications define a `Schema`, bind it to an `AuthzScope`, write tuples, and
ask the engine for authorization decisions. Anvil is the durable source of
truth for schemas, bindings, tuples, consistency revisions, and watch streams;
this crate does not maintain a second authorization database.

```rust,no_run
use anvil_storage::AnvilClient;
use zanzibar::anvil::AnvilRebacEngine;

# async fn example() -> anyhow::Result<()> {
let client = AnvilClient::connect("http://127.0.0.1:50051").await?;
let engine = AnvilRebacEngine::new(client);
# let _ = engine;
# Ok(())
# }
```

Real-Anvil integration tests use `ANVIL_E2E_GRPC` and either
`ANVIL_E2E_TOKEN` or `ANVIL_E2E_CLIENT_ID` plus
`ANVIL_E2E_CLIENT_SECRET`.
