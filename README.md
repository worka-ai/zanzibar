<div align="center">
  <h1>🛡️ Zanzibar-rs</h1>
  <p>
    <strong>A Rust ReBAC engine inspired by Google's Zanzibar paper, with Postgres and Anvil-backed storage implementations.</strong>
  </p>
  <p>
    <a href="https://crates.io/crates/zanzibar"><img src="https://img.shields.io/crates/v/zanzibar.svg" alt="Crates.io" /></a>
    <a href="https://docs.rs/zanzibar"><img src="https://img.shields.io/docsrs/zanzibar.svg" alt="Docs.rs" /></a>
    <a href="https://github.com/worka-ai/zanzibar/actions"><img src="https://img.shields.io/github/actions/workflow/status/worka-ai/zanzibar/pr.yml?branch=main" alt="Build Status" /></a>
  </p>
</div>

---

`zanzibar` is an authorization library for building relationship-based access control into Rust services. Instead of hardcoding roles into application logic, applications define relationships between subjects and objects, bind those relationships to a schema, and ask the engine to resolve access decisions.

The crate supports:

- Postgres-backed tuple, schema, and realm storage.
- Optional Anvil-backed storage via the `anvil` feature.
- Scoped authorization realms so one storage tenant can safely contain many independent applications, customers, organizations, or systems.
- Computed usersets, tuple-to-userset rewrites, inherited relations, batch checks, object listing, and subject listing.
- Property tests for recursive graph correctness.

## Installation

```toml
[dependencies]
zanzibar = "0.2"
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }

# Optional Anvil backend:
# zanzibar = { version = "0.2", features = ["anvil"] }
```

Run the Postgres migration from the exported schema string:

```rust
use sqlx::PgPool;

async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(zanzibar::POSTGRES_SCHEMA).execute(pool).await?;
    Ok(())
}
```

## Core Model

Zanzibar uses these concepts:

1. `Object`: the resource being protected, such as `doc:roadmap`.
2. `Subject`: the caller or userset, such as `user:alice` or `group:engineering#member`.
3. `Relation`: the relationship being checked, such as `viewer` or `owner`.
4. `Tuple`: a stored fact connecting an object, relation, and subject.
5. `Schema`: the rules that explain how relations inherit or compute from other relations.
6. `AuthzScope`: the isolation boundary for tuples and decisions.

`AuthzScope` is deliberately not just a numeric application tenant id. It is:

```rust
AuthzScope::new("storage-tenant", "authz-realm")
```

The storage tenant identifies the durable backend container. The authz realm identifies the isolated ReBAC universe inside that container. Every tuple write, read, check, list, and watch operation is scoped by `AuthzScope`.

## Basic Usage

```rust
use std::collections::HashMap;
use zanzibar::{
    AuthzScope, NamespaceConfig, Object, RebacEngine, RelationRule, SchemaBuilder,
    SchemaId, Subject, Tuple, TupleUpdate, put_and_bind_schema,
};
use zanzibar::postgres::PostgresRebacEngine;

let engine = PostgresRebacEngine::new(pool);
let scope = AuthzScope::new("prod", "customer-acme");

let schema = SchemaBuilder::new()
    .namespace("doc", NamespaceConfig {
        rules: HashMap::from([
            ("viewer".to_string(), vec![RelationRule::Inherit("editor".to_string())]),
            ("editor".to_string(), vec![]),
        ]),
    })
    .build();

put_and_bind_schema(
    &engine,
    &scope,
    SchemaId("default".to_string()),
    schema,
    None,
)
.await?;

let doc = Object { namespace: "doc".into(), id: "roadmap".into() };
let alice = Subject::Entity(Object { namespace: "user".into(), id: "alice".into() });

engine.write_tuples(&scope, vec![TupleUpdate::Write(Tuple {
    object: doc.clone(),
    relation: "editor".into(),
    subject: alice.clone(),
})]).await?;

let decision = engine.check(&scope, &alice, "viewer", &doc).await?;
assert!(decision.allowed);
```

## Versioned Schemas

`apply_schema` was removed in `0.2`. Schema management is explicit:

1. `put_schema(storage_tenant, schema_id, schema)` stores an immutable schema revision.
2. `bind_schema(scope, schema_ref, expected_generation)` binds a realm to a specific revision.
3. `get_schema(storage_tenant, schema_id, revision)` retrieves a latest or exact revision.
4. `get_schema_binding(scope)` returns the active binding for a realm.

Use `put_and_bind_schema` for the common bootstrap path.

## Anvil Backend

Enable the `anvil` feature and construct an `AnvilRebacEngine` with an `anvil-storage` client:

```rust
use anvil_storage::AnvilClient;
use zanzibar::anvil::AnvilRebacEngine;

let client = AnvilClient::connect_with_bearer("http://127.0.0.1:50051", token).await?;
let engine = AnvilRebacEngine::new(client);
```

The Anvil backend uses the same `RebacEngine` trait as Postgres. The caller must use an `AuthzScope` whose storage tenant matches the authenticated Anvil tenant.

## Testing

Postgres tests use `WORKA_CLOUD_DATABASE_URL` when set:

```bash
WORKA_CLOUD_DATABASE_URL=postgresql://worka:worka@localhost:55432/worka \
  cargo test --no-default-features
```

Anvil backend tests are ignored by default because they require a running Anvil server and token or client credentials:

```bash
ANVIL_E2E_GRPC=http://127.0.0.1:50051 \
ANVIL_E2E_CLIENT_ID=... \
ANVIL_E2E_CLIENT_SECRET=... \
  cargo test --features anvil --test anvil_backend -- --ignored
```
