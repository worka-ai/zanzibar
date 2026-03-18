<div align="center">
  <h1>🛡️ Zanzibar-rs</h1>
  <p>
    <strong>A high-performance, Postgres-backed ReBAC (Relationship-Based Access Control) engine in Rust, inspired by Google's Zanzibar paper.</strong>
  </p>
  <p>
    <a href="https://crates.io/crates/zanzibar"><img src="https://img.shields.io/crates/v/zanzibar.svg" alt="Crates.io" /></a>
    <a href="https://docs.rs/zanzibar"><img src="https://img.shields.io/docsrs/zanzibar.svg" alt="Docs.rs" /></a>
    <a href="https://github.com/worka-ai/zanzibar/actions"><img src="https://img.shields.io/github/actions/workflow/status/worka-ai/zanzibar/pr.yml?branch=main" alt="Build Status" /></a>
  </p>
</div>

---

`zanzibar` is an open-source authorization library designed for building enterprise-grade, permissions-aware applications. Instead of hardcoding roles (`admin`, `user`) into your application logic, Zanzibar allows you to define flexible **relationships** between resources and subjects, and recursively resolves permissions at runtime.

Built on `sqlx` and PostgreSQL recursive Common Table Expressions (CTEs), this engine effortlessly scales to millions of relational tuples while maintaining millisecond-level resolution times.

## 🚀 Features

- **Pure ReBAC:** Implement Google Drive, GitHub, or AWS IAM style permissions instantly.
- **Computed & Inherited Relations:** Model complex inheritance (e.g. `Folder` viewers automatically get `Document` viewer access).
- **Postgres Native:** Leverages highly-optimized recursive CTEs. No graph database required.
- **Stateless & Async:** Built on `tokio` and `sqlx`. Drop it into any async Rust web framework (Axum, Actix, etc).
- **Mathematical Correctness:** Hardened via `proptest` graph fuzzing to guarantee loop safety and transitive consistency.

## 📦 Installation

Add `zanzibar` to your `Cargo.toml`:

```toml
[dependencies]
zanzibar = "0.1.0"
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }
```

### Applying the Schema
The crate exports its required Postgres tables as a string constant so you can easily include it in your application's migration runner.

```rust
use sqlx::PgPool;

async fn migrate(pool: &PgPool) {
    sqlx::query(zanzibar::POSTGRES_SCHEMA)
        .execute(pool)
        .await
        .unwrap();
}
```

## 🧠 Core Concepts

Zanzibar uses four primary concepts to determine access:

1.  **Object:** The resource being accessed (e.g., `document:readme.md`).
2.  **Subject:** The entity attempting access. Can be a specific user (`user:alice`) or a group of users (`group:engineering#member`).
3.  **Relation:** The type of connection between the Object and Subject (e.g., `viewer`, `owner`).
4.  **Tuple:** A directed edge in the database establishing a fact: *Subject has Relation to Object*.

---

## 🛠️ Usage & Examples

### 1. Simple Scenario: Direct Access
The most basic usage is granting a user a direct relation to a specific resource.

```rust
use zanzibar::{Object, Subject, Tuple, TupleUpdate, postgres::PostgresRebacEngine, RebacEngine};

// 1. Initialize the engine
let engine = PostgresRebacEngine::new(pool);
let tenant_id = 1;

let doc = Object { namespace: "doc".into(), id: "1".into() };
let alice = Subject::Entity(Object { namespace: "user".into(), id: "alice".into() });

// 2. Write the tuple: Alice is a viewer of doc:1
engine.write_tuples(tenant_id, vec![TupleUpdate::Write(Tuple {
    object: doc.clone(),
    relation: "viewer".into(),
    subject: alice.clone(),
})]).await?;

// 3. Check access
let has_access = engine.check(tenant_id, &alice, "viewer", &doc).await?;
assert!(has_access); // true
```

### 2. Intermediate Scenario: Group Memberships (Usersets)
Instead of adding every user to a document, add a group to the document, and add users to the group.

```rust
let engineering_group = Object { namespace: "group".into(), id: "eng".into() };

// The Engineering group's members are viewers of doc:1
engine.write_tuples(tenant_id, vec![TupleUpdate::Write(Tuple {
    object: doc.clone(),
    relation: "viewer".into(),
    subject: Subject::Userset { 
        object: engineering_group.clone(), 
        relation: "member".into() 
    },
})]).await?;

// Alice is a member of the Engineering group
engine.write_tuples(tenant_id, vec![TupleUpdate::Write(Tuple {
    object: engineering_group,
    relation: "member".into(),
    subject: alice.clone(),
})]).await?;

// Alice is now transitively a viewer of doc:1
let has_access = engine.check(tenant_id, &alice, "viewer", &doc).await?;
assert!(has_access); // true
```

---

### 3. Advanced Scenario: Google Drive (Recommended Typed API)

When building large systems, constructing `Object` and `Subject` structs manually using raw strings is error-prone. **We strongly recommend wrapping the `zanzibar` engine in a strictly typed, domain-specific API.**

Here is how you would implement a Google Drive clone where Documents inherit permissions from their parent Folders, using a strictly typed wrapper.

#### Step 1: Define the Schema
First, register the relational algebra with the engine so it knows how relationships cascade.

```rust
use zanzibar::{SchemaBuilder, NamespaceConfig, RelationRule};
use std::collections::HashMap;

let schema = SchemaBuilder::new()
    .namespace("folder", NamespaceConfig {
        rules: HashMap::from([
            // Folder viewers inherit from parent folder viewers
            ("viewer".to_string(), vec![
                RelationRule::Computed {
                    tuple_relation: "parent".to_string(),
                    target_relation: "viewer".to_string(),
                }
            ]),
        ]),
    })
    .namespace("doc", NamespaceConfig {
        rules: HashMap::from([
            // Doc viewers inherit from parent folder viewers
            ("viewer".to_string(), vec![
                RelationRule::Computed {
                    tuple_relation: "parent".to_string(),
                    target_relation: "viewer".to_string(),
                }
            ]),
        ]),
    })
    .build();

engine.apply_schema(tenant_id, schema).await?;
```

#### Step 2: Build the Typed Wrapper

```rust
pub struct DriveAuth {
    engine: PostgresRebacEngine,
    tenant_id: i64,
}

impl DriveAuth {
    pub async fn add_doc_to_folder(&self, doc_id: &str, folder_id: &str) -> Result<(), RebacError> {
        self.engine.write_tuples(self.tenant_id, vec![TupleUpdate::Write(Tuple {
            object: Object { namespace: "doc".into(), id: doc_id.into() },
            relation: "parent".into(),
            subject: Subject::Entity(Object { namespace: "folder".into(), id: folder_id.into() }),
        })]).await
    }

    pub async fn add_folder_viewer(&self, folder_id: &str, user_id: &str) -> Result<(), RebacError> {
        self.engine.write_tuples(self.tenant_id, vec![TupleUpdate::Write(Tuple {
            object: Object { namespace: "folder".into(), id: folder_id.into() },
            relation: "viewer".into(),
            subject: Subject::Entity(Object { namespace: "user".into(), id: user_id.into() }),
        })]).await
    }

    pub async fn can_view_doc(&self, user_id: &str, doc_id: &str) -> Result<bool, RebacError> {
        let user = Subject::Entity(Object { namespace: "user".into(), id: user_id.into() });
        let doc = Object { namespace: "doc".into(), id: doc_id.into() };
        self.engine.check(self.tenant_id, &user, "viewer", &doc).await
    }
}
```

#### Step 3: Use the Wrapper
Your business logic is now incredibly clean, secure, and type-safe.

```rust
let auth = DriveAuth { engine, tenant_id };

// 1. Add doc_1 inside folder_X
auth.add_doc_to_folder("1", "X").await?;

// 2. Make Alice a viewer of folder_X
auth.add_folder_viewer("X", "alice").await?;

// 3. Alice can now view doc_1 because it is in folder_X!
let can_view = auth.can_view_doc("alice", "1").await?;
assert!(can_view); // true
```

---

## 📈 Performance & Scaling

`zanzibar` includes a high-performance benchmarking suite. Using a local PostgreSQL 16 instance, the engine yields the following p50 latencies:

| Scenario | Tuple Count | Latency (P50) | Description |
| :--- | :--- | :--- | :--- |
| **Micro: Width** | 1,000 | `0.6ms` | Direct hit against a document with 1,000 direct viewers. |
| **Micro: Depth** | 50 Levels | `1.8ms` | Traversal check against 50 deeply nested parent folders. |
| **Enterprise: Load** | **10,000,000** | `331ms` | 100 concurrent workers hammering the DB simultaneously with exhaustive miss queries on 10 million tuples. |

### Enterprise Scaling Roadmap
Relying entirely on PostgreSQL Recursive CTEs works phenomenally up to around ~10 Million rows, at which point the memory overhead of the intermediate join sets (`work_mem`) begins to cause latency spikes. 

For future releases, `zanzibar` plans to incorporate:
1. **Application-Layer Traversal:** Moving graph compute out of Postgres and into asynchronous Rust `tokio` tasks for infinite horizontal scalability.
2. **Reachability Caching:** Integrating Bloom Filters to instantly reject negative lookups without hitting the database.

## 🤝 Contributing
We welcome contributions! Please ensure you run the `proptest` graph fuzzer and the `criterion` benchmarks before submitting a PR.

```bash
# Run property-based correctness fuzzer
cargo test --test proptest_graph

# Run micro-benchmarks
cargo bench

# Run the 10-Million row stress test
cargo run --release --bin stress_test -- --rows 10000000
```
