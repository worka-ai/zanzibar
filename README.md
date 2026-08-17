# Zanzibar for Rust

Model application authorization as relationships, then let Anvil answer the
question that matters: **may this subject perform this action on this object?**

`zanzibar` is a typed Rust API for schemas, relationship tuples, consistency,
and permission checks backed by Anvil 0.9.3. It suits applications whose access
rules grow beyond a role column: shared documents, nested teams, delegated
administration, tenant resources, public objects, and other relationship-based
policies.

Anvil remains the durable authority and evaluates permissions server-side. The
crate provides the application-facing model, authenticated connection, token
refresh, exact schema bindings, atomic tuple mutations, and typed results.

## Capabilities

| Capability | Available |
| --- | --- |
| Direct relations and derived permissions | Yes |
| Entity, userset, same-resource, exact, and public subject selectors | Yes |
| Nested userset evaluation | Yes |
| Atomic add/remove batches with idempotent retries | Yes, up to 1,000 mutations |
| Single and ordered batch permission checks | Yes, up to 1,000 checks |
| Latest, at-least, and exact-revision consistency | Yes |
| Filtered, revision-pinned tuple pagination | Yes |
| Automatic client-credential exchange and bearer refresh | Yes |

## Install

```sh
cargo add zanzibar@0.3
cargo add tokio --features macros,rt-multi-thread
```

The adapter targets Anvil 0.9.3. Start Anvil and provision a tenant owner by
following Anvil's [five-minute setup](https://github.com/worka-ai/anvil#your-first-object-in-five-minutes).
That flow gives the application three values:

```sh
export ANVIL_ENDPOINT=http://127.0.0.1:50051
export ANVIL_STORAGE_TENANT=example
export ANVIL_CLIENT_ID=example-client
export ANVIL_CLIENT_SECRET='the-secret-selected-during-provisioning'
```

Use the HTTP endpoint only for loopback development. For networked deployments,
put Anvil behind a TLS terminator and configure its `https://` endpoint before
sending application credentials.

Applications authenticate with the client ID and secret. Anvil exchanges them
for short-lived bearer credentials; `AnvilRebacEngine` refreshes those
credentials before they expire.

## Define, bind, grant, and check

This complete example declares a writable `viewer` relation and a derived
`can_read` permission. It binds the schema to one authorization realm, grants
Alice access, and checks the permission at or after the mutation's revision.

```rust,no_run
use std::collections::BTreeSet;

use zanzibar::anvil::{AnvilRebacConfig, AnvilRebacEngine};
use zanzibar::{
    AuthzScope, CheckRequest, Consistency, MutateTuplesRequest,
    NamespaceDefinition, Object, PermissionRule, RebacEngine,
    RelationDefinition, SchemaBuilder, SchemaId, Subject, SubjectSelector,
    Tuple, TupleUpdate, put_and_bind_schema,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenant = std::env::var("ANVIL_STORAGE_TENANT")?;
    let engine = AnvilRebacEngine::connect(AnvilRebacConfig {
        endpoint: std::env::var("ANVIL_ENDPOINT")?,
        storage_tenant: tenant.clone().into(),
        client_id: std::env::var("ANVIL_CLIENT_ID")?,
        client_secret: std::env::var("ANVIL_CLIENT_SECRET")?,
    })
    .await?;

    let schema = SchemaBuilder::new()
        .namespace(
            "document",
            NamespaceDefinition::new()
                .relation(
                    "viewer",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                            namespace: "user".into(),
                        }]),
                    },
                )
                .relation(
                    "can_read",
                    RelationDefinition::Permission {
                        rules: BTreeSet::from([PermissionRule::Inherit {
                            relation: "viewer".into(),
                        }]),
                    },
                ),
        )
        .build();

    // A realm is an independent authorization graph inside this storage tenant.
    let scope = AuthzScope::new(tenant, "documents");
    put_and_bind_schema(
        &engine,
        &scope,
        SchemaId("document-access".into()),
        schema,
        None,
    )
    .await?;

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let roadmap = Object {
        namespace: "document".into(),
        id: "roadmap".into(),
    };
    let written = engine
        .mutate_tuples(MutateTuplesRequest::new(
            scope.clone(),
            "grant-roadmap-alice-v1",
            vec![TupleUpdate::Add(Tuple {
                object: roadmap.clone(),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )?)
        .await?;

    let decision = engine
        .check(
            &scope,
            CheckRequest {
                subject: alice,
                relation: "can_read".into(),
                object: roadmap,
            },
            Consistency::AtLeast(written.revision),
        )
        .await?;

    assert!(decision.allowed);
    println!("allowed at authorization revision {}", decision.revision.0);
    Ok(())
}
```

The application that performs a realm's first schema binding becomes that
realm's owner. Later calls are authorized by Anvil's Zanzibar policy just like
the data being protected.

## Schemas and relationships

A direct relation accepts stored tuples. Its selectors say which typed subjects
are legal. A permission is derived from direct relations or other permissions:

- `Inherit` includes another relation or permission on the same object.
- `TupleToUserset` follows a related object and evaluates a relation there.
- `AnyUserset` permits subjects such as `group:engineering#member`, enabling
  nested group and delegation models.
- `Public` permits Anvil's reserved anonymous principal as a tuple subject;
  access is granted only when that tuple is written, and protected resources
  remain private by default.

Schemas are immutable and content-addressed by their returned `SchemaRef`.
Publishing identical content is an idempotent replay. Binding uses a generation
check, so schema changes cannot silently overwrite a concurrent update.

## Consistency, batching, and retries

Every tuple mutation and permission decision returns an `AuthzRevision`:

- `Consistency::Latest` evaluates current authoritative state.
- `Consistency::AtLeast(revision)` requires state that includes a known write;
  if the serving state is still behind, Anvil returns `RevisionUnavailable`.
- `Consistency::Exact(revision)` evaluates only that current revision and fails
  if it is no longer retained.

`MutateTuplesRequest` requires a caller-generated operation ID and a non-empty
batch. Reuse an operation ID only when retrying the **same** logical batch; a new
add or remove needs a new ID. Anvil applies up to 1,000 mutations atomically and
returns whether the call was replayed. `check_many` evaluates up to 1,000 checks
at one revision while preserving request order.

Tuple reads are filtered and paginated. A continuation token pins its filters
and revision, preventing a multi-page result from drifting silently.

## Current scope

This release models opaque authorization object IDs. Anvil exact-path object
references are not yet exposed by this crate. Object/subject discovery and
ordered tuple watches are also outside the API; applications can use paged
tuple reads for bounded inspection.

With Anvil 0.9.3, create and bind new custom realms while one cluster node is
active, then expand the cluster. Existing bound realms continue to operate
across the cluster.

## License

Apache-2.0
