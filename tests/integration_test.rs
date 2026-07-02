use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{
    AuthzScope, BindingGeneration, NamespaceConfig, Object, RebacEngine, RelationRule, Schema,
    SchemaBuilder, SchemaId, Subject, Tuple, TupleUpdate, put_and_bind_schema,
};

mod common;

static COUNTER: AtomicU64 = AtomicU64::new(0);
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

async fn setup_db() -> PgPool {
    INIT_ONCE.call_once(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        COUNTER.store(now % 1_000_000_000_000, Ordering::SeqCst);
    });

    let database_url = std::env::var("WORKA_CLOUD_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://worka:worka@localhost:5432/worka".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to db");
    common::ensure_schema(&pool).await;
    pool
}

fn next_scope() -> AuthzScope {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    AuthzScope::new("postgres-test", format!("realm-{id}"))
}

fn base_schema() -> Schema {
    SchemaBuilder::new()
        .namespace(
            "doc",
            NamespaceConfig {
                rules: HashMap::from([("viewer".to_string(), vec![])]),
            },
        )
        .namespace(
            "group",
            NamespaceConfig {
                rules: HashMap::from([("member".to_string(), vec![])]),
            },
        )
        .build()
}

async fn bind_base_schema(engine: &PostgresRebacEngine, scope: &AuthzScope) {
    put_and_bind_schema(
        engine,
        scope,
        SchemaId("default".to_string()),
        base_schema(),
        None,
    )
    .await
    .unwrap();
}

fn user(id: &str) -> Subject {
    Subject::Entity(Object {
        namespace: "user".into(),
        id: id.into(),
    })
}

fn object(namespace: &str, id: &str) -> Object {
    Object {
        namespace: namespace.into(),
        id: id.into(),
    }
}

#[tokio::test]
async fn test_basic_tuple_read_write() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    bind_base_schema(&engine, &scope).await;

    let tuple = Tuple {
        object: object("doc", "1"),
        relation: "viewer".into(),
        subject: user("alice"),
    };

    engine
        .write_tuples(&scope, vec![TupleUpdate::Write(tuple.clone())])
        .await
        .unwrap();

    let tuples = engine
        .read_tuples(&scope, Some(object("doc", "1")), None, None)
        .await
        .unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0], tuple);

    engine
        .write_tuples(&scope, vec![TupleUpdate::Delete(tuple)])
        .await
        .unwrap();
    let tuples = engine
        .read_tuples(&scope, Some(object("doc", "1")), None, None)
        .await
        .unwrap();
    assert_eq!(tuples.len(), 0);
}

#[tokio::test]
async fn test_check_direct() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    bind_base_schema(&engine, &scope).await;

    let alice = user("alice");
    let doc1 = object("doc", "1");

    assert!(
        !engine
            .check(&scope, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );

    engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: doc1.clone(),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    assert!(
        engine
            .check(&scope, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn test_check_userset_recursive() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    bind_base_schema(&engine, &scope).await;

    let alice = user("alice");
    let group_a = object("group", "a");
    let doc1 = object("doc", "1");

    engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: doc1.clone(),
                relation: "viewer".into(),
                subject: Subject::Userset {
                    object: group_a.clone(),
                    relation: "member".into(),
                },
            })],
        )
        .await
        .unwrap();

    assert!(
        !engine
            .check(&scope, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );

    engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: group_a.clone(),
                relation: "member".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    assert!(
        engine
            .check(&scope, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn test_list_objects_and_subjects() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    bind_base_schema(&engine, &scope).await;

    let alice = user("alice");
    let doc1 = object("doc", "1");
    let doc2 = object("doc", "2");

    engine
        .write_tuples(
            &scope,
            vec![
                TupleUpdate::Write(Tuple {
                    object: doc1.clone(),
                    relation: "viewer".into(),
                    subject: alice.clone(),
                }),
                TupleUpdate::Write(Tuple {
                    object: doc2.clone(),
                    relation: "viewer".into(),
                    subject: alice.clone(),
                }),
            ],
        )
        .await
        .unwrap();

    let mut objects = engine
        .list_objects(&scope, &alice, "viewer", "doc")
        .await
        .unwrap()
        .object_ids;
    objects.sort();
    assert_eq!(objects, vec!["1".to_string(), "2".to_string()]);

    let mut subjects = engine
        .list_subjects(&scope, &doc1, "viewer", "user")
        .await
        .unwrap()
        .subject_ids;
    subjects.sort();
    assert_eq!(subjects, vec!["alice".to_string()]);
}

#[tokio::test]
async fn test_multi_realm_and_storage_tenant_isolation() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope_a = next_scope();
    let scope_b = AuthzScope::new(
        scope_a.anvil_storage_tenant_id.0.clone(),
        format!("{}-other", scope_a.authz_realm_id.0),
    );
    let scope_c = AuthzScope::new("other-storage-tenant", scope_a.authz_realm_id.0.clone());
    bind_base_schema(&engine, &scope_a).await;
    bind_base_schema(&engine, &scope_b).await;
    bind_base_schema(&engine, &scope_c).await;

    let alice = user("alice");
    let doc1 = object("doc", "1");

    engine
        .write_tuples(
            &scope_a,
            vec![TupleUpdate::Write(Tuple {
                object: doc1.clone(),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    assert!(
        engine
            .check(&scope_a, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .check(&scope_b, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .check(&scope_c, &alice, "viewer", &doc1)
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn test_schema_revision_and_binding_generation() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    let schema_id = SchemaId("default".to_string());

    let schema_v1 = base_schema();
    let ref_v1 = engine
        .put_schema(
            &scope.anvil_storage_tenant_id,
            schema_id.clone(),
            schema_v1.clone(),
        )
        .await
        .unwrap();
    let ref_v1_again = engine
        .put_schema(&scope.anvil_storage_tenant_id, schema_id.clone(), schema_v1)
        .await
        .unwrap();
    assert_eq!(ref_v1, ref_v1_again);

    let schema_v2 = SchemaBuilder::new()
        .namespace(
            "doc",
            NamespaceConfig {
                rules: HashMap::from([
                    (
                        "viewer".to_string(),
                        vec![RelationRule::Inherit("editor".to_string())],
                    ),
                    ("editor".to_string(), vec![]),
                ]),
            },
        )
        .namespace(
            "group",
            NamespaceConfig {
                rules: HashMap::from([("member".to_string(), vec![])]),
            },
        )
        .build();
    let ref_v2 = engine
        .put_schema(&scope.anvil_storage_tenant_id, schema_id.clone(), schema_v2)
        .await
        .unwrap();
    assert_ne!(ref_v1.schema_revision, ref_v2.schema_revision);

    let binding1 = engine.bind_schema(&scope, ref_v1, None).await.unwrap();
    assert_eq!(binding1.binding_generation, BindingGeneration(1));
    let stale = engine
        .bind_schema(&scope, ref_v2.clone(), Some(BindingGeneration(1)))
        .await
        .unwrap();
    assert_eq!(stale.binding_generation, BindingGeneration(2));
    let err = engine
        .bind_schema(&scope, ref_v2, Some(BindingGeneration(1)))
        .await
        .expect_err("stale generation must fail");
    assert!(err.to_string().contains("generation conflict"));
}

#[tokio::test]
async fn test_tuple_writes_require_bound_schema_and_known_relation() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();
    let alice = user("alice");

    let err = engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: object("doc", "1"),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .expect_err("no binding must fail");
    assert!(err.to_string().contains("schema binding not found"));

    bind_base_schema(&engine, &scope).await;
    let err = engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: object("doc", "1"),
                relation: "editor".into(),
                subject: alice,
            })],
        )
        .await
        .expect_err("unknown relation must fail");
    assert!(err.to_string().contains("unknown relation"));
}

#[tokio::test]
async fn test_computed_relation_inheritance() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let scope = next_scope();

    let schema = SchemaBuilder::new()
        .namespace(
            "agent",
            NamespaceConfig {
                rules: HashMap::from([
                    (
                        "can_invoke".to_string(),
                        vec![RelationRule::Inherit("owner".to_string())],
                    ),
                    ("owner".to_string(), vec![]),
                ]),
            },
        )
        .build();
    put_and_bind_schema(
        &engine,
        &scope,
        SchemaId("default".to_string()),
        schema,
        None,
    )
    .await
    .unwrap();

    let alice = user("alice");
    let agent1 = object("agent", "worka.onboarding");

    engine
        .write_tuples(
            &scope,
            vec![TupleUpdate::Write(Tuple {
                object: agent1.clone(),
                relation: "owner".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    assert!(
        engine
            .check(&scope, &alice, "owner", &agent1)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine
            .check(&scope, &alice, "can_invoke", &agent1)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .check(&scope, &alice, "viewer", &agent1)
            .await
            .unwrap()
            .allowed
    );
}
