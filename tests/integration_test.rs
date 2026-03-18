use sqlx::PgPool;
use std::sync::atomic::{AtomicI64, Ordering};
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{Object, RebacEngine, Subject, Tuple, TupleUpdate};

static TENANT_COUNTER: AtomicI64 = AtomicI64::new(0);
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

async fn setup_db() -> PgPool {
    INIT_ONCE.call_once(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        // Use nanoseconds to make collisions across separate 'cargo test' runs highly unlikely
        TENANT_COUNTER.store((now % 1_000_000_000_000) as i64, Ordering::SeqCst);
    });

    PgPool::connect("postgresql://worka:worka@localhost:5432/worka")
        .await
        .expect("Failed to connect to db")
}

fn next_tenant_id() -> i64 {
    TENANT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[tokio::test]
async fn test_basic_tuple_read_write() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let tenant_id = next_tenant_id();

    let tuple = Tuple {
        object: Object {
            namespace: "doc".into(),
            id: "1".into(),
        },
        relation: "viewer".into(),
        subject: Subject::Entity(Object {
            namespace: "user".into(),
            id: "alice".into(),
        }),
    };

    engine
        .write_tuples(tenant_id, vec![TupleUpdate::Write(tuple.clone())])
        .await
        .unwrap();

    let tuples = engine
        .read_tuples(
            tenant_id,
            Some(Object {
                namespace: "doc".into(),
                id: "1".into(),
            }),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0], tuple);

    // Delete
    engine
        .write_tuples(tenant_id, vec![TupleUpdate::Delete(tuple)])
        .await
        .unwrap();
    let tuples = engine
        .read_tuples(
            tenant_id,
            Some(Object {
                namespace: "doc".into(),
                id: "1".into(),
            }),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(tuples.len(), 0);
}

#[tokio::test]
async fn test_check_direct() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let tenant_id = next_tenant_id();

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let doc1 = Object {
        namespace: "doc".into(),
        id: "1".into(),
    };

    // Initially no access
    assert!(
        !engine
            .check(tenant_id, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );

    // Grant access
    engine
        .write_tuples(
            tenant_id,
            vec![TupleUpdate::Write(Tuple {
                object: doc1.clone(),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    // Now has access
    assert!(
        engine
            .check(tenant_id, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_check_userset_recursive() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let tenant_id = next_tenant_id();

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let group_a = Object {
        namespace: "group".into(),
        id: "a".into(),
    };
    let doc1 = Object {
        namespace: "doc".into(),
        id: "1".into(),
    };

    // Group A members are viewers of Doc 1
    engine
        .write_tuples(
            tenant_id,
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
            .check(tenant_id, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );

    // Alice becomes member of Group A
    engine
        .write_tuples(
            tenant_id,
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
            .check(tenant_id, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_list_objects_and_subjects() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let tenant_id = next_tenant_id();

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let doc1 = Object {
        namespace: "doc".into(),
        id: "1".into(),
    };
    let doc2 = Object {
        namespace: "doc".into(),
        id: "2".into(),
    };

    engine
        .write_tuples(
            tenant_id,
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
        .list_objects(tenant_id, &alice, "viewer", "doc")
        .await
        .unwrap();
    objects.sort();
    assert_eq!(objects, vec!["1".to_string(), "2".to_string()]);

    let mut subjects = engine
        .list_subjects(tenant_id, &doc1, "viewer", "user")
        .await
        .unwrap();
    subjects.sort();
    assert_eq!(subjects, vec!["alice".to_string()]);
}

#[tokio::test]
async fn test_multi_tenant_isolation() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);

    let tenant_1 = next_tenant_id();
    let tenant_2 = next_tenant_id();

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let doc1 = Object {
        namespace: "doc".into(),
        id: "1".into(),
    };

    // Tenant 1 grants access
    engine
        .write_tuples(
            tenant_1,
            vec![TupleUpdate::Write(Tuple {
                object: doc1.clone(),
                relation: "viewer".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    // Tenant 1 has access
    assert!(
        engine
            .check(tenant_1, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );

    // Tenant 2 does NOT have access (isolation)
    assert!(
        !engine
            .check(tenant_2, &alice, "viewer", &doc1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_computed_relation_inheritance() {
    let pool = setup_db().await;
    let engine = PostgresRebacEngine::new(pool);
    let tenant_id = next_tenant_id();

    let alice = Subject::Entity(Object {
        namespace: "user".into(),
        id: "alice".into(),
    });
    let agent1 = Object {
        namespace: "agent".into(),
        id: "worka.onboarding".into(),
    };

    // Define Schema: owner inherits into can_invoke
    let mut rules = std::collections::HashMap::new();
    rules.insert(
        "can_invoke".to_string(),
        vec![zanzibar::RelationRule::Inherit("owner".to_string())],
    );

    let schema = zanzibar::SchemaBuilder::new()
        .namespace("agent", zanzibar::NamespaceConfig { rules })
        .build();

    engine.apply_schema(tenant_id, schema).await.unwrap();

    // Grant ONLY 'owner'
    engine
        .write_tuples(
            tenant_id,
            vec![TupleUpdate::Write(Tuple {
                object: agent1.clone(),
                relation: "owner".into(),
                subject: alice.clone(),
            })],
        )
        .await
        .unwrap();

    // Check 'owner' (direct)
    assert!(
        engine
            .check(tenant_id, &alice, "owner", &agent1)
            .await
            .unwrap()
    );

    // Check 'can_invoke' (computed/inherited)
    assert!(
        engine
            .check(tenant_id, &alice, "can_invoke", &agent1)
            .await
            .unwrap()
    );

    // Check 'something_else' (should be false)
    assert!(
        !engine
            .check(tenant_id, &alice, "viewer", &agent1)
            .await
            .unwrap()
    );
}
