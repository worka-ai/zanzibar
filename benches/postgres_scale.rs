//! Zanzibar Benchmark Suite
//! 
//! This suite uses `criterion` to measure the statistical performance of the 
//! `zanzibar` authorization engine backed by PostgreSQL.
//!
//! # How it Works
//! `criterion` runs the functions repeatedly to gather statistically significant 
//! samples of execution time. It stores the results in `target/criterion/` 
//! and compares the current run against the previous run to detect performance 
//! regressions or improvements.
//!
//! # Scenarios
//! 1. `deep_hierarchy_50`: Measures recursive CTE performance by checking access 
//!    to a folder nested 50 levels deep.
//! 2. `wide_hierarchy_hit`: Measures join performance by checking access to a 
//!    document with 1,000 direct viewers, where the user *does* have access.
//! 3. `wide_hierarchy_miss`: The worst-case scenario. Checks access for a user 
//!    who does *not* have access to a document with 1,000 direct viewers, 
//!    forcing the DB to do an exhaustive search before returning false.
//!
//! # Output
//! You can view generated HTML graphs of these benchmarks in your browser at:
//! `target/criterion/report/index.html`

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::runtime::Runtime;
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{
    NamespaceConfig, Object, RebacEngine, RelationRule, SchemaBuilder, Subject, Tuple, TupleUpdate,
};

static TENANT_COUNTER: AtomicI64 = AtomicI64::new(1000);
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

async fn setup_db() -> PgPool {
    INIT_ONCE.call_once(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        TENANT_COUNTER.store((now % 1_000_000_000_000) as i64, Ordering::SeqCst);
    });

    PgPool::connect("postgresql://worka:worka@localhost:5432/worka")
        .await
        .expect("Failed to connect to db")
}

fn next_tenant_id() -> i64 {
    TENANT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn benchmark_rebac(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // 1. Setup Data for Deep Hierarchy
    let deep_tenant_id = next_tenant_id();
    let deep_pool = rt.block_on(setup_db());
    let deep_engine = PostgresRebacEngine::new(deep_pool.clone());

    rt.block_on(async {
        let schema = SchemaBuilder::new()
            .namespace(
                "folder",
                NamespaceConfig {
                    rules: HashMap::from([(
                        "viewer".to_string(),
                        vec![RelationRule::Computed {
                            tuple_relation: "parent".to_string(),
                            target_relation: "viewer".to_string(),
                        }],
                    )]),
                },
            )
            .build();
        deep_engine
            .apply_schema(deep_tenant_id, schema)
            .await
            .unwrap();

        let mut updates = Vec::new();
        // 50 deep hierarchy: folder_50 -> folder_49 -> ... -> folder_1 -> folder_0
        for i in 1..=50 {
            updates.push(TupleUpdate::Write(Tuple {
                object: Object {
                    namespace: "folder".into(),
                    id: format!("folder_{}", i),
                },
                relation: "parent".into(),
                subject: Subject::Entity(Object {
                    namespace: "folder".into(),
                    id: format!("folder_{}", i - 1),
                }),
            }));
        }
        // Give alice access to root folder_0
        updates.push(TupleUpdate::Write(Tuple {
            object: Object {
                namespace: "folder".into(),
                id: "folder_0".into(),
            },
            relation: "viewer".into(),
            subject: Subject::Entity(Object {
                namespace: "user".into(),
                id: "alice".into(),
            }),
        }));

        // Chunk inserts to avoid query limits
        for chunk in updates.chunks(10) {
            deep_engine
                .write_tuples(deep_tenant_id, chunk.to_vec())
                .await
                .unwrap();
        }
    });

    // 2. Setup Data for Wide Hierarchy
    let wide_tenant_id = next_tenant_id();
    let wide_pool = rt.block_on(setup_db());
    let wide_engine = PostgresRebacEngine::new(wide_pool.clone());

    rt.block_on(async {
        let schema = SchemaBuilder::new()
            .namespace(
                "doc",
                NamespaceConfig {
                    rules: HashMap::from([
                        (
                            "viewer".to_string(),
                            vec![RelationRule::Inherit("editor".to_string())],
                        ),
                        (
                            "editor".to_string(),
                            vec![RelationRule::Inherit("owner".to_string())],
                        ),
                    ]),
                },
            )
            .build();
        wide_engine
            .apply_schema(wide_tenant_id, schema)
            .await
            .unwrap();

        let mut updates = Vec::new();
        // Give 1000 users direct viewer access
        for i in 0..1000 {
            updates.push(TupleUpdate::Write(Tuple {
                object: Object {
                    namespace: "doc".into(),
                    id: "doc_1".into(),
                },
                relation: "viewer".into(),
                subject: Subject::Entity(Object {
                    namespace: "user".into(),
                    id: format!("user_{}", i),
                }),
            }));
        }
        for chunk in updates.chunks(100) {
            wide_engine
                .write_tuples(wide_tenant_id, chunk.to_vec())
                .await
                .unwrap();
        }
    });

    let mut group = c.benchmark_group("rebac_postgres");

    // Bench: Deep Depth
    group.bench_function("deep_hierarchy_50", |b| {
        b.to_async(&rt).iter(|| async {
            let user = Subject::Entity(Object {
                namespace: "user".into(),
                id: "alice".into(),
            });
            let folder = Object {
                namespace: "folder".into(),
                id: "folder_50".into(),
            };
            let res = deep_engine
                .check(deep_tenant_id, &user, "viewer", &folder)
                .await
                .unwrap();
            assert!(res);
        });
    });

    // Bench: Wide Access (Check access for a user who does have it)
    group.bench_function("wide_hierarchy_hit", |b| {
        b.to_async(&rt).iter(|| async {
            let user = Subject::Entity(Object {
                namespace: "user".into(),
                id: "user_999".into(),
            });
            let doc = Object {
                namespace: "doc".into(),
                id: "doc_1".into(),
            };
            let res = wide_engine
                .check(wide_tenant_id, &user, "viewer", &doc)
                .await
                .unwrap();
            assert!(res);
        });
    });

    // Bench: Wide Access (Check access for a user who DOES NOT have it)
    group.bench_function("wide_hierarchy_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let user = Subject::Entity(Object {
                namespace: "user".into(),
                id: "alice".into(),
            }); // alice isn't in doc_1's 1000 users
            let doc = Object {
                namespace: "doc".into(),
                id: "doc_1".into(),
            };
            let res = wide_engine
                .check(wide_tenant_id, &user, "viewer", &doc)
                .await
                .unwrap();
            assert!(!res);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50).measurement_time(std::time::Duration::from_secs(10));
    targets = benchmark_rebac
);
criterion_main!(benches);
