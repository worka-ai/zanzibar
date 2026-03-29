use proptest::prelude::*;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{NamespaceConfig, Object, RebacEngine, SchemaBuilder, Subject, Tuple, TupleUpdate};

mod common;

static TENANT_COUNTER: AtomicI64 = AtomicI64::new(0);
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

async fn setup_db() -> PgPool {
    INIT_ONCE.call_once(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        TENANT_COUNTER.store((now % 1_000_000_000_000) as i64, Ordering::SeqCst);
    });

    let pool = PgPool::connect("postgresql://worka:worka@localhost:5432/worka")
        .await
        .expect("Failed to connect to db");
    common::ensure_schema(&pool).await;
    pool
}

fn next_tenant_id() -> i64 {
    TENANT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Clone)]
enum GeneratedTuple {
    Direct { obj: String, subject: String },        // doc -> user
    Userset { obj: String, group: String },         // doc -> group#member
    GroupMember { group: String, subject: String }, // group -> user
    GroupInclude { group: String, nested_group: String }, // group -> group#member
}

fn graph_strategy(
    num_docs: usize,
    num_groups: usize,
    num_users: usize,
) -> impl Strategy<Value = Vec<GeneratedTuple>> {
    let max_edges = num_docs * num_users + num_groups * num_users + num_groups * num_groups;

    proptest::collection::vec(
        prop_oneof![
            (0..num_docs, 0..num_users).prop_map(|(d, u)| GeneratedTuple::Direct {
                obj: format!("doc_{}", d),
                subject: format!("user_{}", u)
            }),
            (0..num_docs, 0..num_groups).prop_map(|(d, g)| GeneratedTuple::Userset {
                obj: format!("doc_{}", d),
                group: format!("group_{}", g)
            }),
            (0..num_groups, 0..num_users).prop_map(|(g, u)| GeneratedTuple::GroupMember {
                group: format!("group_{}", g),
                subject: format!("user_{}", u)
            }),
            (0..num_groups, 0..num_groups).prop_map(|(g1, g2)| GeneratedTuple::GroupInclude {
                group: format!("group_{}", g1),
                nested_group: format!("group_{}", g2)
            }),
        ],
        0..max_edges.min(50), // generate up to 50 random edges
    )
}

// A pure Rust Oracle that computes reachability using BFS to guarantee termination on cycles
fn check_oracle(tuples: &[GeneratedTuple], doc_id: &str, user_id: &str) -> bool {
    let mut direct_viewers: HashSet<String> = HashSet::new();
    let mut group_viewers: HashSet<String> = HashSet::new(); // groups that have access to doc
    let mut group_members: HashMap<String, HashSet<String>> = HashMap::new(); // group -> direct users
    let mut nested_groups: HashMap<String, HashSet<String>> = HashMap::new(); // group -> direct sub-groups

    for t in tuples {
        match t {
            GeneratedTuple::Direct { obj, subject } if obj == doc_id => {
                direct_viewers.insert(subject.clone());
            }
            GeneratedTuple::Userset { obj, group } if obj == doc_id => {
                group_viewers.insert(group.clone());
            }
            GeneratedTuple::GroupMember { group, subject } => {
                group_members
                    .entry(group.clone())
                    .or_default()
                    .insert(subject.clone());
            }
            GeneratedTuple::GroupInclude {
                group,
                nested_group,
            } => {
                nested_groups
                    .entry(group.clone())
                    .or_default()
                    .insert(nested_group.clone());
            }
            _ => {}
        }
    }

    if direct_viewers.contains(user_id) {
        return true;
    }

    let mut queue: VecDeque<String> = group_viewers.into_iter().collect();
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(g) = queue.pop_front() {
        if visited.contains(&g) {
            continue;
        }
        visited.insert(g.clone());

        // Check direct members
        if let Some(members) = group_members.get(&g) {
            if members.contains(user_id) {
                return true;
            }
        }

        // Enqueue nested groups
        if let Some(nested) = nested_groups.get(&g) {
            for sub_g in nested {
                queue.push_back(sub_g.clone());
            }
        }
    }

    false
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn test_arbitrary_graphs_with_cycles_match_oracle(tuples in graph_strategy(5, 5, 5)) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let pool = setup_db().await;
            let engine = PostgresRebacEngine::new(pool);
            let tenant_id = next_tenant_id();

            // Schema:
            // - Doc can have viewers (inherits from owner, but we'll just test viewers)
            // - Group can have members (Users or other Groups)
            // - Doc viewer can be a Group#member
            let schema = SchemaBuilder::new()
                .namespace("doc", NamespaceConfig {
                    rules: HashMap::from([
                        ("viewer".to_string(), vec![]), // Just a direct relation, subjects can be Userset
                    ]),
                })
                .namespace("group", NamespaceConfig {
                    rules: HashMap::from([
                        ("member".to_string(), vec![]),
                    ]),
                })
                .build();

            engine.apply_schema(tenant_id, schema).await.unwrap();

            let mut updates = Vec::new();
            for t in &tuples {
                let up = match t {
                    GeneratedTuple::Direct { obj, subject } => TupleUpdate::Write(Tuple {
                        object: Object { namespace: "doc".into(), id: obj.clone() },
                        relation: "viewer".into(),
                        subject: Subject::Entity(Object { namespace: "user".into(), id: subject.clone() }),
                    }),
                    GeneratedTuple::Userset { obj, group } => TupleUpdate::Write(Tuple {
                        object: Object { namespace: "doc".into(), id: obj.clone() },
                        relation: "viewer".into(),
                        subject: Subject::Userset {
                            object: Object { namespace: "group".into(), id: group.clone() },
                            relation: "member".into()
                        },
                    }),
                    GeneratedTuple::GroupMember { group, subject } => TupleUpdate::Write(Tuple {
                        object: Object { namespace: "group".into(), id: group.clone() },
                        relation: "member".into(),
                        subject: Subject::Entity(Object { namespace: "user".into(), id: subject.clone() }),
                    }),
                    GeneratedTuple::GroupInclude { group, nested_group } => TupleUpdate::Write(Tuple {
                        object: Object { namespace: "group".into(), id: group.clone() },
                        relation: "member".into(),
                        subject: Subject::Userset {
                            object: Object { namespace: "group".into(), id: nested_group.clone() },
                            relation: "member".into()
                        },
                    }),
                };
                updates.push(up);
            }

            if !updates.is_empty() {
                engine.write_tuples(tenant_id, updates).await.unwrap();
            }

            // Verify all possible (doc, user) combinations against the Oracle
            for d in 0..5 {
                let doc_id = format!("doc_{}", d);
                let doc_obj = Object { namespace: "doc".into(), id: doc_id.clone() };

                for u in 0..5 {
                    let user_id = format!("user_{}", u);
                    let user_sub = Subject::Entity(Object { namespace: "user".into(), id: user_id.clone() });

                    let oracle_answer = check_oracle(&tuples, &doc_id, &user_id);
                    let engine_answer = engine.check(tenant_id, &user_sub, "viewer", &doc_obj).await.unwrap();

                    assert_eq!(
                        oracle_answer,
                        engine_answer,
                        "Mismatch for doc {} user {}\nGraph: {:#?}",
                        doc_id, user_id, tuples
                    );
                }
            }
        });
    }
}
