use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use zanzibar::anvil::{AnvilRebacConfig, AnvilRebacEngine};
use zanzibar::{
    AnvilStorageTenantId, AuthzScope, CheckRequest, Consistency, MutateTuplesRequest,
    NamespaceDefinition, Object, ObjectFilter, PermissionRule, ReadTuplesRequest, RebacEngine,
    RebacError, RelationDefinition, Schema, SchemaBuilder, SchemaId, Subject, SubjectSelector,
    Tuple, TupleFilter, TupleUpdate,
};

static ANVIL_E2E_LOCK: Mutex<()> = Mutex::const_new(());
static UNIQUE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn object(namespace: &str, id: &str) -> Object {
    Object {
        namespace: namespace.to_string(),
        id: id.to_string(),
    }
}

fn user(id: &str) -> Subject {
    Subject::Entity(object("user", id))
}

fn tuple(object_id: &str, relation: &str, subject: Subject) -> Tuple {
    Tuple {
        object: object("document", object_id),
        relation: relation.to_string(),
        subject,
    }
}

fn unique_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{nanos}-{sequence}")
}

fn authorization_schema() -> Schema {
    SchemaBuilder::new()
        .namespace(
            "group",
            NamespaceDefinition::new().relation(
                "member",
                RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                        namespace: "user".into(),
                    }]),
                },
            ),
        )
        .namespace(
            "document",
            NamespaceDefinition::new()
                .relation(
                    "viewer",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([
                            SubjectSelector::AnyObject {
                                namespace: "user".into(),
                            },
                            SubjectSelector::AnyUserset {
                                namespace: "group".into(),
                                relation: "member".into(),
                            },
                        ]),
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
        .build()
}

fn selector_and_traversal_schema() -> Schema {
    SchemaBuilder::new()
        .namespace(
            "folder",
            NamespaceDefinition::new().relation(
                "viewer",
                RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                        namespace: "user".into(),
                    }]),
                },
            ),
        )
        .namespace(
            "document",
            NamespaceDefinition::new()
                .relation(
                    "exact_reader",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([SubjectSelector::Exact(
                            Subject::Entity(object("service", "indexer")),
                        )]),
                    },
                )
                .relation(
                    "self_reader",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([SubjectSelector::SameResourceId {
                            namespace: "account".into(),
                        }]),
                    },
                )
                .relation(
                    "public_reader",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([SubjectSelector::Public]),
                    },
                )
                .relation(
                    "parent",
                    RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                            namespace: "folder".into(),
                        }]),
                    },
                )
                .relation(
                    "via_parent",
                    RelationDefinition::Permission {
                        rules: BTreeSet::from([PermissionRule::TupleToUserset {
                            tuple_relation: "parent".into(),
                            target_relation: "viewer".into(),
                        }]),
                    },
                ),
        )
        .build()
}

async fn engine() -> (AnvilRebacEngine, AnvilStorageTenantId) {
    let endpoint = std::env::var("ANVIL_E2E_GRPC")
        .expect("ANVIL_E2E_GRPC must point to an Anvil 0.8.1 public endpoint");
    let storage_tenant = AnvilStorageTenantId(
        std::env::var("ANVIL_E2E_TENANT").expect("ANVIL_E2E_TENANT must be set"),
    );
    let client_id = std::env::var("ANVIL_E2E_CLIENT_ID").expect("ANVIL_E2E_CLIENT_ID must be set");
    let client_secret =
        std::env::var("ANVIL_E2E_CLIENT_SECRET").expect("ANVIL_E2E_CLIENT_SECRET must be set");

    let engine = AnvilRebacEngine::connect(AnvilRebacConfig {
        endpoint,
        storage_tenant: storage_tenant.clone(),
        client_id,
        client_secret,
    })
    .await
    .expect("connect and exchange Anvil application credentials");
    (engine, storage_tenant)
}

async fn publish_and_bind(
    engine: &AnvilRebacEngine,
    tenant: &AnvilStorageTenantId,
    scope: &AuthzScope,
) {
    let published = engine
        .put_schema(
            tenant,
            SchemaId(unique_id("schema")),
            authorization_schema(),
        )
        .await
        .expect("publish test schema");
    engine
        .bind_schema(scope, published.schema_ref, None)
        .await
        .expect("bind test schema");
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC, ANVIL_E2E_TENANT, ANVIL_E2E_CLIENT_ID and ANVIL_E2E_CLIENT_SECRET"]
async fn schema_lifecycle_and_server_side_checks_use_one_revision() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
    let (engine, tenant) = engine().await;
    let schema = authorization_schema();
    let schema_id = SchemaId(unique_id("schema-lifecycle"));
    let scope = AuthzScope::new(tenant.clone(), unique_id("realm-lifecycle"));

    let published = engine
        .put_schema(&tenant, schema_id.clone(), schema.clone())
        .await
        .expect("publish schema");
    assert!(!published.replayed);

    let replay = engine
        .put_schema(&tenant, schema_id, schema.clone())
        .await
        .expect("replay identical schema publication");
    assert!(replay.replayed);
    assert_eq!(replay.schema_ref, published.schema_ref);

    let (loaded_ref, loaded_schema) = engine
        .get_schema(&tenant, &published.schema_ref)
        .await
        .expect("load the exact immutable schema");
    assert_eq!(loaded_ref, published.schema_ref);
    assert_eq!(loaded_schema, schema);

    let bound = engine
        .bind_schema(&scope, published.schema_ref.clone(), None)
        .await
        .expect("bind schema to a new realm");
    let loaded_binding = engine
        .get_schema_binding(&scope)
        .await
        .expect("load schema binding");
    assert_eq!(loaded_binding, bound.binding);

    let group_members = Tuple {
        object: object("group", "engineering"),
        relation: "member".into(),
        subject: user("alice"),
    };
    let document_viewers = tuple(
        "roadmap",
        "viewer",
        Subject::Userset {
            object: object("group", "engineering"),
            relation: "member".into(),
        },
    );
    let mutation = MutateTuplesRequest::new(
        scope.clone(),
        unique_id("grant-userset"),
        vec![
            TupleUpdate::Add(group_members),
            TupleUpdate::Add(document_viewers),
        ],
    )
    .unwrap();
    let written = engine
        .mutate_tuples(mutation)
        .await
        .expect("write one atomic relationship batch");

    let alice = CheckRequest {
        subject: user("alice"),
        relation: "can_read".into(),
        object: object("document", "roadmap"),
    };
    let bob = CheckRequest {
        subject: user("bob"),
        relation: "can_read".into(),
        object: object("document", "roadmap"),
    };
    let single = engine
        .check(
            &scope,
            alice.clone(),
            Consistency::AtLeast(written.revision),
        )
        .await
        .expect("check nested userset permission");
    assert!(single.allowed);
    assert_eq!(single.revision, written.revision);

    let batch = engine
        .check_many(
            &scope,
            vec![alice, bob],
            Consistency::Exact(written.revision),
        )
        .await
        .expect("check a permission batch");
    assert_eq!(batch.decisions, vec![true, false]);
    assert_eq!(batch.revision, written.revision);
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC, ANVIL_E2E_TENANT, ANVIL_E2E_CLIENT_ID and ANVIL_E2E_CLIENT_SECRET"]
async fn exact_same_resource_public_and_tuple_to_userset_work_end_to_end() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
    let (engine, tenant) = engine().await;
    let schema = selector_and_traversal_schema();
    let scope = AuthzScope::new(tenant.clone(), unique_id("realm-selectors"));
    let published = engine
        .put_schema(
            &tenant,
            SchemaId(unique_id("schema-selectors")),
            schema.clone(),
        )
        .await
        .expect("publish selector and traversal schema");
    engine
        .bind_schema(&scope, published.schema_ref.clone(), None)
        .await
        .expect("bind selector and traversal schema");
    let (_, loaded) = engine
        .get_schema(&tenant, &published.schema_ref)
        .await
        .expect("load canonical selector and traversal schema");
    assert_eq!(loaded, schema);

    let written = engine
        .mutate_tuples(
            MutateTuplesRequest::new(
                scope.clone(),
                unique_id("selector-and-traversal-tuples"),
                vec![
                    TupleUpdate::Add(Tuple {
                        object: object("folder", "engineering"),
                        relation: "viewer".into(),
                        subject: user("alice"),
                    }),
                    TupleUpdate::Add(Tuple {
                        object: object("document", "roadmap"),
                        relation: "parent".into(),
                        subject: Subject::Entity(object("folder", "engineering")),
                    }),
                    TupleUpdate::Add(Tuple {
                        object: object("document", "search"),
                        relation: "exact_reader".into(),
                        subject: Subject::Entity(object("service", "indexer")),
                    }),
                    TupleUpdate::Add(Tuple {
                        object: object("document", "account-7"),
                        relation: "self_reader".into(),
                        subject: Subject::Entity(object("account", "account-7")),
                    }),
                    TupleUpdate::Add(Tuple {
                        object: object("document", "announcement"),
                        relation: "public_reader".into(),
                        subject: Subject::Public,
                    }),
                ],
            )
            .unwrap(),
        )
        .await
        .expect("write selector and traversal tuples");

    let checks = vec![
        CheckRequest {
            subject: user("alice"),
            relation: "via_parent".into(),
            object: object("document", "roadmap"),
        },
        CheckRequest {
            subject: Subject::Entity(object("service", "indexer")),
            relation: "exact_reader".into(),
            object: object("document", "search"),
        },
        CheckRequest {
            subject: Subject::Entity(object("account", "account-7")),
            relation: "self_reader".into(),
            object: object("document", "account-7"),
        },
        CheckRequest {
            subject: Subject::Public,
            relation: "public_reader".into(),
            object: object("document", "announcement"),
        },
    ];
    let checked = engine
        .check_many(&scope, checks, Consistency::AtLeast(written.revision))
        .await
        .expect("check every selector and traversal result");
    assert_eq!(checked.decisions, vec![true, true, true, true]);
    assert_eq!(checked.revision, written.revision);
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC, ANVIL_E2E_TENANT, ANVIL_E2E_CLIENT_ID and ANVIL_E2E_CLIENT_SECRET"]
async fn distinct_mutations_survive_replay_and_tuple_reads_paginate() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
    let (engine, tenant) = engine().await;
    let scope = AuthzScope::new(tenant.clone(), unique_id("realm-mutations"));
    publish_and_bind(&engine, &tenant, &scope).await;

    let alice_viewer = tuple("guide", "viewer", user("alice"));
    let first_add = MutateTuplesRequest::new(
        scope.clone(),
        unique_id("add-alice-first"),
        vec![TupleUpdate::Add(alice_viewer.clone())],
    )
    .unwrap();
    let added = engine
        .mutate_tuples(first_add.clone())
        .await
        .expect("add relationship");
    let replayed = engine
        .mutate_tuples(first_add)
        .await
        .expect("replay the same logical operation");
    assert!(replayed.replayed);
    assert_eq!(replayed.revision, added.revision);
    assert!(replayed.replay_guarantee_expires_at.is_some());

    engine
        .mutate_tuples(
            MutateTuplesRequest::new(
                scope.clone(),
                unique_id("remove-alice"),
                vec![TupleUpdate::Remove(alice_viewer.clone())],
            )
            .unwrap(),
        )
        .await
        .expect("remove relationship");
    let removed = engine
        .check(
            &scope,
            CheckRequest {
                subject: user("alice"),
                relation: "viewer".into(),
                object: object("document", "guide"),
            },
            Consistency::Latest,
        )
        .await
        .expect("check removed relationship");
    assert!(!removed.allowed);

    engine
        .mutate_tuples(
            MutateTuplesRequest::new(
                scope.clone(),
                unique_id("add-alice-second"),
                vec![
                    TupleUpdate::Add(alice_viewer),
                    TupleUpdate::Add(tuple("guide", "viewer", user("bob"))),
                ],
            )
            .unwrap(),
        )
        .await
        .expect("add the relationship again with a distinct operation ID");

    let filter = TupleFilter {
        object: Some(ObjectFilter::Exact(object("document", "guide"))),
        relation: Some("viewer".into()),
        subject: None,
    };
    let first_page = engine
        .read_tuples(
            ReadTuplesRequest::new(scope.clone())
                .with_filter(filter.clone())
                .with_page_size(1)
                .unwrap(),
        )
        .await
        .expect("read first tuple page");
    assert_eq!(first_page.tuples.len(), 1);
    let next_page_token = first_page
        .next_page_token
        .clone()
        .expect("two tuples require a continuation token");

    let second_page = engine
        .read_tuples(
            ReadTuplesRequest::new(scope)
                .with_filter(filter)
                .with_consistency(Consistency::Exact(first_page.revision))
                .with_page_size(1)
                .unwrap()
                .with_page_token(next_page_token),
        )
        .await
        .expect("read pinned continuation page");
    assert_eq!(second_page.revision, first_page.revision);
    assert_eq!(second_page.tuples.len(), 1);
    assert!(second_page.next_page_token.is_none());

    let subjects = first_page
        .tuples
        .into_iter()
        .chain(second_page.tuples)
        .map(|tuple| tuple.subject.id().to_string())
        .collect::<HashSet<_>>();
    assert_eq!(subjects, HashSet::from(["alice".into(), "bob".into()]));
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC, ANVIL_E2E_TENANT, ANVIL_E2E_CLIENT_ID and ANVIL_E2E_CLIENT_SECRET"]
async fn invalid_batches_are_atomic_and_tenant_mismatches_fail_closed() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
    let (engine, tenant) = engine().await;
    let scope = AuthzScope::new(tenant.clone(), unique_id("realm-atomicity"));
    publish_and_bind(&engine, &tenant, &scope).await;

    let empty = MutateTuplesRequest::new(scope.clone(), unique_id("empty"), Vec::new());
    assert!(matches!(empty, Err(RebacError::InvalidMutation(_))));

    let valid_tuple = tuple("atomic", "viewer", user("alice"));
    let invalid_tuple = Tuple {
        object: object("bad/slash", "atomic"),
        relation: "viewer".into(),
        subject: user("bob"),
    };
    let error = engine
        .mutate_tuples(
            MutateTuplesRequest::new(
                scope.clone(),
                unique_id("invalid-atomic-batch"),
                vec![
                    TupleUpdate::Add(valid_tuple),
                    TupleUpdate::Add(invalid_tuple),
                ],
            )
            .unwrap(),
        )
        .await
        .expect_err("one invalid tuple must reject the complete batch");
    assert!(matches!(error, RebacError::InvalidMutation(_)));

    let decision = engine
        .check(
            &scope,
            CheckRequest {
                subject: user("alice"),
                relation: "viewer".into(),
                object: object("document", "atomic"),
            },
            Consistency::Latest,
        )
        .await
        .expect("check that the valid half was not applied");
    assert!(!decision.allowed);

    let wrong_scope = AuthzScope::new("another-tenant", unique_id("wrong-tenant"));
    let mismatch = engine
        .check(
            &wrong_scope,
            CheckRequest {
                subject: user("alice"),
                relation: "viewer".into(),
                object: object("document", "atomic"),
            },
            Consistency::Latest,
        )
        .await
        .expect_err("a scope cannot switch the authenticated storage tenant");
    assert!(matches!(mismatch, RebacError::PermissionDenied(_)));
}
