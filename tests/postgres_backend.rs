#![cfg(feature = "postgres")]

use std::collections::BTreeSet;

use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{
    AuthzScope, Consistency, MutateTuplesRequest, Object, ObjectFilter, PermissionRule,
    PostgresTransactionalRebacEngine, ReadTuplesRequest, RebacEngine, RelationDefinition,
    SchemaBuilder, SchemaId, SchemaRef, StorageTenantId, Subject, SubjectSelector, Tuple,
    TupleFilter, TupleUpdate, TypedCheckRequest,
};

fn object(namespace: &str, id: &str) -> Object {
    Object {
        namespace: namespace.into(),
        id: id.into(),
    }
}

fn entity(namespace: &str, id: &str) -> Subject {
    Subject::Entity(object(namespace, id))
}

fn tuple(object: Object, relation: &str, subject: Subject) -> Tuple {
    Tuple {
        object,
        relation: relation.into(),
        subject,
    }
}

fn schema() -> zanzibar::Schema {
    SchemaBuilder::new()
        .namespace("user", zanzibar::NamespaceDefinition::new())
        .namespace("service", zanzibar::NamespaceDefinition::new())
        .namespace(
            "group",
            zanzibar::NamespaceDefinition::new().relation(
                "member",
                RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                        namespace: "user".into(),
                    }]),
                },
            ),
        )
        .namespace(
            "folder",
            zanzibar::NamespaceDefinition::new().relation(
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
            zanzibar::NamespaceDefinition::new()
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
                            SubjectSelector::Exact(entity("service", "indexer")),
                            SubjectSelector::SameResourceId {
                                namespace: "account".into(),
                            },
                            SubjectSelector::Public,
                        ]),
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
                    "read",
                    RelationDefinition::Permission {
                        rules: BTreeSet::from([
                            PermissionRule::Inherit {
                                relation: "viewer".into(),
                            },
                            PermissionRule::TupleToUserset {
                                tuple_relation: "parent".into(),
                                target_relation: "viewer".into(),
                            },
                        ]),
                    },
                ),
        )
        .namespace(
            "account",
            zanzibar::NamespaceDefinition::new().relation(
                "viewer",
                RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                        namespace: "user".into(),
                    }]),
                },
            ),
        )
        .build()
}

async fn engine() -> (PostgresRebacEngine, sqlx::PgPool, String) {
    let database_url = std::env::var("WORKA_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://worka:worka@127.0.0.1:55432/worka_test".into());
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("start docker compose before cargo test; PostgreSQL test service must be ready");
    let schema_name = format!("zanzibar_{}", Uuid::new_v4().simple());
    let engine = PostgresRebacEngine::new(pool.clone(), schema_name.clone()).unwrap();
    engine.prepare().await.unwrap();
    (engine, pool, schema_name)
}

async fn clean(pool: sqlx::PgPool, schema: &str) {
    let quoted = format!("\"{schema}\"");
    pool.execute(format!("DROP SCHEMA {quoted} CASCADE").as_str())
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
async fn postgres_current_api_preserves_typed_checks_versions_replays_and_cursor_pages() {
    let (engine, pool, schema_name) = engine().await;
    let scope = AuthzScope::new(StorageTenantId("tenant-a".into()), "realm-a");
    let schema = schema();

    let published = engine
        .put_schema(
            &scope.storage_tenant_id,
            SchemaId("worka".into()),
            schema.clone(),
        )
        .await
        .unwrap();
    let same = engine
        .put_schema(
            &scope.storage_tenant_id,
            SchemaId("worka".into()),
            schema.clone(),
        )
        .await
        .unwrap();
    assert_eq!(same.schema_ref, published.schema_ref);

    let bound = engine
        .bind_schema(&scope, published.schema_ref.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        engine.get_schema_binding(&scope).await.unwrap(),
        bound.binding
    );
    let (loaded_ref, loaded_schema) = engine
        .get_schema(&scope.storage_tenant_id, &published.schema_ref)
        .await
        .unwrap();
    assert_eq!(loaded_ref, published.schema_ref);
    assert_eq!(loaded_schema, schema);

    let doc = object("document", "doc-1");
    let parent = object("folder", "folder-1");
    let alice_viewer = tuple(doc.clone(), "viewer", entity("user", "alice"));
    let group_member = tuple(object("group", "editors"), "member", entity("user", "bob"));
    let grouped_viewer = tuple(
        doc.clone(),
        "viewer",
        Subject::Userset {
            object: object("group", "editors"),
            relation: "member".into(),
        },
    );
    let parent_tuple = tuple(doc.clone(), "parent", Subject::Entity(parent.clone()));
    let folder_viewer = tuple(parent, "viewer", entity("user", "carol"));
    let exact_service = tuple(doc.clone(), "viewer", entity("service", "indexer"));
    let public_tuple = tuple(doc.clone(), "viewer", Subject::Public);

    let seed = MutateTuplesRequest::new(
        scope.clone(),
        vec![
            TupleUpdate::Add(alice_viewer.clone()),
            TupleUpdate::Add(group_member),
            TupleUpdate::Add(grouped_viewer),
            TupleUpdate::Add(parent_tuple),
            TupleUpdate::Add(folder_viewer),
            TupleUpdate::Add(exact_service),
            TupleUpdate::Add(public_tuple),
        ],
    )
    .unwrap()
    .with_operation_id("seed-1")
    .unwrap();
    let written = engine.mutate_tuples(seed.clone()).await.unwrap();
    let replayed = engine.mutate_tuples(seed).await.unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.revision, written.revision);

    let checked = engine
        .check_many(
            &scope,
            vec![
                zanzibar::CheckRequest {
                    subject: entity("user", "alice"),
                    relation: "read".into(),
                    object: doc.clone(),
                },
                zanzibar::CheckRequest {
                    subject: entity("user", "bob"),
                    relation: "read".into(),
                    object: doc.clone(),
                },
                zanzibar::CheckRequest {
                    subject: entity("user", "carol"),
                    relation: "read".into(),
                    object: doc.clone(),
                },
                zanzibar::CheckRequest {
                    subject: entity("service", "indexer"),
                    relation: "read".into(),
                    object: doc.clone(),
                },
                zanzibar::CheckRequest {
                    subject: Subject::Public,
                    relation: "read".into(),
                    object: doc.clone(),
                },
            ],
            Consistency::AtLeast(written.revision),
        )
        .await
        .unwrap();
    assert_eq!(checked.decisions, vec![true, true, true, true, true]);
    assert_eq!(checked.revision, written.revision);

    let request = ReadTuplesRequest::new(scope.clone())
        .with_filter(TupleFilter {
            object: Some(ObjectFilter::Exact(doc.clone())),
            ..Default::default()
        })
        .with_page_size(2)
        .unwrap();
    let first = engine.read_tuples(request.clone()).await.unwrap();
    assert_eq!(first.tuples.len(), 2);
    let token = first.next_page_token.clone().unwrap();
    let second = engine
        .read_tuples(request.clone().with_page_token(token.clone()))
        .await
        .unwrap();
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.tuples.len(), 2);
    let third = engine
        .read_tuples(
            request
                .clone()
                .with_page_token(second.next_page_token.unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(third.tuples.len(), 1);
    assert!(third.next_page_token.is_none());

    let remove = MutateTuplesRequest::new(
        scope.clone(),
        vec![TupleUpdate::Remove(alice_viewer.clone())],
    )
    .unwrap()
    .with_operation_id("remove-alice")
    .unwrap();
    let removed = engine.mutate_tuples(remove).await.unwrap();
    let historical = engine
        .check(
            &scope,
            zanzibar::CheckRequest {
                subject: entity("user", "alice"),
                relation: "read".into(),
                object: doc.clone(),
            },
            Consistency::Exact(written.revision),
        )
        .await
        .unwrap();
    assert!(historical.allowed);
    let latest = engine
        .check(
            &scope,
            zanzibar::CheckRequest {
                subject: entity("user", "alice"),
                relation: "read".into(),
                object: doc,
            },
            Consistency::Latest,
        )
        .await
        .unwrap();
    assert!(!latest.allowed);
    assert_eq!(latest.revision, removed.revision);

    let mismatched_replay = MutateTuplesRequest::new(
        scope.clone(),
        vec![TupleUpdate::Add(tuple(
            object("document", "different"),
            "viewer",
            entity("user", "mallory"),
        ))],
    )
    .unwrap()
    .with_operation_id("seed-1")
    .unwrap();
    assert!(matches!(
        engine.mutate_tuples(mismatched_replay).await,
        Err(zanzibar::RebacError::Conflict(_))
    ));

    // Cursor identity is bound to the originating scope and filter.
    let foreign_scope = AuthzScope::new(StorageTenantId("tenant-b".into()), "realm-a");
    let foreign_request = ReadTuplesRequest::new(foreign_scope)
        .with_page_size(2)
        .unwrap();
    assert!(matches!(
        engine
            .read_tuples(foreign_request.with_page_token(token))
            .await,
        Err(zanzibar::RebacError::InvalidReadRequest(_))
    ));

    clean(pool, &schema_name).await;
}

#[tokio::test]
async fn postgres_transaction_extension_uses_the_callers_commit_boundary() {
    let (engine, pool, schema_name) = engine().await;
    let scope = AuthzScope::new(StorageTenantId("tenant-transaction".into()), "realm-a");
    let published = engine
        .put_schema(&scope.storage_tenant_id, SchemaId("worka".into()), schema())
        .await
        .unwrap();
    engine
        .bind_schema(&scope, published.schema_ref, None)
        .await
        .unwrap();

    let object = object("group", "transactional-group");
    let subject = entity("user", "transactional-user");
    let request = MutateTuplesRequest::new(
        scope.clone(),
        vec![TupleUpdate::Add(tuple(
            object.clone(),
            "member",
            subject.clone(),
        ))],
    )
    .unwrap()
    .with_operation_id("worka-transactional-membership")
    .unwrap();
    let check = TypedCheckRequest {
        subject: subject.clone(),
        relation: "member".into(),
        object: object.clone(),
    };

    let mut rolled_back = pool.begin().await.unwrap();
    engine
        .mutate_tuples_in_transaction(&mut rolled_back, request.clone())
        .await
        .unwrap();
    rolled_back.rollback().await.unwrap();
    assert!(
        !engine
            .check(&scope, check.clone(), Consistency::Latest)
            .await
            .unwrap()
            .allowed,
        "a caller rollback removes the tuple and its operation receipt"
    );

    let mut committed = pool.begin().await.unwrap();
    engine
        .mutate_tuples_in_transaction(&mut committed, request)
        .await
        .unwrap();
    let inside = engine
        .check_many_in_transaction(
            &mut committed,
            &scope,
            vec![check.clone()],
            Consistency::Latest,
        )
        .await
        .unwrap();
    assert_eq!(inside.decisions, [true]);
    committed.commit().await.unwrap();
    assert!(
        engine
            .check(&scope, check, Consistency::Latest)
            .await
            .unwrap()
            .allowed
    );

    clean(pool, &schema_name).await;
}

#[test]
fn schema_ref_digest_is_fixed_width() {
    assert!(SchemaRef::new("worka", zanzibar::SchemaRevision(1), [0; 32]).is_ok());
    assert!(SchemaRef::new("worka", zanzibar::SchemaRevision(1), [0; 31]).is_err());
}
