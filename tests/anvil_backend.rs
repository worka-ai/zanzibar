#![cfg(feature = "anvil")]

use anvil_storage::AnvilClient;
use std::collections::HashMap;
use std::time::Duration;
use zanzibar::anvil::AnvilRebacEngine;
use zanzibar::{
    NamespaceConfig, Object, RebacEngine, RelationRule, SchemaBuilder, Subject, Tuple, TupleUpdate,
};

fn object(namespace: &str, id: &str) -> Object {
    Object {
        namespace: namespace.to_string(),
        id: id.to_string(),
    }
}

fn user(id: &str) -> Subject {
    Subject::Entity(object("user", id))
}

fn tuple(namespace: &str, object_id: &str, relation: &str, subject: Subject) -> TupleUpdate {
    TupleUpdate::Write(Tuple {
        object: object(namespace, object_id),
        relation: relation.to_string(),
        subject,
    })
}

async fn engine() -> AnvilRebacEngine {
    let endpoint = std::env::var("ANVIL_E2E_GRPC")
        .expect("ANVIL_E2E_GRPC must point to an Anvil gRPC endpoint");
    let token = std::env::var("ANVIL_E2E_TOKEN")
        .expect("ANVIL_E2E_TOKEN must contain an Anvil bearer token with authz permissions");
    let client = AnvilClient::connect_with_bearer(endpoint, token)
        .await
        .expect("connect to Anvil e2e endpoint");
    AnvilRebacEngine::new(client)
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC and ANVIL_E2E_TOKEN"]
async fn anvil_backend_checks_direct_computed_tuple_to_userset_and_nested_usersets() {
    let engine = engine().await;
    let schema = SchemaBuilder::new()
        .namespace(
            "document",
            NamespaceConfig {
                rules: HashMap::from([
                    (
                        "viewer".to_string(),
                        vec![
                            RelationRule::Inherit("editor".to_string()),
                            RelationRule::Computed {
                                tuple_relation: "parent_folder".to_string(),
                                target_relation: "viewer".to_string(),
                            },
                            RelationRule::TupleToUserset {
                                tuple_relation: "shared_with".to_string(),
                                target_relation: "member".to_string(),
                            },
                        ],
                    ),
                    ("editor".to_string(), vec![]),
                    ("parent_folder".to_string(), vec![]),
                    ("shared_with".to_string(), vec![]),
                ]),
            },
        )
        .namespace(
            "folder",
            NamespaceConfig {
                rules: HashMap::new(),
            },
        )
        .namespace(
            "group",
            NamespaceConfig {
                rules: HashMap::new(),
            },
        )
        .build();
    engine.apply_schema(1, schema).await.unwrap();

    let first = engine
        .write_tuples_with_zookie(vec![
            tuple("document", "direct", "editor", user("alice")),
            tuple(
                "document",
                "computed",
                "parent_folder",
                Subject::Entity(object("folder", "platform")),
            ),
            tuple("folder", "platform", "viewer", user("bob")),
            tuple(
                "document",
                "tuple-to-userset",
                "shared_with",
                Subject::Entity(object("group", "engineering")),
            ),
            tuple("group", "engineering", "member", user("carol")),
            tuple(
                "document",
                "nested",
                "viewer",
                Subject::Userset {
                    object: object("group", "platform"),
                    relation: "member".to_string(),
                },
            ),
            tuple(
                "group",
                "platform",
                "member",
                Subject::Userset {
                    object: object("group", "engineering"),
                    relation: "member".to_string(),
                },
            ),
        ])
        .await
        .unwrap()
        .expect("tuple write returns a zookie");

    assert!(
        engine
            .check(1, &user("alice"), "viewer", &object("document", "direct"))
            .await
            .unwrap()
    );
    assert!(
        engine
            .check(1, &user("bob"), "viewer", &object("document", "computed"))
            .await
            .unwrap()
    );
    assert!(
        engine
            .check(
                1,
                &user("carol"),
                "viewer",
                &object("document", "tuple-to-userset"),
            )
            .await
            .unwrap()
    );
    assert!(
        engine
            .check(1, &user("carol"), "viewer", &object("document", "nested"))
            .await
            .unwrap()
    );

    let (allowed, token) = engine
        .check_with_consistency(
            1,
            &user("carol"),
            "viewer",
            &object("document", "nested"),
            zanzibar::anvil::AnvilConsistency::Exact(first.zookie.clone()),
        )
        .await
        .unwrap();
    assert!(allowed);
    assert_eq!(token.zookie, first.zookie);

    let objects = engine
        .list_objects(1, &user("carol"), "viewer", "document")
        .await
        .unwrap();
    assert_eq!(objects, vec!["nested", "tuple-to-userset"]);

    let subjects = engine
        .list_subjects(1, &object("document", "nested"), "viewer", "user")
        .await
        .unwrap();
    assert_eq!(subjects, vec!["carol"]);
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC and ANVIL_E2E_TOKEN"]
async fn anvil_backend_batch_write_is_atomic_and_watch_replays_from_revision() {
    let engine = engine().await;
    engine
        .apply_schema(
            1,
            SchemaBuilder::new()
                .namespace(
                    "document",
                    NamespaceConfig {
                        rules: HashMap::new(),
                    },
                )
                .build(),
        )
        .await
        .unwrap();

    let err = engine
        .write_tuples(
            1,
            vec![
                tuple("document", "alpha", "viewer", user("alice")),
                tuple("bad/slash", "beta", "viewer", user("bob")),
            ],
        )
        .await
        .expect_err("invalid tuple in a batch must fail the whole write");
    assert!(err.to_string().contains("Anvil request failed"));
    assert!(
        !engine
            .check(1, &user("alice"), "viewer", &object("document", "alpha"))
            .await
            .unwrap()
    );

    let token = engine
        .write_tuples_with_zookie(vec![tuple("document", "alpha", "viewer", user("alice"))])
        .await
        .unwrap()
        .unwrap();
    let mut stream = engine.watch_tuple_log(0, "document").await.unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.revision, token.revision);
    assert_eq!(event.namespace, "document");
    assert_eq!(event.object_id, "alpha");
    assert_eq!(event.subject_kind, "user");
    assert_eq!(event.subject_id, "alice");
}
