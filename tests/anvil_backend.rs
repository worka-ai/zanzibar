#![cfg(feature = "anvil")]

use anvil_storage::{AnvilClient, proto};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use zanzibar::anvil::AnvilRebacEngine;

static ANVIL_E2E_LOCK: Mutex<()> = Mutex::const_new(());
use zanzibar::{
    AuthzScope, NamespaceConfig, Object, RebacEngine, RelationRule, SchemaBuilder, SchemaId,
    Subject, Tuple, TupleUpdate, put_and_bind_schema,
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

fn unique_realm(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    format!("{prefix}-{nanos}")
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
    let token = match std::env::var("ANVIL_E2E_TOKEN") {
        Ok(token) => token,
        Err(_) => fetch_e2e_token(&endpoint).await,
    };
    let client = AnvilClient::connect_with_bearer(endpoint, token)
        .await
        .expect("connect to Anvil e2e endpoint");
    AnvilRebacEngine::new(client)
}

async fn fetch_e2e_token(endpoint: &str) -> String {
    let client_id = std::env::var("ANVIL_E2E_CLIENT_ID")
        .expect("ANVIL_E2E_CLIENT_ID must be set when ANVIL_E2E_TOKEN is absent");
    let client_secret = std::env::var("ANVIL_E2E_CLIENT_SECRET")
        .expect("ANVIL_E2E_CLIENT_SECRET must be set when ANVIL_E2E_TOKEN is absent");
    let client = AnvilClient::connect(endpoint.to_string())
        .await
        .expect("connect to Anvil token endpoint");
    client
        .auth()
        .get_access_token(proto::GetAccessTokenRequest {
            client_id,
            client_secret,
            scopes: vec!["*".to_string()],
        })
        .await
        .expect("obtain Anvil e2e access token")
        .into_inner()
        .access_token
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC plus ANVIL_E2E_TOKEN or ANVIL_E2E_CLIENT_ID/ANVIL_E2E_CLIENT_SECRET"]
async fn anvil_backend_checks_direct_computed_tuple_to_userset_and_nested_usersets() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
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
    let scope = AuthzScope::new("1", unique_realm("schema-checks"));
    put_and_bind_schema(
        &engine,
        &scope,
        SchemaId("default".to_string()),
        schema,
        None,
    )
    .await
    .unwrap();

    let first = engine
        .write_tuples_with_zookie(
            &scope,
            vec![
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
            ],
        )
        .await
        .unwrap()
        .expect("tuple write returns a zookie");

    assert!(
        engine
            .check(
                &scope,
                &user("alice"),
                "viewer",
                &object("document", "direct")
            )
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine
            .check(
                &scope,
                &user("bob"),
                "viewer",
                &object("document", "computed")
            )
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine
            .check(
                &scope,
                &user("carol"),
                "viewer",
                &object("document", "tuple-to-userset"),
            )
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine
            .check(
                &scope,
                &user("carol"),
                "viewer",
                &object("document", "nested")
            )
            .await
            .unwrap()
            .allowed
    );

    let (allowed, token) = engine
        .check_with_consistency(
            &scope,
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
        .list_objects(&scope, &user("carol"), "viewer", "document")
        .await
        .unwrap();
    assert_eq!(objects.object_ids, vec!["nested", "tuple-to-userset"]);

    let subjects = engine
        .list_subjects(&scope, &object("document", "nested"), "viewer", "user")
        .await
        .unwrap();
    assert_eq!(subjects.subject_ids, vec!["carol"]);
}

#[tokio::test]
#[ignore = "requires ANVIL_E2E_GRPC plus ANVIL_E2E_TOKEN or ANVIL_E2E_CLIENT_ID/ANVIL_E2E_CLIENT_SECRET"]
async fn anvil_backend_batch_write_is_atomic_and_watch_replays_from_revision() {
    let _guard = ANVIL_E2E_LOCK.lock().await;
    let engine = engine().await;
    let scope = AuthzScope::new("1", unique_realm("batch-watch"));
    put_and_bind_schema(
        &engine,
        &scope,
        SchemaId("default".to_string()),
        SchemaBuilder::new()
            .namespace(
                "document",
                NamespaceConfig {
                    rules: HashMap::new(),
                },
            )
            .build(),
        None,
    )
    .await
    .unwrap();

    let err = engine
        .write_tuples(
            &scope,
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
            .check(
                &scope,
                &user("alice"),
                "viewer",
                &object("document", "alpha")
            )
            .await
            .unwrap()
            .allowed
    );

    let token = engine
        .write_tuples_with_zookie(
            &scope,
            vec![tuple("document", "alpha", "viewer", user("alice"))],
        )
        .await
        .unwrap()
        .unwrap();
    let mut stream = engine.watch_tuple_log(&scope, 0, "document").await.unwrap();
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
