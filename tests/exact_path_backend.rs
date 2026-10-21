//! Opt-in public-API regression against an existing provisioned Keldra tenant.
use std::collections::{BTreeSet, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use zanzibar::exact_path as ep;
use zanzibar::keldra::KeldraRebacConfig;
use zanzibar::{
    AuthzScope, Consistency, KeldraStorageTenantId, ObjectId, PermissionRule, RebacEngine, SchemaId,
};

fn object(namespace: &str, id: ObjectId) -> ep::Object {
    ep::Object {
        namespace: namespace.into(),
        id,
    }
}

fn path(namespace: &str, tenant: &str, bucket: &str, path: &str) -> ep::Object {
    object(
        namespace,
        ObjectId::ExactPath {
            tenant: tenant.into(),
            bucket: bucket.into(),
            path: path.into(),
        },
    )
}

fn user(id: &str) -> ep::Subject {
    ep::Subject::Entity(object("user", ObjectId::Opaque(id.into())))
}

fn tuple(object: ep::Object, relation: &str, subject: ep::Subject) -> ep::Tuple {
    ep::Tuple {
        object,
        relation: relation.into(),
        subject,
    }
}

fn schema(exact_service: ep::Subject) -> ep::Schema {
    ep::SchemaBuilder::new()
        .namespace("user", ep::NamespaceDefinition::new())
        .namespace("service", ep::NamespaceDefinition::new())
        .namespace(
            "team",
            ep::NamespaceDefinition::new().relation(
                "member",
                ep::RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([ep::SubjectSelector::AnyObject {
                        namespace: "user".into(),
                    }]),
                },
            ),
        )
        .namespace(
            "document",
            ep::NamespaceDefinition::new()
                .relation(
                    "viewer",
                    ep::RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([
                            ep::SubjectSelector::AnyObject {
                                namespace: "user".into(),
                            },
                            ep::SubjectSelector::AnyUserset {
                                namespace: "team".into(),
                                relation: "member".into(),
                            },
                        ]),
                    },
                )
                .relation(
                    "read",
                    ep::RelationDefinition::Permission {
                        rules: BTreeSet::from([PermissionRule::Inherit {
                            relation: "viewer".into(),
                        }]),
                    },
                )
                .relation(
                    "service_reader",
                    ep::RelationDefinition::Direct {
                        allowed_subjects: BTreeSet::from([
                            ep::SubjectSelector::Exact(exact_service),
                            ep::SubjectSelector::Exact(ep::Subject::Entity(object(
                                "service",
                                ObjectId::Opaque("daemon".into()),
                            ))),
                        ]),
                    },
                ),
        )
        .build()
}

#[tokio::test]
#[ignore = "requires KELDRA_E2E_GRPC, KELDRA_E2E_TENANT, KELDRA_E2E_CLIENT_ID and KELDRA_E2E_CLIENT_SECRET"]
async fn exact_paths_round_trip_through_schema_mutation_reads_and_checks() {
    let endpoint = std::env::var("KELDRA_E2E_GRPC").expect("KELDRA_E2E_GRPC");
    let tenant = std::env::var("KELDRA_E2E_TENANT").expect("KELDRA_E2E_TENANT");
    let client_id = std::env::var("KELDRA_E2E_CLIENT_ID").expect("KELDRA_E2E_CLIENT_ID");
    let client_secret =
        std::env::var("KELDRA_E2E_CLIENT_SECRET").expect("KELDRA_E2E_CLIENT_SECRET");
    let unique = format!(
        "exact-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::process::id()
    );
    let buckets = [format!("{unique}-a"), format!("{unique}-b")];
    let channel = ::keldra::connect_channel(&endpoint)
        .await
        .expect("public channel");
    let token = ::keldra::exchange_client_credentials(channel.clone(), &client_id, &client_secret)
        .await
        .expect("credential exchange")
        .access_token;
    let mut admin = ::keldra::administration_client(channel, &token).unwrap();
    for bucket in &buckets {
        admin
            .create_bucket(::keldra::v1::CreateBucketRequest {
                bucket: bucket.clone(),
                versioning: ::keldra::v1::ObjectVersioning::Unversioned as i32,
                payload_compression: None,
            })
            .await
            .expect("create isolated identity-test bucket");
    }
    let storage_tenant = KeldraStorageTenantId(tenant.clone());
    let engine = ep::KeldraRebacEngine::connect(KeldraRebacConfig {
        endpoint,
        storage_tenant: storage_tenant.clone(),
        client_id,
        client_secret,
    })
    .await
    .expect("typed backend connection");
    let scope = AuthzScope::new(storage_tenant.clone(), unique.clone());
    let service = ep::Subject::Entity(path(
        "service",
        &tenant,
        &buckets[0],
        "services/indexer.json",
    ));
    let expected_schema = schema(service.clone());
    let published = engine
        .put_schema(&storage_tenant, SchemaId(unique), expected_schema.clone())
        .await
        .expect("publish exact-selector schema");
    let (reference, loaded) = engine
        .get_schema(&storage_tenant, &published.schema_ref)
        .await
        .expect("decode exact-selector schema");
    assert_eq!(reference, published.schema_ref);
    assert_eq!(loaded, expected_schema);
    let binding = engine
        .bind_schema(&scope, reference, None)
        .await
        .expect("bind isolated realm");
    assert_eq!(
        engine.get_schema_binding(&scope).await.unwrap(),
        binding.binding
    );

    let document = path("document", &tenant, &buckets[0], "documents/one.json");
    let team = path("team", &tenant, &buckets[0], "teams/editors.json");
    let opaque_document = object("document", ObjectId::Opaque("documents/one.json".into()));
    let viewers = ep::Subject::Userset {
        object: team.clone(),
        relation: "member".into(),
    };
    let rows = vec![
        tuple(team, "member", user("alice")),
        tuple(document.clone(), "viewer", viewers.clone()),
        tuple(opaque_document.clone(), "viewer", user("bob")),
        tuple(document.clone(), "service_reader", service.clone()),
    ];
    let written = engine
        .mutate_tuples(
            ep::MutateTuplesRequest::new(
                scope.clone(),
                rows.iter().cloned().map(ep::TupleUpdate::Add).collect(),
            )
            .unwrap(),
        )
        .await
        .expect("mixed exact and opaque mutation batch");
    let consistency = Consistency::AtLeast(written.revision);
    let check = |subject, object, relation: &str| ep::CheckRequest {
        subject,
        object,
        relation: relation.into(),
    };
    let checks = vec![
        check(user("alice"), document.clone(), "read"),
        check(user("bob"), document.clone(), "read"),
        check(user("bob"), opaque_document.clone(), "read"),
        check(user("alice"), opaque_document.clone(), "read"),
        check(
            user("alice"),
            path("document", &tenant, &buckets[1], "documents/one.json"),
            "read",
        ),
        check(
            user("alice"),
            path("document", &tenant, &buckets[0], "documents/two.json"),
            "read",
        ),
        check(service, document.clone(), "service_reader"),
    ];
    let decisions = engine
        .check_many(&scope, checks.clone(), consistency)
        .await
        .expect("mixed identity check-many");
    assert_eq!(
        decisions.decisions,
        vec![true, false, true, false, false, false, true]
    );
    for (request, expected) in checks.into_iter().zip(decisions.decisions) {
        assert_eq!(
            engine
                .check(&scope, request, consistency)
                .await
                .unwrap()
                .allowed,
            expected
        );
    }
    let exact = engine
        .read_tuples(
            ep::ReadTuplesRequest::new(scope.clone())
                .with_consistency(consistency)
                .with_filter(ep::TupleFilter {
                    object: Some(ep::ObjectFilter::Exact(document.clone())),
                    relation: Some("viewer".into()),
                    subject: Some(viewers),
                }),
        )
        .await
        .expect("exact path and userset filters");
    assert_eq!(exact.tuples, vec![rows[1].clone()]);
    let mut request = ep::ReadTuplesRequest::new(scope.clone())
        .with_consistency(consistency)
        .with_page_size(1)
        .unwrap()
        .with_filter(ep::TupleFilter {
            object: Some(ep::ObjectFilter::Namespace("document".into())),
            ..Default::default()
        });
    let mut found = HashSet::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= 4, "namespace pagination must terminate");
        let page = engine
            .read_tuples(request.clone())
            .await
            .expect("mixed namespace page");
        assert_eq!(page.tuples.len(), 1);
        for row in page.tuples {
            assert!(found.insert(row), "duplicate paginated tuple");
        }
        match page.next_page_token {
            Some(token) => request.page_token = Some(token),
            None => break,
        }
    }
    assert_eq!(found, rows[1..].iter().cloned().collect());
    assert_eq!(pages, 3);
    let removed = engine
        .mutate_tuples(
            ep::MutateTuplesRequest::new(
                scope.clone(),
                rows.iter().cloned().map(ep::TupleUpdate::Remove).collect(),
            )
            .unwrap(),
        )
        .await
        .expect("remove mixed identity batch");
    assert!(
        !engine
            .check(
                &scope,
                check(user("alice"), document.clone(), "read"),
                Consistency::AtLeast(removed.revision)
            )
            .await
            .unwrap()
            .allowed
    );
    let empty = engine
        .read_tuples(
            ep::ReadTuplesRequest::new(scope)
                .with_consistency(Consistency::AtLeast(removed.revision))
                .with_filter(ep::TupleFilter {
                    object: Some(ep::ObjectFilter::Exact(document)),
                    ..Default::default()
                }),
        )
        .await
        .expect("removed exact-path tuples");
    assert!(empty.tuples.is_empty());
    assert!(empty.next_page_token.is_none());
}
