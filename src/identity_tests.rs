use super::*;
use crate::exact_path as typed;

fn path(namespace: &str, tenant: &str, bucket: &str, path: &str) -> typed::Object {
    typed::Object {
        namespace: namespace.into(),
        id: ObjectId::ExactPath {
            tenant: tenant.into(),
            bucket: bucket.into(),
            path: path.into(),
        },
    }
}

#[test]
fn exact_identity_preserves_wire_kind_and_all_address_components() {
    let object = path("document", "tenant-a", "documents", "folders/report.json");
    let wire = object_to_proto(object.clone());
    assert!(matches!(&wire.id, Some(Id::ExactPath(address))
        if address.tenant == "tenant-a" && address.bucket == "documents"
        && address.path == "folders/report.json"));
    assert_eq!(object_from_proto::<ObjectId>(wire.clone()).unwrap(), object);
    assert!(object_from_proto::<String>(wire).is_err());
    for other in [
        path("document", "tenant-b", "documents", "folders/report.json"),
        path("document", "tenant-a", "other", "folders/report.json"),
        path("document", "tenant-a", "documents", "other.json"),
        typed::Object {
            namespace: "document".into(),
            id: "folders/report.json".into(),
        },
    ] {
        assert_ne!(object_to_proto(other), object_to_proto(object.clone()));
    }
}

#[test]
fn mixed_tuple_mutations_filters_checks_and_usersets_preserve_identity() {
    let object = path("document", "tenant", "docs", "report.json");
    let subjects = [
        typed::Subject::Entity(typed::Object {
            namespace: "user".into(),
            id: "alice".into(),
        }),
        typed::Subject::Entity(path("folder", "tenant", "docs", "parent.json")),
        typed::Subject::Userset {
            object: path("group", "tenant", "docs", "team.json"),
            relation: "member".into(),
        },
        typed::Subject::Public,
    ];
    for subject in subjects {
        let tuple = typed::Tuple {
            object: object.clone(),
            relation: "viewer".into(),
            subject: subject.clone(),
        };
        assert_eq!(
            tuple_from_proto::<ObjectId>(tuple_to_proto(tuple.clone())).unwrap(),
            tuple
        );
        for update in [
            typed::TupleUpdate::Add(tuple.clone()),
            typed::TupleUpdate::Remove(tuple.clone()),
        ] {
            let wire = tuple_update_to_proto(update).unwrap();
            let tuple_wire = match wire.operation.unwrap() {
                Operation::Add(t) | Operation::Remove(t) => t,
            };
            assert_eq!(tuple_from_proto::<ObjectId>(tuple_wire).unwrap(), tuple);
        }
        let filter = tuple_filter_to_proto(typed::TupleFilter {
            object: Some(typed::ObjectFilter::Exact(object.clone())),
            relation: Some("viewer".into()),
            subject: Some(subject.clone()),
        });
        assert_eq!(
            filter.object.unwrap().selection,
            Some(Selection::Exact(object_to_proto(object.clone())))
        );
        assert_eq!(
            subject_from_proto::<ObjectId>(filter.subject.unwrap()).unwrap(),
            subject
        );
        let request = typed::CheckRequest {
            object: object.clone(),
            relation: "viewer".into(),
            subject: subject.clone(),
        };
        let check = check_to_proto(request);
        if matches!(subject, typed::Subject::Userset { .. }) {
            assert!(matches!(check, Err(RebacError::InvalidTuple(_))));
        } else {
            assert_eq!(check.unwrap().object, Some(object_to_proto(object.clone())));
        }
    }
}

#[test]
fn schema_exact_selectors_round_trip_in_both_identity_positions() {
    let schema = typed::SchemaBuilder::new()
        .namespace(
            "document",
            typed::NamespaceDefinition::new().relation(
                "viewer",
                typed::RelationDefinition::Direct {
                    allowed_subjects: BTreeSet::from([
                        typed::SubjectSelector::Exact(typed::Subject::Entity(path(
                            "folder",
                            "tenant",
                            "docs",
                            "parent.json",
                        ))),
                        typed::SubjectSelector::Exact(typed::Subject::Userset {
                            object: path("group", "tenant", "docs", "group.json"),
                            relation: "member".into(),
                        }),
                        typed::SubjectSelector::Exact(typed::Subject::Entity(typed::Object {
                            namespace: "user".into(),
                            id: "alice".into(),
                        })),
                    ]),
                },
            ),
        )
        .build();
    let wire = schema_to_proto(&schema).unwrap();
    assert!(schema_from_proto::<String>(wire.clone()).is_err());
    assert_eq!(schema_from_proto::<ObjectId>(wire).unwrap(), schema);
}
