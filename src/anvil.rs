use crate::{
    CheckRequest, Object, RebacEngine, RebacError, RelationRule, Schema, Subject, Tuple,
    TupleUpdate,
};
use anvil_storage::{
    AnvilClient,
    proto::{
        AuthzTupleMutation, CheckPermissionRequest, ListAuthzSubjectsRequest,
        ReadAuthzTuplesRequest, WriteAuthzTuplesRequest,
    },
};
use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};
use tokio::sync::RwLock;

#[async_trait]
pub trait AnvilTenantClientProvider: Send + Sync {
    async fn client_for_tenant(&self, tenant_id: i64) -> Result<AnvilClient, RebacError>;
}

#[derive(Clone)]
pub struct StaticAnvilTenantClientProvider {
    client: AnvilClient,
}

impl StaticAnvilTenantClientProvider {
    pub fn new(client: AnvilClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AnvilTenantClientProvider for StaticAnvilTenantClientProvider {
    async fn client_for_tenant(&self, _tenant_id: i64) -> Result<AnvilClient, RebacError> {
        Ok(self.client.clone())
    }
}

#[async_trait]
pub trait AnvilSchemaStore: Send + Sync {
    async fn apply_schema(&self, tenant_id: i64, schema: Schema) -> Result<(), RebacError>;
    async fn schema(&self, tenant_id: i64) -> Result<Schema, RebacError>;
}

#[derive(Debug, Default)]
pub struct InMemoryAnvilSchemaStore {
    schemas: RwLock<HashMap<i64, Schema>>,
}

impl InMemoryAnvilSchemaStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AnvilSchemaStore for InMemoryAnvilSchemaStore {
    async fn apply_schema(&self, tenant_id: i64, schema: Schema) -> Result<(), RebacError> {
        self.schemas.write().await.insert(tenant_id, schema);
        Ok(())
    }

    async fn schema(&self, tenant_id: i64) -> Result<Schema, RebacError> {
        Ok(self
            .schemas
            .read()
            .await
            .get(&tenant_id)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Clone)]
pub struct AnvilRebacEngine<C, S> {
    clients: C,
    schemas: Arc<S>,
}

impl AnvilRebacEngine<StaticAnvilTenantClientProvider, InMemoryAnvilSchemaStore> {
    pub fn new(client: AnvilClient) -> Self {
        Self::with_schema_store(
            StaticAnvilTenantClientProvider::new(client),
            InMemoryAnvilSchemaStore::new(),
        )
    }
}

impl<C, S> AnvilRebacEngine<C, S>
where
    C: AnvilTenantClientProvider,
    S: AnvilSchemaStore,
{
    pub fn with_schema_store(clients: C, schemas: S) -> Self {
        Self {
            clients,
            schemas: Arc::new(schemas),
        }
    }

    async fn read_active_tuples(
        &self,
        tenant_id: i64,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError> {
        let mut auth = self.clients.client_for_tenant(tenant_id).await?.auth();
        let (subject_kind, subject_id) = subject
            .as_ref()
            .map(subject_to_anvil_parts)
            .unwrap_or_else(|| (String::new(), String::new()));
        let mut page_token = String::new();
        let mut tuples = Vec::new();

        loop {
            let response = auth
                .read_authz_tuples(ReadAuthzTuplesRequest {
                    namespace: object
                        .as_ref()
                        .map(|object| object.namespace.clone())
                        .unwrap_or_default(),
                    object_id: object
                        .as_ref()
                        .map(|object| object.id.clone())
                        .unwrap_or_default(),
                    relation: relation.clone().unwrap_or_default(),
                    subject_kind: subject_kind.clone(),
                    subject_id: subject_id.clone(),
                    caveat_hash: String::new(),
                    consistency: "latest".to_string(),
                    zookie: String::new(),
                    page_size: 1000,
                    page_token,
                })
                .await
                .map_err(status_error)?
                .into_inner();

            tuples.extend(
                response
                    .tuples
                    .into_iter()
                    .map(|tuple| {
                        Ok(Tuple {
                            object: Object {
                                namespace: tuple.namespace,
                                id: tuple.object_id,
                            },
                            relation: tuple.relation,
                            subject: subject_from_anvil_parts(
                                &tuple.subject_kind,
                                &tuple.subject_id,
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>, RebacError>>()?,
            );

            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }

        Ok(tuples)
    }

    async fn check_with_schema(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object: &Object,
        schema: &Schema,
    ) -> Result<bool, RebacError> {
        let mut queue = VecDeque::from([(object.clone(), relation.to_string())]);
        let mut visited = HashSet::new();

        while let Some((current_object, current_relation)) = queue.pop_front() {
            if !visited.insert((current_object.clone(), current_relation.clone())) {
                continue;
            }
            if userset_node_matches_subject(&current_object, &current_relation, subject) {
                return Ok(true);
            }

            let tuples = self
                .read_active_tuples(
                    tenant_id,
                    Some(current_object.clone()),
                    Some(current_relation.clone()),
                    None,
                )
                .await?;

            for tuple in tuples {
                if subject_matches(&tuple.subject, subject) {
                    return Ok(true);
                }
                if let Subject::Userset { object, relation } = tuple.subject {
                    queue.push_back((object, relation));
                }
            }

            if let Some(namespace) = schema.namespaces.get(&current_object.namespace)
                && let Some(rules) = namespace.rules.get(&current_relation)
            {
                for rule in rules {
                    match rule {
                        RelationRule::Inherit(inherited_relation) => {
                            queue.push_back((current_object.clone(), inherited_relation.clone()));
                        }
                        RelationRule::Computed {
                            tuple_relation,
                            target_relation,
                        }
                        | RelationRule::TupleToUserset {
                            tuple_relation,
                            target_relation,
                        } => {
                            let jump_tuples = self
                                .read_active_tuples(
                                    tenant_id,
                                    Some(current_object.clone()),
                                    Some(tuple_relation.clone()),
                                    None,
                                )
                                .await?;
                            for jump in jump_tuples {
                                queue.push_back((
                                    subject_object(&jump.subject),
                                    target_relation.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl<C, S> RebacEngine for AnvilRebacEngine<C, S>
where
    C: AnvilTenantClientProvider,
    S: AnvilSchemaStore,
{
    async fn apply_schema(&self, tenant_id: i64, schema: Schema) -> Result<(), RebacError> {
        self.schemas.apply_schema(tenant_id, schema).await
    }

    async fn write_tuples(
        &self,
        tenant_id: i64,
        updates: Vec<TupleUpdate>,
    ) -> Result<(), RebacError> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut auth = self.clients.client_for_tenant(tenant_id).await?.auth();
        let mutations = updates
            .into_iter()
            .map(tuple_update_to_anvil_mutation)
            .collect::<Vec<_>>();
        auth.write_authz_tuples(WriteAuthzTuplesRequest { mutations })
            .await
            .map_err(status_error)?;
        Ok(())
    }

    async fn read_tuples(
        &self,
        tenant_id: i64,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError> {
        self.read_active_tuples(tenant_id, object, relation, subject)
            .await
    }

    async fn check(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<bool, RebacError> {
        let schema = self.schemas.schema(tenant_id).await?;
        if schema.namespaces.is_empty() {
            let mut auth = self.clients.client_for_tenant(tenant_id).await?.auth();
            return auth
                .check_permission(CheckPermissionRequest {
                    namespace: object.namespace.clone(),
                    object_id: object.id.clone(),
                    relation: relation.to_string(),
                    subject_kind: subject_to_anvil_parts(subject).0,
                    subject_id: subject_to_anvil_parts(subject).1,
                    caveat_hash: String::new(),
                    consistency: "latest".to_string(),
                    zookie: String::new(),
                })
                .await
                .map(|response| response.into_inner().allowed)
                .map_err(status_error);
        }
        self.check_with_schema(tenant_id, subject, relation, object, &schema)
            .await
    }

    async fn check_many(
        &self,
        tenant_id: i64,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<bool>, RebacError> {
        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            results.push(
                self.check(
                    tenant_id,
                    &request.subject,
                    &request.relation,
                    &request.object,
                )
                .await?,
            );
        }
        Ok(results)
    }

    async fn list_objects(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Result<Vec<String>, RebacError> {
        let tuples = self
            .read_active_tuples(
                tenant_id,
                Some(Object {
                    namespace: object_namespace.to_string(),
                    id: String::new(),
                }),
                None,
                None,
            )
            .await?;
        let mut candidates = tuples
            .into_iter()
            .map(|tuple| tuple.object.id)
            .collect::<HashSet<_>>();
        let mut objects = Vec::new();
        for object_id in candidates.drain() {
            let object = Object {
                namespace: object_namespace.to_string(),
                id: object_id,
            };
            if self.check(tenant_id, subject, relation, &object).await? {
                objects.push(object.id);
            }
        }
        objects.sort();
        Ok(objects)
    }

    async fn list_subjects(
        &self,
        tenant_id: i64,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<Vec<String>, RebacError> {
        let mut auth = self.clients.client_for_tenant(tenant_id).await?.auth();
        let mut page_token = String::new();
        let mut subjects = HashSet::new();
        loop {
            let response = auth
                .list_authz_subjects(ListAuthzSubjectsRequest {
                    namespace: object.namespace.clone(),
                    object_id: object.id.clone(),
                    relation: relation.to_string(),
                    subject_kind: subject_namespace.to_string(),
                    consistency: "latest".to_string(),
                    zookie: String::new(),
                    page_size: 1000,
                    page_token,
                })
                .await
                .map_err(status_error)?
                .into_inner();
            subjects.extend(
                response
                    .subjects
                    .into_iter()
                    .map(|subject| subject.subject_id),
            );
            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }
        let mut subjects = subjects.into_iter().collect::<Vec<_>>();
        subjects.sort();
        Ok(subjects)
    }
}

fn tuple_update_to_anvil_mutation(update: TupleUpdate) -> AuthzTupleMutation {
    let (operation, tuple) = match update {
        TupleUpdate::Write(tuple) => ("add", tuple),
        TupleUpdate::Delete(tuple) => ("remove", tuple),
    };
    let (subject_kind, subject_id) = subject_to_anvil_parts(&tuple.subject);
    AuthzTupleMutation {
        namespace: tuple.object.namespace,
        object_id: tuple.object.id,
        relation: tuple.relation,
        subject_kind,
        subject_id,
        caveat_hash: String::new(),
        operation: operation.to_string(),
        reason: "zanzibar tuple update".to_string(),
    }
}

fn subject_to_anvil_parts(subject: &Subject) -> (String, String) {
    match subject {
        Subject::Entity(object) => (object.namespace.clone(), object.id.clone()),
        Subject::Userset { object, relation } => (
            "userset".to_string(),
            format!("{}/{}#{}", object.namespace, object.id, relation),
        ),
    }
}

fn subject_from_anvil_parts(subject_kind: &str, subject_id: &str) -> Result<Subject, RebacError> {
    if subject_kind == "userset" {
        let Some((namespace, rest)) = subject_id.split_once('/') else {
            return Err(RebacError::Internal("invalid userset subject".to_string()));
        };
        let Some((id, relation)) = rest.rsplit_once('#') else {
            return Err(RebacError::Internal("invalid userset subject".to_string()));
        };
        return Ok(Subject::Userset {
            object: Object {
                namespace: namespace.to_string(),
                id: id.to_string(),
            },
            relation: relation.to_string(),
        });
    }
    Ok(Subject::Entity(Object {
        namespace: subject_kind.to_string(),
        id: subject_id.to_string(),
    }))
}

fn subject_matches(candidate: &Subject, subject: &Subject) -> bool {
    match (candidate, subject) {
        (Subject::Entity(candidate), Subject::Entity(subject)) => {
            (candidate.namespace == subject.namespace || candidate.namespace == "*")
                && (candidate.id == subject.id || candidate.id == "*")
        }
        (
            Subject::Userset {
                object: candidate,
                relation: candidate_relation,
            },
            Subject::Userset {
                object: subject,
                relation: subject_relation,
            },
        ) => candidate == subject && candidate_relation == subject_relation,
        _ => false,
    }
}

fn userset_node_matches_subject(object: &Object, relation: &str, subject: &Subject) -> bool {
    matches!(
        subject,
        Subject::Userset {
            object: subject_object,
            relation: subject_relation,
        } if subject_object == object && subject_relation == relation
    )
}

fn subject_object(subject: &Subject) -> Object {
    match subject {
        Subject::Entity(object) => object.clone(),
        Subject::Userset { object, .. } => object.clone(),
    }
}

fn status_error(error: impl std::fmt::Display) -> RebacError {
    RebacError::Internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_userset_round_trips_through_anvil_shape() {
        let subject = Subject::Userset {
            object: Object {
                namespace: "group".to_string(),
                id: "engineering".to_string(),
            },
            relation: "member".to_string(),
        };
        let (kind, id) = subject_to_anvil_parts(&subject);
        assert_eq!(kind, "userset");
        assert_eq!(id, "group/engineering#member");
        assert_eq!(subject_from_anvil_parts(&kind, &id).unwrap(), subject);
    }

    #[test]
    fn tuple_updates_map_to_anvil_mutations() {
        let tuple = Tuple {
            object: Object {
                namespace: "document".to_string(),
                id: "alpha".to_string(),
            },
            relation: "viewer".to_string(),
            subject: Subject::Entity(Object {
                namespace: "user".to_string(),
                id: "alice".to_string(),
            }),
        };
        let mutation = tuple_update_to_anvil_mutation(TupleUpdate::Delete(tuple));
        assert_eq!(mutation.namespace, "document");
        assert_eq!(mutation.object_id, "alpha");
        assert_eq!(mutation.subject_kind, "user");
        assert_eq!(mutation.subject_id, "alice");
        assert_eq!(mutation.operation, "remove");
    }

    #[tokio::test]
    async fn in_memory_schema_store_is_tenant_scoped() {
        let store = InMemoryAnvilSchemaStore::new();
        let schema = Schema {
            namespaces: HashMap::from([("document".to_string(), Default::default())]),
        };
        store.apply_schema(7, schema.clone()).await.unwrap();
        assert!(
            store
                .schema(7)
                .await
                .unwrap()
                .namespaces
                .contains_key("document")
        );
        assert!(store.schema(8).await.unwrap().namespaces.is_empty());
    }
}
