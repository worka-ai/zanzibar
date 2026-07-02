use crate::{
    AnvilStorageTenantId, AuthzDecisionMetadata, AuthzScope, AuthzWriteResult, BindingGeneration,
    CheckDecision, CheckRequest, ListObjectsResult, ListSubjectsResult, NamespaceConfig, Object,
    RebacEngine, RebacError, RelationRule, Schema, SchemaBinding, SchemaId, SchemaRef,
    SchemaRevision, Subject, Tuple, TupleUpdate,
};
use anvil_storage::{AnvilClient, proto};
use async_trait::async_trait;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::Streaming;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnvilConsistencyToken {
    pub revision: u64,
    pub zookie: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AnvilConsistency {
    #[default]
    Latest,
    Exact(String),
    AtLeast(String),
}

impl AnvilConsistency {
    fn as_request_parts(&self) -> (&'static str, String) {
        match self {
            Self::Latest => ("latest", String::new()),
            Self::Exact(zookie) => ("exact", zookie.clone()),
            Self::AtLeast(zookie) => ("at_least", zookie.clone()),
        }
    }
}

#[derive(Clone)]
pub struct AnvilRebacEngine {
    client: AnvilClient,
    schemas: Arc<RwLock<HashMap<(String, String, u64), Schema>>>,
}

impl AnvilRebacEngine {
    pub fn new(client: AnvilClient) -> Self {
        Self {
            client,
            schemas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn write_tuples_with_zookie(
        &self,
        scope: &AuthzScope,
        updates: Vec<TupleUpdate>,
    ) -> Result<Option<AnvilConsistencyToken>, RebacError> {
        if updates.is_empty() {
            return Ok(None);
        }
        let mutations = updates
            .into_iter()
            .map(tuple_update_to_mutation)
            .collect::<Result<Vec<_>, _>>()?;
        let response = self
            .client
            .auth()
            .write_authz_tuples(proto::WriteAuthzTuplesRequest {
                mutations,
                scope: Some(scope_to_proto(scope)),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        Ok(Some(AnvilConsistencyToken {
            revision: response.revision,
            zookie: response.zookie,
        }))
    }

    pub async fn read_tuples_with_consistency(
        &self,
        scope: &AuthzScope,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
        consistency: AnvilConsistency,
    ) -> Result<(Vec<Tuple>, AnvilConsistencyToken), RebacError> {
        let (subject_kind, subject_id) = match subject.as_ref() {
            Some(subject) => {
                let encoded = encode_subject(subject)?;
                (encoded.subject_kind, encoded.subject_id)
            }
            None => (String::new(), String::new()),
        };
        let (consistency, zookie) = consistency.as_request_parts();
        let mut client = self.client.auth();
        let mut page_token = String::new();
        let mut tuples = Vec::new();
        let token = loop {
            let response = client
                .read_authz_tuples(proto::ReadAuthzTuplesRequest {
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
                    consistency: consistency.to_string(),
                    zookie: zookie.clone(),
                    page_size: 1000,
                    page_token,
                    scope: Some(scope_to_proto(scope)),
                })
                .await
                .map_err(anvil_status)?
                .into_inner();
            let response_token = AnvilConsistencyToken {
                revision: response.revision,
                zookie: response.zookie.clone(),
            };
            for tuple in response.tuples {
                tuples.push(tuple_from_proto(tuple)?);
            }
            if response.next_page_token.is_empty() {
                break response_token;
            }
            page_token = response.next_page_token;
        };
        Ok((tuples, token))
    }

    pub async fn check_with_consistency(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object: &Object,
        consistency: AnvilConsistency,
    ) -> Result<(bool, AnvilConsistencyToken), RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        let schema = self
            .schema_for_ref(&scope.anvil_storage_tenant_id, &binding.schema_ref)
            .await?;
        let (tuples, token) = self
            .read_tuples_with_consistency(scope, None, None, None, consistency)
            .await?;
        let view = TupleView::new(tuples);
        Ok((view.check(&schema, object, relation, subject), token))
    }

    pub async fn watch_tuple_log(
        &self,
        scope: &AuthzScope,
        after_revision: u64,
        namespace: impl Into<String>,
    ) -> Result<Streaming<proto::WatchAuthzTupleLogResponse>, RebacError> {
        self.client
            .auth()
            .watch_authz_tuple_log(proto::WatchAuthzTupleLogRequest {
                after_revision,
                namespace: namespace.into(),
                scope: Some(scope_to_proto(scope)),
            })
            .await
            .map(|response| response.into_inner())
            .map_err(anvil_status)
    }
}

#[async_trait]
impl RebacEngine for AnvilRebacEngine {
    async fn put_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: SchemaId,
        schema: Schema,
    ) -> Result<SchemaRef, RebacError> {
        validate_schema(&schema)?;
        let namespaces = schema_to_proto_namespaces(&schema)?;
        let response = self
            .client
            .auth()
            .put_authz_schema(proto::PutAuthzSchemaRequest {
                anvil_storage_tenant_id: storage_tenant.0.clone(),
                schema_id: schema_id.0.clone(),
                namespaces,
                reason: "zanzibar schema put".to_string(),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        let schema_ref = response
            .schema_ref
            .map(schema_ref_from_proto)
            .ok_or_else(|| RebacError::Internal("Anvil schema response missing ref".to_string()))?;
        self.schemas.write().await.insert(
            (
                storage_tenant.0.clone(),
                schema_ref.schema_id.0.clone(),
                schema_ref.schema_revision.0,
            ),
            schema,
        );
        Ok(schema_ref)
    }

    async fn get_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: &SchemaId,
        revision: Option<SchemaRevision>,
    ) -> Result<(SchemaRef, Schema), RebacError> {
        let response = self
            .client
            .auth()
            .get_authz_schema(proto::GetAuthzSchemaRequest {
                namespace: String::new(),
                anvil_storage_tenant_id: storage_tenant.0.clone(),
                schema_id: schema_id.0.clone(),
                schema_revision: revision.map(|revision| revision.0),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        let schema_ref = response
            .schema_ref
            .map(schema_ref_from_proto)
            .ok_or_else(|| RebacError::SchemaNotFound(schema_id.0.clone()))?;
        let schema = schema_from_proto_namespaces(response.namespaces)?;
        self.schemas.write().await.insert(
            (
                storage_tenant.0.clone(),
                schema_ref.schema_id.0.clone(),
                schema_ref.schema_revision.0,
            ),
            schema.clone(),
        );
        Ok((schema_ref, schema))
    }

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<SchemaBinding, RebacError> {
        let response = self
            .client
            .auth()
            .bind_authz_schema(proto::BindAuthzSchemaRequest {
                scope: Some(scope_to_proto(scope)),
                schema_ref: Some(schema_ref_to_proto(&schema_ref)),
                expected_binding_generation: expected_generation.map(|generation| generation.0),
                reason: "zanzibar schema bind".to_string(),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        let response_ref = response
            .schema_ref
            .map(schema_ref_from_proto)
            .ok_or_else(|| {
                RebacError::Internal("Anvil binding response missing ref".to_string())
            })?;
        Ok(SchemaBinding {
            scope: scope.clone(),
            schema_ref: response_ref,
            binding_generation: BindingGeneration(response.binding_generation),
        })
    }

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError> {
        let response = self
            .client
            .auth()
            .get_authz_schema_binding(proto::GetAuthzSchemaBindingRequest {
                scope: Some(scope_to_proto(scope)),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        let schema_ref = response
            .schema_ref
            .map(schema_ref_from_proto)
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))?;
        Ok(SchemaBinding {
            scope: scope.clone(),
            schema_ref,
            binding_generation: BindingGeneration(response.binding_generation),
        })
    }

    async fn write_tuples(
        &self,
        scope: &AuthzScope,
        updates: Vec<TupleUpdate>,
    ) -> Result<AuthzWriteResult, RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        let token = self
            .write_tuples_with_zookie(scope, updates)
            .await?
            .unwrap_or(AnvilConsistencyToken {
                revision: 0,
                zookie: String::new(),
            });
        Ok(AuthzWriteResult {
            metadata: AuthzDecisionMetadata {
                scope: scope.clone(),
                schema_ref: binding.schema_ref,
                authz_revision: token.revision,
                zookie: token.zookie,
            },
        })
    }

    async fn read_tuples(
        &self,
        scope: &AuthzScope,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError> {
        self.read_tuples_with_consistency(
            scope,
            object,
            relation,
            subject,
            AnvilConsistency::Latest,
        )
        .await
        .map(|(tuples, _)| tuples)
    }

    async fn check(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<CheckDecision, RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        self.check_with_consistency(scope, subject, relation, object, AnvilConsistency::Latest)
            .await
            .map(|(allowed, token)| CheckDecision {
                allowed,
                metadata: AuthzDecisionMetadata {
                    scope: scope.clone(),
                    schema_ref: binding.schema_ref,
                    authz_revision: token.revision,
                    zookie: token.zookie,
                },
            })
    }

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<CheckDecision>, RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        let schema = self
            .schema_for_ref(&scope.anvil_storage_tenant_id, &binding.schema_ref)
            .await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(requests
            .into_iter()
            .map(|request| CheckDecision {
                allowed: view.check(
                    &schema,
                    &request.object,
                    &request.relation,
                    &request.subject,
                ),
                metadata: AuthzDecisionMetadata {
                    scope: scope.clone(),
                    schema_ref: binding.schema_ref.clone(),
                    authz_revision: 0,
                    zookie: String::new(),
                },
            })
            .collect())
    }

    async fn list_objects(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Result<ListObjectsResult, RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        let schema = self
            .schema_for_ref(&scope.anvil_storage_tenant_id, &binding.schema_ref)
            .await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(ListObjectsResult {
            object_ids: view.list_objects(&schema, subject, relation, object_namespace),
            metadata: AuthzDecisionMetadata {
                scope: scope.clone(),
                schema_ref: binding.schema_ref,
                authz_revision: 0,
                zookie: String::new(),
            },
        })
    }

    async fn list_subjects(
        &self,
        scope: &AuthzScope,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<ListSubjectsResult, RebacError> {
        let binding = self.get_schema_binding(scope).await?;
        let schema = self
            .schema_for_ref(&scope.anvil_storage_tenant_id, &binding.schema_ref)
            .await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(ListSubjectsResult {
            subject_ids: view.list_subjects(&schema, object, relation, subject_namespace),
            metadata: AuthzDecisionMetadata {
                scope: scope.clone(),
                schema_ref: binding.schema_ref,
                authz_revision: 0,
                zookie: String::new(),
            },
        })
    }
}

impl AnvilRebacEngine {
    async fn schema_for_ref(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<Schema, RebacError> {
        let key = (
            storage_tenant.0.clone(),
            schema_ref.schema_id.0.clone(),
            schema_ref.schema_revision.0,
        );
        if let Some(schema) = self.schemas.read().await.get(&key).cloned() {
            return Ok(schema);
        }
        let response = self
            .client
            .auth()
            .get_authz_schema(proto::GetAuthzSchemaRequest {
                namespace: String::new(),
                anvil_storage_tenant_id: storage_tenant.0.clone(),
                schema_id: schema_ref.schema_id.0.clone(),
                schema_revision: Some(schema_ref.schema_revision.0),
            })
            .await
            .map_err(anvil_status)?
            .into_inner();
        let schema = schema_from_proto_namespaces(response.namespaces)?;
        self.schemas.write().await.insert(key, schema.clone());
        Ok(schema)
    }
}

fn scope_to_proto(scope: &AuthzScope) -> proto::AuthzScope {
    proto::AuthzScope {
        anvil_storage_tenant_id: scope.anvil_storage_tenant_id.0.clone(),
        authz_realm_id: scope.authz_realm_id.0.clone(),
    }
}

fn schema_ref_to_proto(schema_ref: &SchemaRef) -> proto::AuthzSchemaRef {
    proto::AuthzSchemaRef {
        schema_id: schema_ref.schema_id.0.clone(),
        schema_revision: schema_ref.schema_revision.0,
        schema_digest: schema_ref.schema_digest.clone(),
    }
}

fn schema_ref_from_proto(schema_ref: proto::AuthzSchemaRef) -> SchemaRef {
    SchemaRef {
        schema_id: SchemaId(schema_ref.schema_id),
        schema_revision: SchemaRevision(schema_ref.schema_revision),
        schema_digest: schema_ref.schema_digest,
    }
}

#[derive(Debug)]
struct EncodedSubject {
    subject_kind: String,
    subject_id: String,
}

fn tuple_update_to_mutation(update: TupleUpdate) -> Result<proto::AuthzTupleMutation, RebacError> {
    let (tuple, operation) = match update {
        TupleUpdate::Write(tuple) => (tuple, "add"),
        TupleUpdate::Delete(tuple) => (tuple, "remove"),
    };
    let subject = encode_subject(&tuple.subject)?;
    Ok(proto::AuthzTupleMutation {
        namespace: tuple.object.namespace,
        object_id: tuple.object.id,
        relation: tuple.relation,
        subject_kind: subject.subject_kind,
        subject_id: subject.subject_id,
        caveat_hash: String::new(),
        operation: operation.to_string(),
        reason: "zanzibar tuple update".to_string(),
        scope: None,
    })
}

fn encode_subject(subject: &Subject) -> Result<EncodedSubject, RebacError> {
    Ok(match subject {
        Subject::Entity(object) => EncodedSubject {
            subject_kind: object.namespace.clone(),
            subject_id: object.id.clone(),
        },
        Subject::Userset { object, relation } => EncodedSubject {
            subject_kind: "userset".to_string(),
            subject_id: encode_userset_subject(object, relation),
        },
    })
}

fn tuple_from_proto(tuple: proto::AuthzTuple) -> Result<Tuple, RebacError> {
    Ok(Tuple {
        object: Object {
            namespace: tuple.namespace,
            id: tuple.object_id,
        },
        relation: tuple.relation,
        subject: decode_subject(&tuple.subject_kind, &tuple.subject_id)?,
    })
}

fn decode_subject(subject_kind: &str, subject_id: &str) -> Result<Subject, RebacError> {
    if subject_kind == "userset" {
        let (object, relation) = decode_userset_subject(subject_id)?;
        Ok(Subject::Userset { object, relation })
    } else {
        Ok(Subject::Entity(Object {
            namespace: subject_kind.to_string(),
            id: subject_id.to_string(),
        }))
    }
}

fn encode_userset_subject(object: &Object, relation: &str) -> String {
    format!("{}/{}#{}", object.namespace, object.id, relation)
}

fn decode_userset_subject(value: &str) -> Result<(Object, String), RebacError> {
    let Some((namespace, rest)) = value.split_once('/') else {
        return Err(RebacError::Internal("invalid userset subject".to_string()));
    };
    let Some((object_id, relation)) = rest.rsplit_once('#') else {
        return Err(RebacError::Internal("invalid userset subject".to_string()));
    };
    Ok((
        Object {
            namespace: namespace.to_string(),
            id: object_id.to_string(),
        },
        relation.to_string(),
    ))
}

fn schema_to_proto_namespaces(
    schema: &Schema,
) -> Result<Vec<proto::AuthzNamespaceSchema>, RebacError> {
    let schema_json = serde_json::to_string(schema)
        .map_err(|err| RebacError::Internal(format!("encode schema: {err}")))?;
    let mut namespaces = schema
        .namespaces
        .iter()
        .map(|(namespace, config)| proto::AuthzNamespaceSchema {
            namespace: namespace.clone(),
            relations: config
                .rules
                .iter()
                .map(|(relation, rules)| proto::AuthzRelationSchema {
                    relation: relation.clone(),
                    rules: rules.iter().map(relation_rule_to_proto).collect(),
                })
                .collect(),
            schema_json: schema_json.clone(),
            schema_hash: String::new(),
            schema_version: 0,
            authz_revision: 0,
            applied_at: String::new(),
        })
        .collect::<Vec<_>>();
    namespaces.sort_by(|left, right| left.namespace.cmp(&right.namespace));
    Ok(namespaces)
}

fn relation_rule_to_proto(rule: &RelationRule) -> proto::AuthzRelationRule {
    match rule {
        RelationRule::Inherit(relation) => proto::AuthzRelationRule {
            kind: "inherit".to_string(),
            relation: relation.clone(),
            tuple_relation: String::new(),
            target_relation: String::new(),
        },
        RelationRule::Computed {
            tuple_relation,
            target_relation,
        } => proto::AuthzRelationRule {
            kind: "computed".to_string(),
            relation: String::new(),
            tuple_relation: tuple_relation.clone(),
            target_relation: target_relation.clone(),
        },
        RelationRule::TupleToUserset {
            tuple_relation,
            target_relation,
        } => proto::AuthzRelationRule {
            kind: "tuple_to_userset".to_string(),
            relation: String::new(),
            tuple_relation: tuple_relation.clone(),
            target_relation: target_relation.clone(),
        },
    }
}

fn schema_from_proto_namespaces(
    namespaces: Vec<proto::AuthzNamespaceSchema>,
) -> Result<Schema, RebacError> {
    let mut schema = Schema::default();
    for namespace in namespaces {
        if !namespace.schema_json.is_empty() {
            let stored_schema: Schema = serde_json::from_str(&namespace.schema_json)
                .map_err(|err| RebacError::Internal(format!("decode schema: {err}")))?;
            if let Some(config) = stored_schema.namespaces.get(&namespace.namespace) {
                schema
                    .namespaces
                    .insert(namespace.namespace.clone(), config.clone());
                continue;
            }
        }
        schema.namespaces.insert(
            namespace.namespace,
            NamespaceConfig {
                rules: namespace
                    .relations
                    .into_iter()
                    .map(|relation| {
                        Ok((
                            relation.relation,
                            relation
                                .rules
                                .into_iter()
                                .map(relation_rule_from_proto)
                                .collect::<Result<Vec<_>, _>>()?,
                        ))
                    })
                    .collect::<Result<HashMap<_, _>, RebacError>>()?,
            },
        );
    }
    Ok(schema)
}

fn relation_rule_from_proto(rule: proto::AuthzRelationRule) -> Result<RelationRule, RebacError> {
    match rule.kind.as_str() {
        "inherit" => Ok(RelationRule::Inherit(rule.relation)),
        "computed" => Ok(RelationRule::Computed {
            tuple_relation: rule.tuple_relation,
            target_relation: rule.target_relation,
        }),
        "tuple_to_userset" => Ok(RelationRule::TupleToUserset {
            tuple_relation: rule.tuple_relation,
            target_relation: rule.target_relation,
        }),
        other => Err(RebacError::Internal(format!(
            "unsupported Anvil authz schema rule kind: {other}"
        ))),
    }
}

fn validate_schema(schema: &Schema) -> Result<(), RebacError> {
    for (namespace, config) in &schema.namespaces {
        validate_component(namespace, "namespace")?;
        for (relation, rules) in &config.rules {
            validate_component(relation, "relation")?;
            for rule in rules {
                match rule {
                    RelationRule::Inherit(relation) => validate_component(relation, "relation")?,
                    RelationRule::Computed {
                        tuple_relation,
                        target_relation,
                    }
                    | RelationRule::TupleToUserset {
                        tuple_relation,
                        target_relation,
                    } => {
                        validate_component(tuple_relation, "tuple relation")?;
                        validate_component(target_relation, "target relation")?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_component(value: &str, name: &str) -> Result<(), RebacError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.chars().any(char::is_control)
    {
        Err(RebacError::Internal(format!(
            "invalid Anvil Zanzibar {name}: {value:?}"
        )))
    } else {
        Ok(())
    }
}

fn anvil_status(status: tonic::Status) -> RebacError {
    RebacError::Internal(format!("Anvil request failed: {status}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeKey {
    namespace: String,
    object_id: String,
    relation: String,
}

impl NodeKey {
    fn new(object: &Object, relation: &str) -> Self {
        Self {
            namespace: object.namespace.clone(),
            object_id: object.id.clone(),
            relation: relation.to_string(),
        }
    }

    fn object(&self) -> Object {
        Object {
            namespace: self.namespace.clone(),
            id: self.object_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct TupleView {
    tuples: Vec<Tuple>,
}

impl TupleView {
    fn new(tuples: Vec<Tuple>) -> Self {
        Self { tuples }
    }

    fn check(&self, schema: &Schema, object: &Object, relation: &str, subject: &Subject) -> bool {
        self.check_node(
            schema,
            &NodeKey::new(object, relation),
            subject,
            &mut HashSet::new(),
        )
    }

    fn list_objects(
        &self,
        schema: &Schema,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Vec<String> {
        self.tuples
            .iter()
            .filter(|tuple| tuple.object.namespace == object_namespace)
            .map(|tuple| tuple.object.id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|object_id| {
                self.check(
                    schema,
                    &Object {
                        namespace: object_namespace.to_string(),
                        id: object_id.clone(),
                    },
                    relation,
                    subject,
                )
            })
            .collect()
    }

    fn list_subjects(
        &self,
        schema: &Schema,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Vec<String> {
        self.tuples
            .iter()
            .filter_map(|tuple| match &tuple.subject {
                Subject::Entity(subject) if subject.namespace == subject_namespace => {
                    Some(subject.id.clone())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|subject_id| {
                self.check(
                    schema,
                    object,
                    relation,
                    &Subject::Entity(Object {
                        namespace: subject_namespace.to_string(),
                        id: subject_id.clone(),
                    }),
                )
            })
            .collect()
    }

    fn check_node(
        &self,
        schema: &Schema,
        node: &NodeKey,
        subject: &Subject,
        visited: &mut HashSet<NodeKey>,
    ) -> bool {
        if !visited.insert(node.clone()) {
            return false;
        }

        if subject_matches_node(subject, node) {
            visited.remove(node);
            return true;
        }

        for tuple in self.tuples_for_node(node) {
            if subject_matches(&tuple.subject, subject)
                || match &tuple.subject {
                    Subject::Userset { object, relation } => {
                        self.check_node(schema, &NodeKey::new(object, relation), subject, visited)
                    }
                    Subject::Entity(_) => false,
                }
            {
                visited.remove(node);
                return true;
            }
        }

        if let Some(namespace) = schema.namespaces.get(&node.namespace)
            && let Some(rules) = namespace.rules.get(&node.relation)
        {
            let object = node.object();
            for rule in rules {
                match rule {
                    RelationRule::Inherit(inherited_relation) => {
                        if self.check_node(
                            schema,
                            &NodeKey::new(&object, inherited_relation),
                            subject,
                            visited,
                        ) {
                            visited.remove(node);
                            return true;
                        }
                    }
                    RelationRule::Computed {
                        tuple_relation,
                        target_relation,
                    }
                    | RelationRule::TupleToUserset {
                        tuple_relation,
                        target_relation,
                    } => {
                        let source_node = NodeKey::new(&object, tuple_relation);
                        for tuple in self.tuples_for_node(&source_node) {
                            let target_object = match &tuple.subject {
                                Subject::Entity(object) | Subject::Userset { object, .. } => object,
                            };
                            if self.check_node(
                                schema,
                                &NodeKey::new(target_object, target_relation),
                                subject,
                                visited,
                            ) {
                                visited.remove(node);
                                return true;
                            }
                        }
                    }
                }
            }
        }

        visited.remove(node);
        false
    }

    fn tuples_for_node<'a>(&'a self, node: &'a NodeKey) -> impl Iterator<Item = &'a Tuple> + 'a {
        self.tuples.iter().filter(move |tuple| {
            tuple.object.namespace == node.namespace
                && tuple.object.id == node.object_id
                && tuple.relation == node.relation
        })
    }
}

fn subject_matches(left: &Subject, right: &Subject) -> bool {
    match (left, right) {
        (Subject::Entity(left), Subject::Entity(right)) => object_matches(left, right),
        (
            Subject::Userset {
                object: left_object,
                relation: left_relation,
            },
            Subject::Userset {
                object: right_object,
                relation: right_relation,
            },
        ) => object_matches(left_object, right_object) && left_relation == right_relation,
        _ => false,
    }
}

fn subject_matches_node(subject: &Subject, node: &NodeKey) -> bool {
    match subject {
        Subject::Userset { object, relation } => {
            object_matches(
                object,
                &Object {
                    namespace: node.namespace.clone(),
                    id: node.object_id.clone(),
                },
            ) && relation == &node.relation
        }
        Subject::Entity(_) => false,
    }
}

fn object_matches(left: &Object, right: &Object) -> bool {
    (left.namespace == right.namespace || left.namespace == "*" || right.namespace == "*")
        && (left.id == right.id || left.id == "*" || right.id == "*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchemaBuilder;

    fn user(id: &str) -> Subject {
        Subject::Entity(Object {
            namespace: "user".to_string(),
            id: id.to_string(),
        })
    }

    fn object(namespace: &str, id: &str) -> Object {
        Object {
            namespace: namespace.to_string(),
            id: id.to_string(),
        }
    }

    #[test]
    fn local_evaluator_handles_inherit_and_nested_usersets() {
        let schema = SchemaBuilder::new()
            .namespace(
                "document",
                NamespaceConfig {
                    rules: HashMap::from([(
                        "viewer".to_string(),
                        vec![RelationRule::Inherit("editor".to_string())],
                    )]),
                },
            )
            .build();
        let view = TupleView::new(vec![
            Tuple {
                object: object("document", "alpha"),
                relation: "editor".to_string(),
                subject: Subject::Userset {
                    object: object("group", "eng"),
                    relation: "member".to_string(),
                },
            },
            Tuple {
                object: object("group", "eng"),
                relation: "member".to_string(),
                subject: user("alice"),
            },
        ]);

        assert!(view.check(
            &schema,
            &object("document", "alpha"),
            "viewer",
            &user("alice")
        ));
    }

    #[test]
    fn local_evaluator_handles_computed_usersets_from_entity_subjects() {
        let schema = SchemaBuilder::new()
            .namespace(
                "document",
                NamespaceConfig {
                    rules: HashMap::from([(
                        "viewer".to_string(),
                        vec![RelationRule::Computed {
                            tuple_relation: "parent_folder".to_string(),
                            target_relation: "viewer".to_string(),
                        }],
                    )]),
                },
            )
            .namespace(
                "folder",
                NamespaceConfig {
                    rules: HashMap::new(),
                },
            )
            .build();
        let view = TupleView::new(vec![
            Tuple {
                object: object("document", "alpha"),
                relation: "parent_folder".to_string(),
                subject: Subject::Entity(object("folder", "platform")),
            },
            Tuple {
                object: object("folder", "platform"),
                relation: "viewer".to_string(),
                subject: user("alice"),
            },
        ]);

        assert!(view.check(
            &schema,
            &object("document", "alpha"),
            "viewer",
            &user("alice")
        ));
        assert_eq!(
            view.list_objects(&schema, &user("alice"), "viewer", "document"),
            vec!["alpha"]
        );
    }

    #[test]
    fn schema_round_trips_through_anvil_proto_shape() {
        let schema = SchemaBuilder::new()
            .namespace(
                "document",
                NamespaceConfig {
                    rules: HashMap::from([(
                        "viewer".to_string(),
                        vec![
                            RelationRule::Inherit("editor".to_string()),
                            RelationRule::TupleToUserset {
                                tuple_relation: "shared_with".to_string(),
                                target_relation: "member".to_string(),
                            },
                        ],
                    )]),
                },
            )
            .build();
        let proto = schema_to_proto_namespaces(&schema).unwrap();
        let decoded = schema_from_proto_namespaces(proto).unwrap();
        assert_eq!(decoded.namespaces.len(), schema.namespaces.len());
        assert_eq!(
            decoded.namespaces["document"].rules["viewer"],
            schema.namespaces["document"].rules["viewer"]
        );
    }

    #[test]
    fn userset_subject_round_trips_through_anvil_tuple_shape() {
        let subject = Subject::Userset {
            object: object("group", "eng"),
            relation: "member".to_string(),
        };
        let encoded = encode_subject(&subject).unwrap();
        assert_eq!(encoded.subject_kind, "userset");
        assert_eq!(encoded.subject_id, "group/eng#member");
        assert_eq!(
            decode_subject(&encoded.subject_kind, &encoded.subject_id).unwrap(),
            subject
        );
    }
}
