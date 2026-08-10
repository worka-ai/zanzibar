use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anvil_storage::v1::authz_consistency::Requirement;
use anvil_storage::v1::object_filter::Selection;
use anvil_storage::v1::object_ref::Id;
use anvil_storage::v1::permission_rule::Rule;
use anvil_storage::v1::relation_definition::Kind as RelationKind;
use anvil_storage::v1::subject::Kind as SubjectKind;
use anvil_storage::v1::subject_selector::Selector;
use anvil_storage::v1::tuple_mutation::Operation;
use anvil_storage::v1::{
    AnyObjectSelector, AnyUsersetSelector, AtLeastRevision, AuthzConsistency as ProtoConsistency,
    AuthzScope as ProtoScope, BindSchemaRequest, CheckPermissionRequest, CheckPermissionsRequest,
    DirectRelation, ExactRevision, GetBindingRequest, GetSchemaRequest, InheritRule,
    LatestConsistency, MutateTuplesRequest as ProtoMutateTuplesRequest,
    NamespaceDefinition as ProtoNamespaceDefinition, ObjectFilter as ProtoObjectFilter, ObjectRef,
    Permission, PermissionCheck, PermissionRule as ProtoPermissionRule, PublicSubjectSelector,
    PutSchemaRequest, ReadTuplesRequest as ProtoReadTuplesRequest,
    RelationDefinition as ProtoRelationDefinition, RelationTuple, SameResourceIdSelector,
    SchemaBinding as ProtoSchemaBinding, SchemaRef as ProtoSchemaRef, Subject as ProtoSubject,
    SubjectSelector as ProtoSubjectSelector, TupleFilter as ProtoTupleFilter,
    TupleMutation as ProtoTupleMutation, TupleToUsersetRule, Userset,
};
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};
use tonic::transport::Channel;
use tonic::{Code, Status};

use crate::{
    AnvilStorageTenantId, AuthzRevision, AuthzScope, BindSchemaResult, BindingGeneration,
    CheckDecision, CheckManyResult, CheckRequest, Consistency, MutateTuplesRequest,
    MutateTuplesResult, NamespaceDefinition, Object, ObjectFilter, PermissionRule, PutSchemaResult,
    ReadTuplesPage, ReadTuplesRequest, RebacEngine, RebacError, RelationDefinition, Schema,
    SchemaBinding, SchemaId, SchemaRef, SchemaRevision, Subject, SubjectSelector, Tuple,
    TupleFilter, TupleUpdate,
};

const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(30);
const TOKEN_EXCHANGE_ATTEMPTS: u32 = 12;
const MAX_MUTATIONS: usize = 1_000;
const MAX_CHECKS: usize = 1_000;
const MAX_PAGE_SIZE: u32 = 1_000;
const ANVIL_PUBLIC_NAMESPACE: &str = "app";
const ANVIL_PUBLIC_ID: &str = "_anvil/public";

/// Durable application credentials used to connect to one Anvil 0.6 cluster.
#[derive(Clone)]
pub struct AnvilRebacConfig {
    pub endpoint: String,
    pub storage_tenant: AnvilStorageTenantId,
    pub client_id: String,
    pub client_secret: String,
}

impl fmt::Debug for AnvilRebacConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnvilRebacConfig")
            .field("endpoint", &self.endpoint)
            .field("storage_tenant", &self.storage_tenant)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
struct SessionToken {
    value: String,
    refresh_at: Instant,
}

struct AnvilSession {
    config: AnvilRebacConfig,
    channel: Channel,
    token: RwLock<Option<SessionToken>>,
    refresh: Mutex<()>,
}

impl fmt::Debug for AnvilSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnvilSession")
            .field("config", &self.config)
            .field("channel", &"<channel>")
            .finish()
    }
}

impl AnvilSession {
    async fn connect(config: AnvilRebacConfig) -> Result<Arc<Self>, RebacError> {
        validate_config(&config)?;
        let channel = anvil_storage::connect_channel(&config.endpoint)
            .await
            .map_err(|error| RebacError::Anvil(format!("failed to connect to Anvil: {error}")))?;
        let session = Arc::new(Self {
            config,
            channel,
            token: RwLock::new(None),
            refresh: Mutex::new(()),
        });
        session.access_token().await?;
        Ok(session)
    }

    async fn client(&self) -> Result<anvil_storage::RawAuthzClient, RebacError> {
        let token = self.access_token().await?;
        anvil_storage::authz_client(self.channel.clone(), &token)
            .map_err(|error| RebacError::Internal(format!("invalid Anvil access token: {error}")))
    }

    async fn access_token(&self) -> Result<String, RebacError> {
        if let Some(token) = self.current_token().await {
            return Ok(token);
        }

        let _refresh = self.refresh.lock().await;
        if let Some(token) = self.current_token().await {
            return Ok(token);
        }

        let mut attempt = 0;
        let response = loop {
            match anvil_storage::exchange_client_credentials(
                self.channel.clone(),
                self.config.client_id.clone(),
                self.config.client_secret.clone(),
            )
            .await
            {
                Ok(response) => break response,
                Err(status)
                    if attempt + 1 < TOKEN_EXCHANGE_ATTEMPTS
                        && matches!(status.code(), Code::ResourceExhausted | Code::Unavailable) =>
                {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(125 * u64::from(attempt))).await;
                }
                Err(status) => return Err(map_status(status)),
            }
        };
        if response.access_token.trim().is_empty() || response.expires_in_seconds == 0 {
            return Err(RebacError::Internal(
                "Anvil credential exchange returned an empty or expired token".into(),
            ));
        }
        let lifetime = Duration::from_secs(response.expires_in_seconds);
        let margin = TOKEN_REFRESH_MARGIN.min(lifetime / 4);
        let token = SessionToken {
            value: response.access_token,
            refresh_at: Instant::now() + lifetime.saturating_sub(margin),
        };
        let value = token.value.clone();
        *self.token.write().await = Some(token);
        Ok(value)
    }

    async fn current_token(&self) -> Option<String> {
        self.token
            .read()
            .await
            .as_ref()
            .filter(|token| Instant::now() < token.refresh_at)
            .map(|token| token.value.clone())
    }
}

/// A thin authenticated adapter over Anvil's authoritative authorization API.
#[derive(Clone)]
pub struct AnvilRebacEngine {
    session: Arc<AnvilSession>,
}

impl fmt::Debug for AnvilRebacEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnvilRebacEngine")
            .field("session", &self.session)
            .finish()
    }
}

impl AnvilRebacEngine {
    pub async fn connect(config: AnvilRebacConfig) -> Result<Self, RebacError> {
        Ok(Self {
            session: AnvilSession::connect(config).await?,
        })
    }

    fn validate_storage_tenant(
        &self,
        storage_tenant: &AnvilStorageTenantId,
    ) -> Result<(), RebacError> {
        if storage_tenant != &self.session.config.storage_tenant {
            return Err(RebacError::PermissionDenied(
                "authorization tenant does not match the authenticated Anvil tenant".into(),
            ));
        }
        Ok(())
    }

    fn validate_scope(&self, scope: &AuthzScope) -> Result<(), RebacError> {
        self.validate_storage_tenant(&scope.anvil_storage_tenant_id)
    }
}

#[async_trait]
impl RebacEngine for AnvilRebacEngine {
    async fn put_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: SchemaId,
        schema: Schema,
    ) -> Result<PutSchemaResult, RebacError> {
        self.validate_storage_tenant(storage_tenant)?;
        let namespaces = schema_to_proto(&schema)?;
        let response = self
            .session
            .client()
            .await?
            .put_schema(PutSchemaRequest {
                schema_id: schema_id.0.clone(),
                namespaces,
            })
            .await
            .map_err(|status| map_schema_status(status, &schema_id))?
            .into_inner();
        let schema_ref = response
            .schema_ref
            .ok_or_else(|| {
                RebacError::Internal("Anvil schema response omitted its reference".into())
            })
            .and_then(schema_ref_from_proto)?;
        Ok(PutSchemaResult {
            schema_ref,
            revision: AuthzRevision(response.revision),
            replayed: response.replayed,
        })
    }

    async fn get_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<(SchemaRef, Schema), RebacError> {
        self.validate_storage_tenant(storage_tenant)?;
        let response = self
            .session
            .client()
            .await?
            .get_schema(GetSchemaRequest {
                schema_ref: Some(schema_ref_to_proto(schema_ref)),
            })
            .await
            .map_err(|status| map_schema_status(status, &schema_ref.schema_id))?
            .into_inner();
        let response_ref = response
            .schema_ref
            .ok_or_else(|| {
                RebacError::Internal("Anvil schema response omitted its reference".into())
            })
            .and_then(schema_ref_from_proto)?;
        Ok((response_ref, schema_from_proto(response.namespaces)?))
    }

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<BindSchemaResult, RebacError> {
        self.validate_scope(scope)?;
        let response = self
            .session
            .client()
            .await?
            .bind_schema(BindSchemaRequest {
                scope: Some(scope_to_proto(scope)),
                schema_ref: Some(schema_ref_to_proto(&schema_ref)),
                expected_binding_generation: expected_generation.map(|value| value.0),
            })
            .await
            .map_err(|status| {
                map_binding_status(status, &schema_ref.schema_id, expected_generation)
            })?
            .into_inner();
        let binding = response
            .binding
            .ok_or_else(|| RebacError::Internal("Anvil bind response omitted its binding".into()))
            .and_then(binding_from_proto)?;
        Ok(BindSchemaResult {
            binding,
            revision: AuthzRevision(response.revision),
        })
    }

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError> {
        self.validate_scope(scope)?;
        let response = self
            .session
            .client()
            .await?
            .get_binding(GetBindingRequest {
                scope: Some(scope_to_proto(scope)),
            })
            .await
            .map_err(|status| {
                if status.code() == Code::NotFound {
                    RebacError::SchemaBindingNotFound(scope.clone())
                } else {
                    map_status(status)
                }
            })?
            .into_inner();
        response
            .binding
            .ok_or_else(|| {
                RebacError::Internal("Anvil binding response omitted its binding".into())
            })
            .and_then(binding_from_proto)
    }

    async fn mutate_tuples(
        &self,
        request: MutateTuplesRequest,
    ) -> Result<MutateTuplesResult, RebacError> {
        let (scope, operation_id, expected_revision, updates) = request.into_parts();
        self.validate_scope(&scope)?;
        if updates.is_empty() {
            return Err(RebacError::InvalidMutation(
                "tuple mutation batch must not be empty".into(),
            ));
        }
        if updates.len() > MAX_MUTATIONS {
            return Err(RebacError::ResourceExhausted(format!(
                "tuple mutation batch exceeds the {MAX_MUTATIONS} item limit"
            )));
        }
        let mutations = updates
            .into_iter()
            .map(tuple_update_to_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let response = self
            .session
            .client()
            .await?
            .mutate_tuples(ProtoMutateTuplesRequest {
                scope: Some(scope_to_proto(&scope)),
                operation_id,
                expected_revision: expected_revision.map(|value| value.0),
                mutations,
            })
            .await
            .map_err(|status| map_mutation_status(status, &scope))?
            .into_inner();
        let replay_guarantee_expires_at = response
            .replay_guarantee_expires_at
            .map(SystemTime::try_from)
            .transpose()
            .map_err(|error| {
                RebacError::Internal(format!("Anvil returned an invalid replay expiry: {error}"))
            })?;
        Ok(MutateTuplesResult {
            revision: AuthzRevision(response.revision),
            replayed: response.replayed,
            replay_guarantee_expires_at,
        })
    }

    async fn read_tuples(&self, request: ReadTuplesRequest) -> Result<ReadTuplesPage, RebacError> {
        self.validate_scope(&request.scope)?;
        if request.page_size > MAX_PAGE_SIZE {
            return Err(RebacError::ResourceExhausted(format!(
                "tuple page size exceeds the {MAX_PAGE_SIZE} item limit"
            )));
        }
        let response = self
            .session
            .client()
            .await?
            .read_tuples(ProtoReadTuplesRequest {
                scope: Some(scope_to_proto(&request.scope)),
                filter: Some(tuple_filter_to_proto(request.filter)),
                consistency: Some(consistency_to_proto(request.consistency)),
                page_size: request.page_size,
                page_token: request.page_token.unwrap_or_default(),
            })
            .await
            .map_err(|status| map_read_status(status, &request.scope))?
            .into_inner();
        let tuples = response
            .tuples
            .into_iter()
            .map(tuple_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ReadTuplesPage {
            tuples,
            revision: AuthzRevision(response.revision),
            next_page_token: (!response.next_page_token.is_empty())
                .then_some(response.next_page_token),
        })
    }

    async fn check(
        &self,
        scope: &AuthzScope,
        request: CheckRequest,
        consistency: Consistency,
    ) -> Result<CheckDecision, RebacError> {
        self.validate_scope(scope)?;
        let response = self
            .session
            .client()
            .await?
            .check_permission(CheckPermissionRequest {
                scope: Some(scope_to_proto(scope)),
                check: Some(check_to_proto(request)?),
                consistency: Some(consistency_to_proto(consistency)),
            })
            .await
            .map_err(|status| map_check_status(status, scope))?
            .into_inner();
        Ok(CheckDecision {
            allowed: response.allowed,
            revision: AuthzRevision(response.revision),
        })
    }

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<CheckRequest>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError> {
        self.validate_scope(scope)?;
        if requests.is_empty() {
            return Err(RebacError::InvalidTuple(
                "permission check batch must not be empty".into(),
            ));
        }
        if requests.len() > MAX_CHECKS {
            return Err(RebacError::ResourceExhausted(format!(
                "permission check batch exceeds the {MAX_CHECKS} item limit"
            )));
        }
        let expected_results = requests.len();
        let checks = requests
            .into_iter()
            .map(check_to_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let response = self
            .session
            .client()
            .await?
            .check_permissions(CheckPermissionsRequest {
                scope: Some(scope_to_proto(scope)),
                checks,
                consistency: Some(consistency_to_proto(consistency)),
            })
            .await
            .map_err(|status| map_check_status(status, scope))?
            .into_inner();
        if response.results.len() != expected_results {
            return Err(RebacError::Internal(format!(
                "Anvil returned {} permission results for {expected_results} checks",
                response.results.len()
            )));
        }
        Ok(CheckManyResult {
            decisions: response
                .results
                .into_iter()
                .map(|result| result.allowed)
                .collect(),
            revision: AuthzRevision(response.revision),
        })
    }
}

fn validate_config(config: &AnvilRebacConfig) -> Result<(), RebacError> {
    for (name, value) in [
        ("endpoint", config.endpoint.as_str()),
        ("storage tenant", config.storage_tenant.0.as_str()),
        ("client ID", config.client_id.as_str()),
        ("client secret", config.client_secret.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(RebacError::Anvil(format!("Anvil {name} cannot be empty")));
        }
    }
    Ok(())
}

fn scope_to_proto(scope: &AuthzScope) -> ProtoScope {
    ProtoScope {
        storage_tenant: scope.anvil_storage_tenant_id.0.clone(),
        realm: scope.authz_realm_id.0.clone(),
    }
}

fn scope_from_proto(scope: ProtoScope) -> AuthzScope {
    AuthzScope::new(scope.storage_tenant, scope.realm)
}

fn schema_ref_to_proto(schema_ref: &SchemaRef) -> ProtoSchemaRef {
    ProtoSchemaRef {
        schema_id: schema_ref.schema_id.0.clone(),
        schema_revision: schema_ref.schema_revision.0,
        schema_digest: schema_ref.schema_digest.to_vec(),
    }
}

fn schema_ref_from_proto(schema_ref: ProtoSchemaRef) -> Result<SchemaRef, RebacError> {
    let digest = schema_ref
        .schema_digest
        .try_into()
        .map_err(|value: Vec<u8>| {
            RebacError::Internal(format!(
                "Anvil returned a schema digest with {} bytes instead of 32",
                value.len()
            ))
        })?;
    Ok(SchemaRef {
        schema_id: SchemaId(schema_ref.schema_id),
        schema_revision: SchemaRevision(schema_ref.schema_revision),
        schema_digest: digest,
    })
}

fn binding_from_proto(binding: ProtoSchemaBinding) -> Result<SchemaBinding, RebacError> {
    let scope = binding
        .scope
        .ok_or_else(|| RebacError::Internal("Anvil binding omitted its scope".into()))?;
    let schema_ref = binding
        .schema_ref
        .ok_or_else(|| RebacError::Internal("Anvil binding omitted its schema reference".into()))?;
    Ok(SchemaBinding {
        scope: scope_from_proto(scope),
        schema_ref: schema_ref_from_proto(schema_ref)?,
        binding_generation: BindingGeneration(binding.generation),
    })
}

fn object_to_proto(object: Object) -> ObjectRef {
    ObjectRef {
        namespace: object.namespace,
        id: Some(Id::OpaqueId(object.id)),
    }
}

fn object_from_proto(object: ObjectRef) -> Result<Object, RebacError> {
    match object.id {
        Some(Id::OpaqueId(id)) => Ok(Object {
            namespace: object.namespace,
            id,
        }),
        Some(Id::ExactPath(_)) => Err(RebacError::Internal(
            "Anvil returned an exact-path object that this Zanzibar model cannot represent".into(),
        )),
        None => Err(RebacError::Internal(
            "Anvil authorization object omitted its ID".into(),
        )),
    }
}

fn subject_to_proto(subject: Subject) -> ProtoSubject {
    let kind = match subject {
        Subject::Entity(object) => SubjectKind::Object(object_to_proto(object)),
        Subject::Userset { object, relation } => SubjectKind::Userset(Userset {
            object: Some(object_to_proto(object)),
            relation,
        }),
        Subject::Public => SubjectKind::Object(ObjectRef {
            namespace: ANVIL_PUBLIC_NAMESPACE.into(),
            id: Some(Id::OpaqueId(ANVIL_PUBLIC_ID.into())),
        }),
    };
    ProtoSubject { kind: Some(kind) }
}

fn subject_from_proto(subject: ProtoSubject) -> Result<Subject, RebacError> {
    match subject.kind {
        Some(SubjectKind::Object(object))
            if object.namespace == ANVIL_PUBLIC_NAMESPACE
                && object.id.as_ref().is_some_and(
                    |id| matches!(id, Id::OpaqueId(value) if value == ANVIL_PUBLIC_ID),
                ) =>
        {
            Ok(Subject::Public)
        }
        Some(SubjectKind::Object(object)) => object_from_proto(object).map(Subject::Entity),
        Some(SubjectKind::Userset(userset)) => {
            let object = userset.object.ok_or_else(|| {
                RebacError::Internal("Anvil userset subject omitted its object".into())
            })?;
            Ok(Subject::Userset {
                object: object_from_proto(object)?,
                relation: userset.relation,
            })
        }
        None => Err(RebacError::Internal(
            "Anvil authorization subject omitted its kind".into(),
        )),
    }
}

fn tuple_to_proto(tuple: Tuple) -> RelationTuple {
    RelationTuple {
        object: Some(object_to_proto(tuple.object)),
        relation: tuple.relation,
        subject: Some(subject_to_proto(tuple.subject)),
    }
}

fn tuple_from_proto(tuple: RelationTuple) -> Result<Tuple, RebacError> {
    let object = tuple.object.ok_or_else(|| {
        RebacError::Internal("Anvil authorization tuple omitted its object".into())
    })?;
    let subject = tuple.subject.ok_or_else(|| {
        RebacError::Internal("Anvil authorization tuple omitted its subject".into())
    })?;
    Ok(Tuple {
        object: object_from_proto(object)?,
        relation: tuple.relation,
        subject: subject_from_proto(subject)?,
    })
}

fn tuple_update_to_proto(update: TupleUpdate) -> Result<ProtoTupleMutation, RebacError> {
    let operation = match update {
        TupleUpdate::Add(tuple) => Operation::Add(tuple_to_proto(tuple)),
        TupleUpdate::Remove(tuple) => Operation::Remove(tuple_to_proto(tuple)),
    };
    Ok(ProtoTupleMutation {
        operation: Some(operation),
    })
}

fn tuple_filter_to_proto(filter: TupleFilter) -> ProtoTupleFilter {
    let object = filter.object.map(|filter| ProtoObjectFilter {
        selection: Some(match filter {
            ObjectFilter::Namespace(namespace) => Selection::Namespace(namespace),
            ObjectFilter::Exact(object) => Selection::Exact(object_to_proto(object)),
        }),
    });
    ProtoTupleFilter {
        object,
        relation: filter.relation,
        subject: filter.subject.map(subject_to_proto),
    }
}

fn consistency_to_proto(consistency: Consistency) -> ProtoConsistency {
    let requirement = match consistency {
        Consistency::Latest => Requirement::Latest(LatestConsistency {}),
        Consistency::AtLeast(revision) => Requirement::AtLeast(AtLeastRevision {
            revision: revision.0,
        }),
        Consistency::Exact(revision) => Requirement::Exact(ExactRevision {
            revision: revision.0,
        }),
    };
    ProtoConsistency {
        requirement: Some(requirement),
    }
}

fn check_to_proto(request: CheckRequest) -> Result<PermissionCheck, RebacError> {
    if matches!(request.subject, Subject::Userset { .. }) {
        return Err(RebacError::InvalidTuple(
            "permission checks require an entity or public subject, not a userset".into(),
        ));
    }
    Ok(PermissionCheck {
        subject: Some(subject_to_proto(request.subject)),
        object: Some(object_to_proto(request.object)),
        relation: request.relation,
    })
}

fn schema_to_proto(schema: &Schema) -> Result<Vec<ProtoNamespaceDefinition>, RebacError> {
    let mut namespaces = schema
        .namespaces
        .iter()
        .map(|(name, namespace)| {
            validate_component(name, "namespace")?;
            let mut relations = namespace
                .relations
                .iter()
                .map(|(name, definition)| {
                    validate_component(name, "relation")?;
                    Ok(ProtoRelationDefinition {
                        name: name.clone(),
                        kind: Some(relation_to_proto(definition.clone())?),
                    })
                })
                .collect::<Result<Vec<_>, RebacError>>()?;
            relations.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(ProtoNamespaceDefinition {
                name: name.clone(),
                relations,
            })
        })
        .collect::<Result<Vec<_>, RebacError>>()?;
    namespaces.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(namespaces)
}

fn relation_to_proto(definition: RelationDefinition) -> Result<RelationKind, RebacError> {
    match definition {
        RelationDefinition::Direct { allowed_subjects } => {
            if allowed_subjects.is_empty() {
                return Err(RebacError::InvalidSchema(
                    "a direct relation must allow at least one subject selector".into(),
                ));
            }
            Ok(RelationKind::Direct(DirectRelation {
                allowed_subjects: allowed_subjects
                    .into_iter()
                    .map(selector_to_proto)
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
        RelationDefinition::Permission { rules } => {
            if rules.is_empty() {
                return Err(RebacError::InvalidSchema(
                    "a permission must contain at least one rule".into(),
                ));
            }
            Ok(RelationKind::Permission(Permission {
                rules: rules
                    .into_iter()
                    .map(rule_to_proto)
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
    }
}

fn selector_to_proto(selector: SubjectSelector) -> Result<ProtoSubjectSelector, RebacError> {
    let selector = match selector {
        SubjectSelector::AnyObject { namespace } => {
            validate_component(&namespace, "subject namespace")?;
            Selector::AnyObject(AnyObjectSelector { namespace })
        }
        SubjectSelector::AnyUserset {
            namespace,
            relation,
        } => {
            validate_component(&namespace, "subject namespace")?;
            validate_component(&relation, "userset relation")?;
            Selector::AnyUserset(AnyUsersetSelector {
                namespace,
                relation,
            })
        }
        SubjectSelector::Exact(subject) => Selector::Exact(subject_to_proto(subject)),
        SubjectSelector::SameResourceId { namespace } => {
            validate_component(&namespace, "subject namespace")?;
            Selector::SameResourceId(SameResourceIdSelector { namespace })
        }
        SubjectSelector::Public => Selector::Public(PublicSubjectSelector {}),
    };
    Ok(ProtoSubjectSelector {
        selector: Some(selector),
    })
}

fn rule_to_proto(rule: PermissionRule) -> Result<ProtoPermissionRule, RebacError> {
    let rule = match rule {
        PermissionRule::Inherit { relation } => {
            validate_component(&relation, "inherited relation")?;
            Rule::Inherit(InheritRule { relation })
        }
        PermissionRule::TupleToUserset {
            tuple_relation,
            target_relation,
        } => {
            validate_component(&tuple_relation, "tuple relation")?;
            validate_component(&target_relation, "target relation")?;
            Rule::TupleToUserset(TupleToUsersetRule {
                tuple_relation,
                target_relation,
            })
        }
    };
    Ok(ProtoPermissionRule { rule: Some(rule) })
}

fn schema_from_proto(namespaces: Vec<ProtoNamespaceDefinition>) -> Result<Schema, RebacError> {
    let mut schema = Schema::default();
    for namespace in namespaces {
        let mut relations = std::collections::HashMap::new();
        for relation in namespace.relations {
            let definition = relation_from_proto(relation.kind.ok_or_else(|| {
                RebacError::Internal("Anvil schema relation omitted its kind".into())
            })?)?;
            relations.insert(relation.name, definition);
        }
        schema
            .namespaces
            .insert(namespace.name, NamespaceDefinition { relations });
    }
    Ok(schema)
}

fn relation_from_proto(kind: RelationKind) -> Result<RelationDefinition, RebacError> {
    match kind {
        RelationKind::Direct(direct) => Ok(RelationDefinition::Direct {
            allowed_subjects: direct
                .allowed_subjects
                .into_iter()
                .map(selector_from_proto)
                .collect::<Result<BTreeSet<_>, _>>()?,
        }),
        RelationKind::Permission(permission) => Ok(RelationDefinition::Permission {
            rules: permission
                .rules
                .into_iter()
                .map(rule_from_proto)
                .collect::<Result<BTreeSet<_>, _>>()?,
        }),
    }
}

fn selector_from_proto(selector: ProtoSubjectSelector) -> Result<SubjectSelector, RebacError> {
    match selector.selector {
        Some(Selector::AnyObject(selector)) => Ok(SubjectSelector::AnyObject {
            namespace: selector.namespace,
        }),
        Some(Selector::AnyUserset(selector)) => Ok(SubjectSelector::AnyUserset {
            namespace: selector.namespace,
            relation: selector.relation,
        }),
        Some(Selector::Exact(subject)) => subject_from_proto(subject).map(SubjectSelector::Exact),
        Some(Selector::SameResourceId(selector)) => Ok(SubjectSelector::SameResourceId {
            namespace: selector.namespace,
        }),
        Some(Selector::Public(_)) => Ok(SubjectSelector::Public),
        None => Err(RebacError::Internal(
            "Anvil schema subject selector omitted its kind".into(),
        )),
    }
}

fn rule_from_proto(rule: ProtoPermissionRule) -> Result<PermissionRule, RebacError> {
    match rule.rule {
        Some(Rule::Inherit(rule)) => Ok(PermissionRule::Inherit {
            relation: rule.relation,
        }),
        Some(Rule::TupleToUserset(rule)) => Ok(PermissionRule::TupleToUserset {
            tuple_relation: rule.tuple_relation,
            target_relation: rule.target_relation,
        }),
        None => Err(RebacError::Internal(
            "Anvil schema permission rule omitted its kind".into(),
        )),
    }
}

fn validate_component(value: &str, name: &str) -> Result<(), RebacError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.chars().any(char::is_control)
    {
        return Err(RebacError::InvalidSchema(format!(
            "invalid {name}: {value:?}"
        )));
    }
    Ok(())
}

fn map_schema_status(status: Status, schema_id: &SchemaId) -> RebacError {
    match status.code() {
        Code::NotFound => RebacError::SchemaNotFound(schema_id.0.clone()),
        Code::InvalidArgument => RebacError::InvalidSchema(status.message().into()),
        _ => map_status(status),
    }
}

fn map_binding_status(
    status: Status,
    schema_id: &SchemaId,
    expected: Option<BindingGeneration>,
) -> RebacError {
    match status.code() {
        Code::NotFound => RebacError::SchemaNotFound(schema_id.0.clone()),
        Code::Aborted if status.message().contains("binding generation") => {
            RebacError::SchemaBindingGenerationConflict {
                expected,
                actual: binding_generation_from_message(status.message()).map(BindingGeneration),
            }
        }
        Code::Aborted | Code::FailedPrecondition => {
            RebacError::SchemaBindingRejected(status.message().into())
        }
        _ => map_status(status),
    }
}

fn binding_generation_from_message(message: &str) -> Option<u64> {
    ["actual ", "current "].into_iter().find_map(|marker| {
        let value = message.split(marker).nth(1)?;
        let digits = value
            .trim_start_matches(|character: char| !character.is_ascii_digit())
            .split(|character: char| !character.is_ascii_digit())
            .next()?;
        digits.parse().ok()
    })
}

fn map_mutation_status(status: Status, scope: &AuthzScope) -> RebacError {
    match status.code() {
        Code::NotFound => RebacError::SchemaBindingNotFound(scope.clone()),
        Code::FailedPrecondition if status.message().contains("no schema binding") => {
            RebacError::SchemaBindingNotFound(scope.clone())
        }
        Code::InvalidArgument => RebacError::InvalidMutation(status.message().into()),
        _ => map_status(status),
    }
}

fn map_read_status(status: Status, scope: &AuthzScope) -> RebacError {
    match status.code() {
        Code::NotFound => RebacError::SchemaBindingNotFound(scope.clone()),
        Code::InvalidArgument => RebacError::InvalidReadRequest(status.message().into()),
        _ => map_status(status),
    }
}

fn map_check_status(status: Status, scope: &AuthzScope) -> RebacError {
    match status.code() {
        Code::NotFound => RebacError::SchemaBindingNotFound(scope.clone()),
        Code::InvalidArgument => RebacError::InvalidTuple(status.message().into()),
        _ => map_status(status),
    }
}

fn map_status(status: Status) -> RebacError {
    let message = status.message().to_owned();
    match status.code() {
        Code::Unauthenticated => RebacError::Unauthenticated(message),
        Code::PermissionDenied => RebacError::PermissionDenied(message),
        Code::Aborted | Code::AlreadyExists => RebacError::Conflict(message),
        Code::FailedPrecondition if message.contains("AUTHZ_REVISION_EXPIRED") => {
            RebacError::RevisionExpired(message)
        }
        Code::FailedPrecondition if message.contains("revision") => {
            RebacError::RevisionUnavailable(message)
        }
        Code::ResourceExhausted => RebacError::ResourceExhausted(message),
        Code::Unavailable | Code::DeadlineExceeded => RebacError::Unavailable(message),
        Code::Internal | Code::DataLoss | Code::Unknown => RebacError::Internal(message),
        _ => RebacError::Anvil(format!("{}: {message}", status.code())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::*;

    fn object(namespace: &str, id: &str) -> Object {
        Object {
            namespace: namespace.into(),
            id: id.into(),
        }
    }

    #[test]
    fn debug_output_redacts_the_client_secret() {
        let config = AnvilRebacConfig {
            endpoint: "https://anvil.example".into(),
            storage_tenant: "tenant-1".into(),
            client_id: "app-1".into(),
            client_secret: "do-not-print".into(),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("do-not-print"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn entity_userset_and_public_subjects_round_trip() {
        let subjects = [
            Subject::Entity(object("user", "alice")),
            Subject::Userset {
                object: object("group", "engineering"),
                relation: "member".into(),
            },
            Subject::Public,
        ];
        for subject in subjects {
            let decoded = subject_from_proto(subject_to_proto(subject.clone())).unwrap();
            assert_eq!(decoded, subject);
        }
    }

    #[test]
    fn schema_round_trips_without_string_encoded_rules() {
        let schema = Schema {
            namespaces: HashMap::from([
                (
                    "group".into(),
                    NamespaceDefinition {
                        relations: HashMap::from([(
                            "member".into(),
                            RelationDefinition::Direct {
                                allowed_subjects: BTreeSet::from([SubjectSelector::AnyObject {
                                    namespace: "user".into(),
                                }]),
                            },
                        )]),
                    },
                ),
                (
                    "document".into(),
                    NamespaceDefinition {
                        relations: HashMap::from([
                            (
                                "reader".into(),
                                RelationDefinition::Direct {
                                    allowed_subjects: BTreeSet::from([
                                        SubjectSelector::AnyObject {
                                            namespace: "user".into(),
                                        },
                                        SubjectSelector::AnyUserset {
                                            namespace: "group".into(),
                                            relation: "member".into(),
                                        },
                                        SubjectSelector::Public,
                                    ]),
                                },
                            ),
                            (
                                "can_read".into(),
                                RelationDefinition::Permission {
                                    rules: BTreeSet::from([PermissionRule::Inherit {
                                        relation: "reader".into(),
                                    }]),
                                },
                            ),
                        ]),
                    },
                ),
            ]),
        };
        let decoded = schema_from_proto(schema_to_proto(&schema).unwrap()).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn schema_selectors_and_rules_have_canonical_set_order() {
        let selectors = BTreeSet::from([
            SubjectSelector::Public,
            SubjectSelector::AnyUserset {
                namespace: "group".into(),
                relation: "member".into(),
            },
            SubjectSelector::AnyObject {
                namespace: "user".into(),
            },
        ]);
        let same_selectors = [
            SubjectSelector::AnyObject {
                namespace: "user".into(),
            },
            SubjectSelector::Public,
            SubjectSelector::AnyUserset {
                namespace: "group".into(),
                relation: "member".into(),
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(selectors, same_selectors);
        assert_eq!(
            relation_to_proto(RelationDefinition::Direct {
                allowed_subjects: selectors,
            })
            .unwrap(),
            relation_to_proto(RelationDefinition::Direct {
                allowed_subjects: same_selectors,
            })
            .unwrap()
        );

        let rules = BTreeSet::from([
            PermissionRule::TupleToUserset {
                tuple_relation: "parent".into(),
                target_relation: "viewer".into(),
            },
            PermissionRule::Inherit {
                relation: "reader".into(),
            },
        ]);
        let same_rules = [
            PermissionRule::Inherit {
                relation: "reader".into(),
            },
            PermissionRule::TupleToUserset {
                tuple_relation: "parent".into(),
                target_relation: "viewer".into(),
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(rules, same_rules);
        assert_eq!(
            relation_to_proto(RelationDefinition::Permission { rules }).unwrap(),
            relation_to_proto(RelationDefinition::Permission { rules: same_rules }).unwrap()
        );
    }

    #[test]
    fn tuple_round_trip_preserves_a_typed_userset() {
        let tuple = Tuple {
            object: object("document", "roadmap"),
            relation: "reader".into(),
            subject: Subject::Userset {
                object: object("group", "engineering"),
                relation: "member".into(),
            },
        };
        assert_eq!(
            tuple_from_proto(tuple_to_proto(tuple.clone())).unwrap(),
            tuple
        );
    }

    #[test]
    fn exact_and_at_least_consistency_use_numeric_revisions() {
        assert!(matches!(
            consistency_to_proto(Consistency::Exact(AuthzRevision(7))).requirement,
            Some(Requirement::Exact(ExactRevision { revision: 7 }))
        ));
        assert!(matches!(
            consistency_to_proto(Consistency::AtLeast(AuthzRevision(9))).requirement,
            Some(Requirement::AtLeast(AtLeastRevision { revision: 9 }))
        ));
    }

    #[test]
    fn status_mapping_distinguishes_authz_failures() {
        assert!(matches!(
            map_status(Status::unauthenticated("bad token")),
            RebacError::Unauthenticated(_)
        ));
        assert!(matches!(
            map_status(Status::permission_denied("forbidden")),
            RebacError::PermissionDenied(_)
        ));
        assert!(matches!(
            map_status(Status::failed_precondition(
                "AUTHZ_REVISION_EXPIRED: no longer current"
            )),
            RebacError::RevisionExpired(_)
        ));
        assert!(matches!(
            map_status(Status::aborted("revision conflict")),
            RebacError::Conflict(_)
        ));
    }

    #[test]
    fn operation_status_mapping_preserves_missing_schema_and_binding() {
        let scope = AuthzScope::new("tenant", "realm");
        let schema_id = SchemaId("missing".into());
        assert!(matches!(
            map_binding_status(Status::not_found("schema missing"), &schema_id, None),
            RebacError::SchemaNotFound(id) if id == "missing"
        ));
        assert!(matches!(
            map_mutation_status(Status::not_found("binding missing"), &scope),
            RebacError::SchemaBindingNotFound(found) if found == scope
        ));
        assert!(matches!(
            map_mutation_status(
                Status::failed_precondition("authorization realm has no schema binding"),
                &scope,
            ),
            RebacError::SchemaBindingNotFound(found) if found == scope
        ));
        assert!(matches!(
            map_read_status(Status::not_found("binding missing"), &scope),
            RebacError::SchemaBindingNotFound(found) if found == scope
        ));
        assert!(matches!(
            map_check_status(Status::not_found("binding missing"), &scope),
            RebacError::SchemaBindingNotFound(found) if found == scope
        ));
    }

    #[test]
    fn binding_conflict_extracts_the_actual_generation_when_available() {
        assert_eq!(
            binding_generation_from_message("expected Some(3), current Some(5)"),
            Some(5)
        );
    }
}
