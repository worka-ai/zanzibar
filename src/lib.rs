#![doc = include_str!("../README.md")]

pub mod keldra;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    time::SystemTime,
};

pub const SCHEMA_DIGEST_LENGTH: usize = 32;
pub const MAX_MUTATIONS_PER_REQUEST: usize = 1_000;
pub const MAX_OPERATION_ID_BYTES: usize = 128;
pub const MAX_READ_PAGE_SIZE: u32 = 1_000;

/// Identifies one object in an authorization graph.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Object {
    pub namespace: String,
    pub id: String,
}

impl std::fmt::Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.id)
    }
}

/// An object, a userset, or Keldra's reserved public principal.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Subject {
    /// A specific entity such as `user:alice`.
    Entity(Object),
    /// Every subject related to an object, such as `group:editors#member`.
    Userset { object: Object, relation: String },
    /// Keldra's reserved `app:_keldra/public` principal.
    Public,
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subject::Entity(object) => write!(f, "{object}"),
            Subject::Userset { object, relation } => write!(f, "{object}#{relation}"),
            Subject::Public => f.write_str("app:_keldra/public"),
        }
    }
}

impl Subject {
    pub fn namespace(&self) -> &str {
        match self {
            Subject::Entity(object) => &object.namespace,
            Subject::Userset { object, .. } => &object.namespace,
            Subject::Public => "app",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Subject::Entity(object) => &object.id,
            Subject::Userset { object, .. } => &object.id,
            Subject::Public => "_keldra/public",
        }
    }

    pub fn relation(&self) -> Option<&str> {
        match self {
            Subject::Userset { relation, .. } => Some(relation),
            Subject::Entity(_) | Subject::Public => None,
        }
    }
}

/// The statement "subject has relation to object".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub object: Object,
    pub relation: String,
    pub subject: Subject,
}

/// One idempotent set mutation within an atomic tuple batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TupleUpdate {
    Add(Tuple),
    Remove(Tuple),
}

/// The subjects accepted by a direct relation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubjectSelector {
    AnyObject { namespace: String },
    AnyUserset { namespace: String, relation: String },
    Exact(Subject),
    SameResourceId { namespace: String },
    Public,
}

/// One rule contributing to a derived permission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermissionRule {
    Inherit {
        relation: String,
    },
    TupleToUserset {
        tuple_relation: String,
        target_relation: String,
    },
}

/// A schema member is either tuple-bearing or derived; it cannot be both.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationDefinition {
    Direct {
        allowed_subjects: BTreeSet<SubjectSelector>,
    },
    Permission {
        rules: BTreeSet<PermissionRule>,
    },
}

/// All relations and permissions declared by one object namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceDefinition {
    pub relations: HashMap<String, RelationDefinition>,
}

impl NamespaceDefinition {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn relation(mut self, name: impl Into<String>, definition: RelationDefinition) -> Self {
        self.relations.insert(name.into(), definition);
        self
    }
}

/// An immutable authorization schema body.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schema {
    pub namespaces: HashMap<String, NamespaceDefinition>,
}

pub struct SchemaBuilder {
    schema: Schema,
}

impl SchemaBuilder {
    pub fn new() -> Self {
        Self {
            schema: Schema::default(),
        }
    }

    pub fn namespace(mut self, name: impl Into<String>, definition: NamespaceDefinition) -> Self {
        self.schema.namespaces.insert(name.into(), definition);
        self
    }

    pub fn build(self) -> Schema {
        self.schema
    }
}

impl Default for SchemaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RebacError {
    #[error("Keldra authorization error: {0}")]
    Keldra(String),
    #[error("authentication failed: {0}")]
    Unauthenticated(String),
    #[error("authorization denied: {0}")]
    PermissionDenied(String),
    #[error("schema not found: {0}")]
    SchemaNotFound(String),
    #[error("schema binding not found for scope: {0:?}")]
    SchemaBindingNotFound(AuthzScope),
    #[error("schema binding rejected: {0}")]
    SchemaBindingRejected(String),
    #[error("schema binding generation conflict: expected {expected:?}, actual {actual:?}")]
    SchemaBindingGenerationConflict {
        expected: Option<BindingGeneration>,
        actual: Option<BindingGeneration>,
    },
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    #[error("invalid tuple: {0}")]
    InvalidTuple(String),
    #[error("invalid tuple mutation: {0}")]
    InvalidMutation(String),
    #[error("invalid tuple read: {0}")]
    InvalidReadRequest(String),
    #[error("authorization revision expired: {0}")]
    RevisionExpired(String),
    #[error("authorization revision is not available yet: {0}")]
    RevisionUnavailable(String),
    #[error("authorization conflict: {0}")]
    Conflict(String),
    #[error("authorization capacity exhausted: {0}")]
    ResourceExhausted(String),
    #[error("authorization service unavailable: {0}")]
    Unavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRequest {
    pub subject: Subject,
    pub relation: String,
    pub object: Object,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeldraStorageTenantId(pub String);

impl From<&str> for KeldraStorageTenantId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for KeldraStorageTenantId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthzRealmId(pub String);

impl From<&str> for AuthzRealmId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for AuthzRealmId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthzScope {
    pub keldra_tenant_id: KeldraStorageTenantId,
    pub authz_realm_id: AuthzRealmId,
}

impl AuthzScope {
    pub fn new(
        keldra_tenant_id: impl Into<KeldraStorageTenantId>,
        authz_realm_id: impl Into<AuthzRealmId>,
    ) -> Self {
        Self {
            keldra_tenant_id: keldra_tenant_id.into(),
            authz_realm_id: authz_realm_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub String);

impl From<&str> for SchemaId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for SchemaId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaRevision(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BindingGeneration(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthzRevision(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub schema_id: SchemaId,
    pub schema_revision: SchemaRevision,
    pub schema_digest: [u8; SCHEMA_DIGEST_LENGTH],
}

impl SchemaRef {
    pub fn new(
        schema_id: impl Into<SchemaId>,
        schema_revision: SchemaRevision,
        schema_digest: impl AsRef<[u8]>,
    ) -> Result<Self, RebacError> {
        let schema_digest = schema_digest.as_ref();
        let actual_length = schema_digest.len();
        let schema_digest = schema_digest.try_into().map_err(|_| {
            RebacError::InvalidSchema(format!(
                "schema digest must be {SCHEMA_DIGEST_LENGTH} bytes, got {actual_length}"
            ))
        })?;

        Ok(Self {
            schema_id: schema_id.into(),
            schema_revision,
            schema_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaBinding {
    pub scope: AuthzScope,
    pub schema_ref: SchemaRef,
    pub binding_generation: BindingGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutSchemaResult {
    pub schema_ref: SchemaRef,
    pub revision: AuthzRevision,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindSchemaResult {
    pub binding: SchemaBinding,
    pub revision: AuthzRevision,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consistency {
    #[default]
    Latest,
    AtLeast(AuthzRevision),
    Exact(AuthzRevision),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectFilter {
    Namespace(String),
    Exact(Object),
}

/// Omitted fields are wildcards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleFilter {
    pub object: Option<ObjectFilter>,
    pub relation: Option<String>,
    pub subject: Option<Subject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadTuplesRequest {
    pub scope: AuthzScope,
    pub filter: TupleFilter,
    pub consistency: Consistency,
    /// Zero selects Keldra's server default. The maximum is 1,000.
    pub page_size: u32,
    pub page_token: Option<String>,
}

impl ReadTuplesRequest {
    pub fn new(scope: AuthzScope) -> Self {
        Self {
            scope,
            filter: TupleFilter::default(),
            consistency: Consistency::Latest,
            page_size: 0,
            page_token: None,
        }
    }

    pub fn with_filter(mut self, filter: TupleFilter) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_consistency(mut self, consistency: Consistency) -> Self {
        self.consistency = consistency;
        self
    }

    pub fn with_page_size(mut self, page_size: u32) -> Result<Self, RebacError> {
        if page_size > MAX_READ_PAGE_SIZE {
            return Err(RebacError::InvalidReadRequest(format!(
                "page size must be at most {MAX_READ_PAGE_SIZE}, got {page_size}"
            )));
        }
        self.page_size = page_size;
        Ok(self)
    }

    pub fn with_page_token(mut self, page_token: impl Into<String>) -> Self {
        self.page_token = Some(page_token.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadTuplesPage {
    pub tuples: Vec<Tuple>,
    pub revision: AuthzRevision,
    pub next_page_token: Option<String>,
}

/// One validated all-or-nothing tuple mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutateTuplesRequest {
    scope: AuthzScope,
    operation_id: String,
    expected_revision: Option<AuthzRevision>,
    updates: Vec<TupleUpdate>,
}

impl MutateTuplesRequest {
    pub fn new(
        scope: AuthzScope,
        operation_id: impl Into<String>,
        updates: Vec<TupleUpdate>,
    ) -> Result<Self, RebacError> {
        let operation_id = operation_id.into();
        if operation_id.is_empty() {
            return Err(RebacError::InvalidMutation(
                "operation ID must not be empty".to_string(),
            ));
        }
        if operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(RebacError::InvalidMutation(format!(
                "operation ID must be at most {MAX_OPERATION_ID_BYTES} bytes"
            )));
        }
        if updates.is_empty() {
            return Err(RebacError::InvalidMutation(
                "at least one tuple update is required".to_string(),
            ));
        }
        if updates.len() > MAX_MUTATIONS_PER_REQUEST {
            return Err(RebacError::InvalidMutation(format!(
                "at most {MAX_MUTATIONS_PER_REQUEST} tuple updates are allowed"
            )));
        }

        Ok(Self {
            scope,
            operation_id,
            expected_revision: None,
            updates,
        })
    }

    pub fn with_expected_revision(mut self, revision: AuthzRevision) -> Self {
        self.expected_revision = Some(revision);
        self
    }

    pub fn scope(&self) -> &AuthzScope {
        &self.scope
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn expected_revision(&self) -> Option<AuthzRevision> {
        self.expected_revision
    }

    pub fn updates(&self) -> &[TupleUpdate] {
        &self.updates
    }

    pub fn into_parts(self) -> (AuthzScope, String, Option<AuthzRevision>, Vec<TupleUpdate>) {
        (
            self.scope,
            self.operation_id,
            self.expected_revision,
            self.updates,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutateTuplesResult {
    pub revision: AuthzRevision,
    pub replayed: bool,
    pub replay_guarantee_expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckDecision {
    pub allowed: bool,
    pub revision: AuthzRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckManyResult {
    /// Decisions retain request order and were evaluated at `revision`.
    pub decisions: Vec<bool>,
    pub revision: AuthzRevision,
}

#[async_trait]
pub trait RebacEngine: Send + Sync {
    async fn put_schema(
        &self,
        storage_tenant: &KeldraStorageTenantId,
        schema_id: SchemaId,
        schema: Schema,
    ) -> Result<PutSchemaResult, RebacError>;

    async fn get_schema(
        &self,
        storage_tenant: &KeldraStorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<(SchemaRef, Schema), RebacError>;

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<BindSchemaResult, RebacError>;

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError>;

    async fn mutate_tuples(
        &self,
        request: MutateTuplesRequest,
    ) -> Result<MutateTuplesResult, RebacError>;

    async fn read_tuples(&self, request: ReadTuplesRequest) -> Result<ReadTuplesPage, RebacError>;

    async fn check(
        &self,
        scope: &AuthzScope,
        request: CheckRequest,
        consistency: Consistency,
    ) -> Result<CheckDecision, RebacError>;

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<CheckRequest>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError>;
}

pub async fn put_and_bind_schema(
    engine: &dyn RebacEngine,
    scope: &AuthzScope,
    schema_id: SchemaId,
    schema: Schema,
    expected_generation: Option<BindingGeneration>,
) -> Result<BindSchemaResult, RebacError> {
    let published = engine
        .put_schema(&scope.keldra_tenant_id, schema_id, schema)
        .await?;
    engine
        .bind_schema(scope, published.schema_ref, expected_generation)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(namespace: &str, id: &str) -> Object {
        Object {
            namespace: namespace.into(),
            id: id.into(),
        }
    }

    fn tuple() -> Tuple {
        Tuple {
            object: object("document", "roadmap"),
            relation: "viewer".into(),
            subject: Subject::Entity(object("user", "alice")),
        }
    }

    #[test]
    fn displays_typed_subjects() {
        assert_eq!(object("doc", "1").to_string(), "doc:1");
        assert_eq!(
            Subject::Entity(object("user", "alice")).to_string(),
            "user:alice"
        );
        assert_eq!(
            Subject::Userset {
                object: object("group", "editors"),
                relation: "member".into(),
            }
            .to_string(),
            "group:editors#member"
        );
        assert_eq!(Subject::Public.to_string(), "app:_keldra/public");
        assert_eq!(Subject::Public.namespace(), "app");
        assert_eq!(Subject::Public.id(), "_keldra/public");
        assert_eq!(Subject::Public.relation(), None);
    }

    #[test]
    fn schema_keeps_direct_relations_and_permissions_distinct() {
        let schema = SchemaBuilder::new()
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
                                SubjectSelector::Exact(Subject::Entity(object(
                                    "service-account",
                                    "indexer",
                                ))),
                                SubjectSelector::SameResourceId {
                                    namespace: "document-owner".into(),
                                },
                                SubjectSelector::Public,
                            ]),
                        },
                    )
                    .relation(
                        "can_read",
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
            .build();

        let document = &schema.namespaces["document"];
        assert!(matches!(
            document.relations["viewer"],
            RelationDefinition::Direct { .. }
        ));
        assert!(matches!(
            document.relations["can_read"],
            RelationDefinition::Permission { .. }
        ));
    }

    #[test]
    fn schema_reference_requires_a_32_byte_digest() {
        let schema_ref = SchemaRef::new("documents", SchemaRevision(7), [9_u8; 32]).unwrap();
        assert_eq!(schema_ref.schema_digest, [9_u8; 32]);

        let error = SchemaRef::new("documents", SchemaRevision(7), [9_u8; 31]).unwrap_err();
        assert!(matches!(error, RebacError::InvalidSchema(_)));
        assert!(error.to_string().contains("32 bytes, got 31"));
    }

    #[test]
    fn read_request_exposes_native_filters_and_consistency() {
        let request = ReadTuplesRequest::new(AuthzScope::new("tenant", "default"))
            .with_filter(TupleFilter {
                object: Some(ObjectFilter::Namespace("document".into())),
                relation: Some("viewer".into()),
                subject: Some(Subject::Entity(object("user", "alice"))),
            })
            .with_consistency(Consistency::AtLeast(AuthzRevision(42)))
            .with_page_size(250)
            .unwrap()
            .with_page_token("next");

        assert_eq!(request.page_size, 250);
        assert_eq!(request.page_token.as_deref(), Some("next"));
        assert_eq!(request.consistency, Consistency::AtLeast(AuthzRevision(42)));
        assert!(matches!(
            request.filter.object,
            Some(ObjectFilter::Namespace(ref namespace)) if namespace == "document"
        ));

        let error = ReadTuplesRequest::new(AuthzScope::new("tenant", "default"))
            .with_page_size(MAX_READ_PAGE_SIZE + 1)
            .unwrap_err();
        assert!(matches!(error, RebacError::InvalidReadRequest(_)));
    }

    #[test]
    fn mutation_requires_a_caller_id_and_nonempty_bounded_updates() {
        let scope = AuthzScope::new("tenant", "default");
        assert!(matches!(
            MutateTuplesRequest::new(scope.clone(), "", vec![TupleUpdate::Add(tuple())]),
            Err(RebacError::InvalidMutation(_))
        ));
        assert!(matches!(
            MutateTuplesRequest::new(scope.clone(), "operation-1", Vec::new()),
            Err(RebacError::InvalidMutation(_))
        ));
        assert!(matches!(
            MutateTuplesRequest::new(
                scope.clone(),
                "x".repeat(MAX_OPERATION_ID_BYTES + 1),
                vec![TupleUpdate::Add(tuple())]
            ),
            Err(RebacError::InvalidMutation(_))
        ));
        assert!(matches!(
            MutateTuplesRequest::new(
                scope.clone(),
                "operation-too-large",
                vec![TupleUpdate::Add(tuple()); MAX_MUTATIONS_PER_REQUEST + 1]
            ),
            Err(RebacError::InvalidMutation(_))
        ));

        let request = MutateTuplesRequest::new(
            scope.clone(),
            "operation-2",
            vec![TupleUpdate::Add(tuple())],
        )
        .unwrap()
        .with_expected_revision(AuthzRevision(8));

        assert_eq!(request.scope(), &scope);
        assert_eq!(request.operation_id(), "operation-2");
        assert_eq!(request.expected_revision(), Some(AuthzRevision(8)));
        assert_eq!(request.updates().len(), 1);
    }
}
