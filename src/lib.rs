#![doc = include_str!("../README.md")]

mod identity;
pub mod keldra;
pub use identity::ObjectId;

/// Opt-in models that can mix opaque subjects with exact-path resources.
/// Legacy root-level model names remain concrete opaque-ID models.
pub mod exact_path {
    pub use super::ObjectId;
    pub type KeldraRebacEngine = super::keldra::TypedKeldraRebacEngine<ObjectId>;
    pub type Object = super::TypedObject<ObjectId>;
    pub type Subject = super::TypedSubject<ObjectId>;
    pub type Tuple = super::TypedTuple<ObjectId>;
    pub type TupleUpdate = super::TypedTupleUpdate<ObjectId>;
    pub type SubjectSelector = super::TypedSubjectSelector<ObjectId>;
    pub type RelationDefinition = super::TypedRelationDefinition<ObjectId>;
    pub type NamespaceDefinition = super::TypedNamespaceDefinition<ObjectId>;
    pub type Schema = super::TypedSchema<ObjectId>;
    pub type SchemaBuilder = super::TypedSchemaBuilder<ObjectId>;
    pub type CheckRequest = super::TypedCheckRequest<ObjectId>;
    pub type ObjectFilter = super::TypedObjectFilter<ObjectId>;
    pub type TupleFilter = super::TypedTupleFilter<ObjectId>;
    pub type ReadTuplesRequest = super::TypedReadTuplesRequest<ObjectId>;
    pub type ReadTuplesPage = super::TypedReadTuplesPage<ObjectId>;
    pub type MutateTuplesRequest = super::TypedMutateTuplesRequest<ObjectId>;
}

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;

pub const SCHEMA_DIGEST_LENGTH: usize = 32;
pub const MAX_MUTATIONS_PER_REQUEST: usize = 1_000;
pub const MAX_OPERATION_ID_BYTES: usize = 128;
pub const MAX_READ_PAGE_SIZE: u32 = 1_000;

/// Identifies one object in an authorization graph.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TypedObject<I> {
    pub namespace: String,
    pub id: I,
}
pub type Object = TypedObject<String>;

impl<I: std::fmt::Display> std::fmt::Display for TypedObject<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.id)
    }
}

/// An object, a userset, or Keldra's reserved public principal.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TypedSubject<I> {
    /// A specific entity such as `user:alice`.
    Entity(TypedObject<I>),
    /// Every subject related to an object, such as `group:editors#member`.
    Userset {
        object: TypedObject<I>,
        relation: String,
    },
    /// Keldra's reserved `app:_keldra/public` principal.
    Public,
}
pub type Subject = TypedSubject<String>;

impl<I: std::fmt::Display> std::fmt::Display for TypedSubject<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entity(object) => write!(f, "{object}"),
            Self::Userset { object, relation } => write!(f, "{object}#{relation}"),
            Self::Public => f.write_str("app:_keldra/public"),
        }
    }
}

impl<I> TypedSubject<I> {
    pub fn namespace(&self) -> &str {
        match self {
            Self::Entity(object) => &object.namespace,
            Self::Userset { object, .. } => &object.namespace,
            Self::Public => "app",
        }
    }

    /// Typed graph identity; the reserved public principal has no user object.
    pub fn object_id(&self) -> Option<&I> {
        match self {
            Self::Entity(object) | Self::Userset { object, .. } => Some(&object.id),
            Self::Public => None,
        }
    }

    pub fn relation(&self) -> Option<&str> {
        match self {
            Self::Userset { relation, .. } => Some(relation),
            Self::Entity(_) | Self::Public => None,
        }
    }
}
impl TypedSubject<String> {
    /// The legacy opaque ID accessor, including the reserved public ID.
    pub fn id(&self) -> &str {
        match self {
            Self::Entity(object) | Self::Userset { object, .. } => &object.id,
            Self::Public => "_keldra/public",
        }
    }
}

/// The statement "subject has relation to object".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TypedTuple<I> {
    pub object: TypedObject<I>,
    pub relation: String,
    pub subject: TypedSubject<I>,
}
pub type Tuple = TypedTuple<String>;

/// One relationship update within an atomic tuple batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TypedTupleUpdate<I> {
    Add(TypedTuple<I>),
    Remove(TypedTuple<I>),
}
pub type TupleUpdate = TypedTupleUpdate<String>;

/// The subjects accepted by a direct relation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypedSubjectSelector<I> {
    AnyObject { namespace: String },
    AnyUserset { namespace: String, relation: String },
    Exact(TypedSubject<I>),
    SameResourceId { namespace: String },
    Public,
}
pub type SubjectSelector = TypedSubjectSelector<String>;

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
#[serde(bound(deserialize = "I: Deserialize<'de> + Ord"))]
pub enum TypedRelationDefinition<I> {
    Direct {
        allowed_subjects: BTreeSet<TypedSubjectSelector<I>>,
    },
    Permission {
        rules: BTreeSet<PermissionRule>,
    },
}
pub type RelationDefinition = TypedRelationDefinition<String>;

/// All relations and permissions declared by one object namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(deserialize = "I: Deserialize<'de> + Ord"))]
pub struct TypedNamespaceDefinition<I> {
    pub relations: HashMap<String, TypedRelationDefinition<I>>,
}
pub type NamespaceDefinition = TypedNamespaceDefinition<String>;

impl<I> Default for TypedNamespaceDefinition<I> {
    fn default() -> Self {
        Self {
            relations: HashMap::new(),
        }
    }
}
impl<I> TypedNamespaceDefinition<I> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn relation(
        mut self,
        name: impl Into<String>,
        definition: TypedRelationDefinition<I>,
    ) -> Self {
        self.relations.insert(name.into(), definition);
        self
    }
}

/// An immutable authorization schema body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(deserialize = "I: Deserialize<'de> + Ord"))]
pub struct TypedSchema<I> {
    pub namespaces: HashMap<String, TypedNamespaceDefinition<I>>,
}
pub type Schema = TypedSchema<String>;

pub struct TypedSchemaBuilder<I> {
    schema: TypedSchema<I>,
}
pub type SchemaBuilder = TypedSchemaBuilder<String>;

impl<I> Default for TypedSchema<I> {
    fn default() -> Self {
        Self {
            namespaces: HashMap::new(),
        }
    }
}
impl<I> TypedSchemaBuilder<I> {
    pub fn new() -> Self {
        Self {
            schema: TypedSchema::default(),
        }
    }

    pub fn namespace(
        mut self,
        name: impl Into<String>,
        definition: TypedNamespaceDefinition<I>,
    ) -> Self {
        self.schema.namespaces.insert(name.into(), definition);
        self
    }

    pub fn build(self) -> TypedSchema<I> {
        self.schema
    }
}

impl<I> Default for TypedSchemaBuilder<I> {
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
pub struct TypedCheckRequest<I> {
    pub subject: TypedSubject<I>,
    pub relation: String,
    pub object: TypedObject<I>,
}
pub type CheckRequest = TypedCheckRequest<String>;

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
pub enum TypedObjectFilter<I> {
    Namespace(String),
    Exact(TypedObject<I>),
}
pub type ObjectFilter = TypedObjectFilter<String>;

/// Omitted fields are wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedTupleFilter<I> {
    pub object: Option<TypedObjectFilter<I>>,
    pub relation: Option<String>,
    pub subject: Option<TypedSubject<I>>,
}
pub type TupleFilter = TypedTupleFilter<String>;
impl<I> Default for TypedTupleFilter<I> {
    fn default() -> Self {
        Self {
            object: None,
            relation: None,
            subject: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedReadTuplesRequest<I> {
    pub scope: AuthzScope,
    pub filter: TypedTupleFilter<I>,
    pub consistency: Consistency,
    /// Zero selects Keldra's server default. The maximum is 1,000.
    pub page_size: u32,
    pub page_token: Option<String>,
}
pub type ReadTuplesRequest = TypedReadTuplesRequest<String>;

impl<I> TypedReadTuplesRequest<I> {
    pub fn new(scope: AuthzScope) -> Self {
        Self {
            scope,
            filter: TypedTupleFilter::default(),
            consistency: Consistency::Latest,
            page_size: 0,
            page_token: None,
        }
    }

    pub fn with_filter(mut self, filter: TypedTupleFilter<I>) -> Self {
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
pub struct TypedReadTuplesPage<I> {
    pub tuples: Vec<TypedTuple<I>>,
    pub revision: AuthzRevision,
    pub next_page_token: Option<String>,
}
pub type ReadTuplesPage = TypedReadTuplesPage<String>;

/// One validated all-or-nothing tuple mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedMutateTuplesRequest<I> {
    scope: AuthzScope,
    operation_id: Option<String>,
    expected_revision: Option<AuthzRevision>,
    updates: Vec<TypedTupleUpdate<I>>,
}
pub type MutateTuplesRequest = TypedMutateTuplesRequest<String>;

impl<I> TypedMutateTuplesRequest<I> {
    pub fn new(scope: AuthzScope, updates: Vec<TypedTupleUpdate<I>>) -> Result<Self, RebacError> {
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
            operation_id: None,
            expected_revision: None,
            updates,
        })
    }

    pub fn with_expected_revision(mut self, revision: AuthzRevision) -> Self {
        self.expected_revision = Some(revision);
        self
    }

    /// Requests five-minute, RAM-only replay protection for this command.
    /// This is not durable and does not survive server restart.
    pub fn with_operation_id(
        mut self,
        operation_id: impl Into<String>,
    ) -> Result<Self, RebacError> {
        let operation_id = operation_id.into();
        if operation_id.is_empty() || operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(RebacError::InvalidMutation(format!(
                "operation ID must contain 1 to {MAX_OPERATION_ID_BYTES} bytes"
            )));
        }
        self.operation_id = Some(operation_id);
        Ok(self)
    }

    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }

    pub fn scope(&self) -> &AuthzScope {
        &self.scope
    }

    pub fn expected_revision(&self) -> Option<AuthzRevision> {
        self.expected_revision
    }

    pub fn updates(&self) -> &[TypedTupleUpdate<I>] {
        &self.updates
    }

    pub fn into_parts(self) -> (AuthzScope, Option<AuthzRevision>, Vec<TypedTupleUpdate<I>>) {
        (self.scope, self.expected_revision, self.updates)
    }

    /// Includes the optional command ID for adapters that support RAM-only replay.
    pub fn into_parts_with_operation_id(
        self,
    ) -> (
        AuthzScope,
        Option<String>,
        Option<AuthzRevision>,
        Vec<TypedTupleUpdate<I>>,
    ) {
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
    /// Whether this response reused an earlier result held in server RAM.
    pub replayed: bool,
    /// End of the five-minute RAM-only replay window, when an ID was supplied.
    /// This is not a durable guarantee and does not survive server restart.
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
pub trait RebacEngine<I: Send + Sync + 'static = String>: Send + Sync {
    async fn put_schema(
        &self,
        storage_tenant: &KeldraStorageTenantId,
        schema_id: SchemaId,
        schema: TypedSchema<I>,
    ) -> Result<PutSchemaResult, RebacError>;

    async fn get_schema(
        &self,
        storage_tenant: &KeldraStorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<(SchemaRef, TypedSchema<I>), RebacError>;

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<BindSchemaResult, RebacError>;

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError>;

    async fn mutate_tuples(
        &self,
        request: TypedMutateTuplesRequest<I>,
    ) -> Result<MutateTuplesResult, RebacError>;

    async fn read_tuples(
        &self,
        request: TypedReadTuplesRequest<I>,
    ) -> Result<TypedReadTuplesPage<I>, RebacError>;

    async fn check(
        &self,
        scope: &AuthzScope,
        request: TypedCheckRequest<I>,
        consistency: Consistency,
    ) -> Result<CheckDecision, RebacError>;

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<TypedCheckRequest<I>>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError>;
}

pub async fn put_and_bind_schema<I: Send + Sync + 'static>(
    engine: &dyn RebacEngine<I>,
    scope: &AuthzScope,
    schema_id: SchemaId,
    schema: TypedSchema<I>,
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
    fn mutation_requires_nonempty_bounded_updates() {
        let scope = AuthzScope::new("tenant", "default");
        assert!(matches!(
            MutateTuplesRequest::new(scope.clone(), Vec::new()),
            Err(RebacError::InvalidMutation(_))
        ));
        assert!(matches!(
            MutateTuplesRequest::new(
                scope.clone(),
                vec![TupleUpdate::Add(tuple()); MAX_MUTATIONS_PER_REQUEST + 1]
            ),
            Err(RebacError::InvalidMutation(_))
        ));
        let request = MutateTuplesRequest::new(scope.clone(), vec![TupleUpdate::Add(tuple())])
            .unwrap()
            .with_expected_revision(AuthzRevision(8));
        assert_eq!(request.scope(), &scope);
        assert_eq!(request.operation_id(), None);
        assert_eq!(request.expected_revision(), Some(AuthzRevision(8)));
        assert_eq!(request.updates().len(), 1);
        let (actual_scope, expected, updates) = request.into_parts();
        assert_eq!(actual_scope, scope);
        assert_eq!(expected, Some(AuthzRevision(8)));
        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn mutation_operation_id_is_optional_and_validated_in_bytes() {
        let request = || {
            MutateTuplesRequest::new(
                AuthzScope::new("tenant", "default"),
                vec![TupleUpdate::Add(tuple())],
            )
            .unwrap()
        };
        assert!(request().with_operation_id("").is_err());
        assert!(
            request()
                .with_operation_id("a".repeat(MAX_OPERATION_ID_BYTES + 1))
                .is_err()
        );
        assert!(request().with_operation_id("é".repeat(65)).is_err());
        let id = "é".repeat(64);
        let request = request()
            .with_expected_revision(AuthzRevision(9))
            .with_operation_id(id.clone())
            .unwrap();
        assert_eq!(request.operation_id(), Some(id.as_str()));
        let (scope, operation_id, revision, updates) = request.into_parts_with_operation_id();
        assert_eq!(scope, AuthzScope::new("tenant", "default"));
        assert_eq!(operation_id, Some(id));
        assert_eq!(revision, Some(AuthzRevision(9)));
        assert_eq!(updates, vec![TupleUpdate::Add(tuple())]);
    }

    #[test]
    fn mutation_legacy_parts_remain_available_with_optional_operation_id() {
        let scope = AuthzScope::new("tenant", "default");
        let request = MutateTuplesRequest::new(scope.clone(), vec![TupleUpdate::Add(tuple())])
            .unwrap()
            .with_operation_id("client-command")
            .unwrap();
        let (actual_scope, expected, updates) = request.into_parts();
        assert_eq!(actual_scope, scope);
        assert_eq!(expected, None);
        assert_eq!(updates, vec![TupleUpdate::Add(tuple())]);
    }

    #[test]
    fn legacy_empty_constructors_and_struct_literals_remain_concrete() {
        let object = Object {
            namespace: "document".into(),
            id: "legacy".into(),
        };
        assert_eq!(object.id, "legacy");
        let schema = Schema::default();
        let builder = SchemaBuilder::new();
        let namespace = NamespaceDefinition::new();
        let filter = TupleFilter::default();
        let public = Subject::Public;
        assert_eq!(public.id(), "_keldra/public");
        assert!(schema.namespaces.is_empty());
        assert!(builder.build().namespaces.is_empty());
        assert!(namespace.relations.is_empty());
        assert!(filter.object.is_none());
    }

    fn exact_object(path: &str) -> exact_path::Object {
        exact_path::Object {
            namespace: "document".into(),
            id: ObjectId::ExactPath {
                tenant: "storage-tenant".into(),
                bucket: "mail".into(),
                path: path.into(),
            },
        }
    }

    #[test]
    fn typed_models_mix_opaque_entities_and_exact_path_resources() {
        use exact_path as ep;
        let resource = exact_object("messages/one.json");
        let subject = ep::Subject::Entity(ep::Object {
            namespace: "user".into(),
            id: ObjectId::Opaque("alice".into()),
        });
        let tuple = ep::Tuple {
            object: resource.clone(),
            relation: "reader".into(),
            subject: subject.clone(),
        };
        let userset = ep::Subject::Userset {
            object: exact_object("groups/editors.json"),
            relation: "member".into(),
        };
        assert!(
            matches!(userset.object_id(), Some(ObjectId::ExactPath { path, .. }) if path == "groups/editors.json")
        );
        assert_eq!(userset.namespace(), "document");
        assert_eq!(userset.relation(), Some("member"));
        assert_eq!(ep::Subject::Public.object_id(), None);
        let request = ep::MutateTuplesRequest::new(
            AuthzScope::new("storage-tenant", "default"),
            vec![
                ep::TupleUpdate::Add(tuple.clone()),
                ep::TupleUpdate::Remove(tuple.clone()),
            ],
        )
        .unwrap();
        let (_, _, updates) = request.into_parts();
        assert_eq!(updates.len(), 2);
        let check = ep::CheckRequest {
            subject,
            object: resource.clone(),
            relation: "read".into(),
        };
        assert_eq!(check.object, resource);
        let request = ep::ReadTuplesRequest::new(AuthzScope::new("storage-tenant", "default"))
            .with_filter(ep::TupleFilter {
                object: Some(ep::ObjectFilter::Exact(resource)),
                relation: Some("reader".into()),
                subject: Some(userset),
            });
        let page = ep::ReadTuplesPage {
            tuples: vec![tuple.clone()],
            revision: AuthzRevision(4),
            next_page_token: None,
        };
        assert!(matches!(
            request.filter.object,
            Some(ep::ObjectFilter::Exact(_))
        ));
        assert_eq!(page.tuples, vec![tuple]);
    }

    #[test]
    fn typed_schema_builders_keep_exact_subject_selectors_without_default_identity() {
        use exact_path as ep;
        // ObjectId intentionally has no Default; empty containers need none.
        let _ = ep::Schema::default();
        let _ = ep::TupleFilter::default();
        let exact = ep::Subject::Entity(exact_object("service/indexer.json"));
        let selectors = BTreeSet::from([
            ep::SubjectSelector::Exact(exact.clone()),
            ep::SubjectSelector::AnyObject {
                namespace: "user".into(),
            },
        ]);
        let schema = ep::SchemaBuilder::new()
            .namespace(
                "document",
                ep::NamespaceDefinition::new().relation(
                    "reader",
                    ep::RelationDefinition::Direct {
                        allowed_subjects: selectors.clone(),
                    },
                ),
            )
            .build();
        let ep::RelationDefinition::Direct { allowed_subjects } =
            &schema.namespaces["document"].relations["reader"]
        else {
            panic!("expected direct relation")
        };
        assert_eq!(allowed_subjects, &selectors);
        assert!(allowed_subjects.contains(&ep::SubjectSelector::Exact(exact)));
        assert_ne!(
            ObjectId::Opaque("messages/one.json".into()),
            exact_object("messages/one.json").id
        );
        let mut changed_scope = exact_object("messages/one.json");
        changed_scope.id = ObjectId::ExactPath {
            tenant: "other".into(),
            bucket: "mail".into(),
            path: "messages/one.json".into(),
        };
        assert_ne!(changed_scope, exact_object("messages/one.json"));
    }
}
