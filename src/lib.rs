#[cfg(feature = "anvil")]
pub mod anvil;

pub mod postgres;

pub const POSTGRES_SCHEMA: &str = include_str!("../schema.sql");

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies a specific entity in the system.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Object {
    pub namespace: String,
    pub id: String,
}

impl std::fmt::Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.id)
    }
}

/// A Subject can be a direct user/entity, or a "Userset" (e.g., all members of a group).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Subject {
    /// A specific entity (e.g., namespace: "user", id: "alice")
    Entity(Object),
    /// A dynamic set of users (e.g., namespace: "workspace", id: "123", relation: "member")
    Userset { object: Object, relation: String },
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subject::Entity(obj) => write!(f, "{}", obj),
            Subject::Userset { object, relation } => write!(f, "{}#{}", object, relation),
        }
    }
}

impl Subject {
    pub fn namespace(&self) -> &str {
        match self {
            Subject::Entity(obj) => &obj.namespace,
            Subject::Userset { object, .. } => &object.namespace,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Subject::Entity(obj) => &obj.id,
            Subject::Userset { object, .. } => &object.id,
        }
    }

    pub fn relation(&self) -> Option<&str> {
        match self {
            Subject::Entity(_) => None,
            Subject::Userset { relation, .. } => Some(relation),
        }
    }
}

/// The core building block: "Subject has Relation to Object"
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub object: Object,
    pub relation: String,
    pub subject: Subject,
}

/// Defines what to update in the graph
#[derive(Debug, Clone)]
pub enum TupleUpdate {
    Write(Tuple),
    Delete(Tuple),
}

/// A "Relation Algebra" Rule for a specific relation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationRule {
    /// Direct inheritance from another relation in the same namespace.
    /// E.g. "viewer" inherits from "editor"
    Inherit(String),
    /// Jump to another object via a relation and check its relation.
    /// E.g. Tool inherits from "parent_pack#can_use"
    Computed {
        tuple_relation: String,
        target_relation: String,
    },
    /// Expands the set of users. If a subject has `tuple_relation`, they are
    /// considered part of the `target_relation` userset.
    /// Used for public access, e.g. agent#is_public -> can_invoke for `user:*`
    TupleToUserset {
        tuple_relation: String,
        target_relation: String,
    },
}

/// A "Relation Algebra" Schema for a specific namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespaceConfig {
    /// Map of relation name -> list of rules that satisfy it.
    pub rules: HashMap<String, Vec<RelationRule>>,
}

/// The system-wide Authorization Schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Schema {
    pub namespaces: HashMap<String, NamespaceConfig>,
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

    pub fn namespace(mut self, name: &str, config: NamespaceConfig) -> Self {
        self.schema.namespaces.insert(name.to_string(), config);
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
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
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
    #[error("schema binding is in progress for scope: {0:?}")]
    SchemaBindingInProgress(AuthzScope),
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    #[error("invalid tuple: {0}")]
    InvalidTuple(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub subject: Subject,
    pub relation: String,
    pub object: Object,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnvilStorageTenantId(pub String);

impl From<&str> for AnvilStorageTenantId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for AnvilStorageTenantId {
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
    pub anvil_storage_tenant_id: AnvilStorageTenantId,
    pub authz_realm_id: AuthzRealmId,
}

impl AuthzScope {
    pub fn new(
        anvil_storage_tenant_id: impl Into<AnvilStorageTenantId>,
        authz_realm_id: impl Into<AuthzRealmId>,
    ) -> Self {
        Self {
            anvil_storage_tenant_id: anvil_storage_tenant_id.into(),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    pub schema_id: SchemaId,
    pub schema_revision: SchemaRevision,
    pub schema_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaBinding {
    pub scope: AuthzScope,
    pub schema_ref: SchemaRef,
    pub binding_generation: BindingGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzDecisionMetadata {
    pub scope: AuthzScope,
    pub schema_ref: SchemaRef,
    pub authz_revision: u64,
    pub zookie: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckDecision {
    pub allowed: bool,
    pub metadata: AuthzDecisionMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzWriteResult {
    pub metadata: AuthzDecisionMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsResult {
    pub object_ids: Vec<String>,
    pub metadata: AuthzDecisionMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSubjectsResult {
    pub subject_ids: Vec<String>,
    pub metadata: AuthzDecisionMetadata,
}

#[async_trait]
pub trait RebacEngine: Send + Sync {
    async fn put_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: SchemaId,
        schema: Schema,
    ) -> Result<SchemaRef, RebacError>;

    async fn get_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: &SchemaId,
        revision: Option<SchemaRevision>,
    ) -> Result<(SchemaRef, Schema), RebacError>;

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<SchemaBinding, RebacError>;

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError>;

    async fn write_tuples(
        &self,
        scope: &AuthzScope,
        updates: Vec<TupleUpdate>,
    ) -> Result<AuthzWriteResult, RebacError>;

    async fn read_tuples(
        &self,
        scope: &AuthzScope,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError>;

    async fn check(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<CheckDecision, RebacError>;

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<CheckDecision>, RebacError>;

    async fn list_objects(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Result<ListObjectsResult, RebacError>;

    async fn list_subjects(
        &self,
        scope: &AuthzScope,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<ListSubjectsResult, RebacError>;
}

pub async fn put_and_bind_schema(
    engine: &dyn RebacEngine,
    scope: &AuthzScope,
    schema_id: SchemaId,
    schema: Schema,
    expected_generation: Option<BindingGeneration>,
) -> Result<SchemaBinding, RebacError> {
    let schema_ref = engine
        .put_schema(&scope.anvil_storage_tenant_id, schema_id, schema)
        .await?;
    engine
        .bind_schema(scope, schema_ref, expected_generation)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_display() {
        let obj = Object {
            namespace: "doc".into(),
            id: "1".into(),
        };
        assert_eq!(format!("{}", obj), "doc:1");
    }

    #[test]
    fn test_subject_display() {
        let alice = Subject::Entity(Object {
            namespace: "user".into(),
            id: "alice".into(),
        });
        assert_eq!(format!("{}", alice), "user:alice");

        let group_members = Subject::Userset {
            object: Object {
                namespace: "group".into(),
                id: "a".into(),
            },
            relation: "member".into(),
        };
        assert_eq!(format!("{}", group_members), "group:a#member");
    }
}
