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

#[derive(Debug, thiserror::Error)]
pub enum RebacError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub subject: Subject,
    pub relation: String,
    pub object: Object,
}

#[async_trait]
pub trait RebacEngine: Send + Sync {
    /// Persists the Authorization Schema (Relation Algebra) to the database.
    async fn apply_schema(&self, tenant_id: i64, schema: Schema) -> Result<(), RebacError>;

    async fn write_tuples(
        &self,
        tenant_id: i64,
        updates: Vec<TupleUpdate>,
    ) -> Result<(), RebacError>;

    async fn read_tuples(
        &self,
        tenant_id: i64,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError>;

    async fn check(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<bool, RebacError>;

    async fn check_many(
        &self,
        tenant_id: i64,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<bool>, RebacError>;

    async fn list_objects(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Result<Vec<String>, RebacError>;

    async fn list_subjects(
        &self,
        tenant_id: i64,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<Vec<String>, RebacError>;
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
