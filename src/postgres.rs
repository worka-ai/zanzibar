use crate::{
    AnvilStorageTenantId, AuthzDecisionMetadata, AuthzScope, AuthzWriteResult, BindingGeneration,
    CheckDecision, CheckRequest, ListObjectsResult, ListSubjectsResult, Object, RebacEngine,
    RebacError, RelationRule, Schema, SchemaBinding, SchemaId, SchemaRef, SchemaRevision, Subject,
    Tuple, TupleUpdate,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Clone)]
pub struct PostgresRebacEngine {
    pool: PgPool,
}

impl PostgresRebacEngine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn lock_scope(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        scope: &AuthzScope,
    ) -> Result<(), RebacError> {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(stable_lock_key(&format!(
                "scope:{}:{}",
                scope.anvil_storage_tenant_id.0, scope.authz_realm_id.0
            )))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn lock_schema(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: &SchemaId,
    ) -> Result<(), RebacError> {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(stable_lock_key(&format!(
                "schema:{}:{}",
                storage_tenant.0, schema_id.0
            )))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn binding_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        scope: &AuthzScope,
    ) -> Result<SchemaBinding, RebacError> {
        let row = sqlx::query(
            r#"SELECT schema_id, schema_revision, schema_digest, binding_generation
               FROM zanzibar_realm_schema_binding
               WHERE storage_tenant_id = $1 AND authz_realm_id = $2"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .fetch_optional(&mut **tx)
        .await?;

        row.map(|row| row_to_binding(scope, row))
            .transpose()?
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))
    }

    async fn schema_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        storage_tenant: &AnvilStorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<Schema, RebacError> {
        let row = sqlx::query(
            r#"SELECT schema_json
               FROM zanzibar_schema
               WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_revision = $3"#,
        )
        .bind(&storage_tenant.0)
        .bind(&schema_ref.schema_id.0)
        .bind(u64_to_i64(schema_ref.schema_revision.0, "schema_revision")?)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Err(RebacError::SchemaNotFound(format!(
                "{}@{} in {}",
                schema_ref.schema_id.0, schema_ref.schema_revision.0, storage_tenant.0
            )));
        };
        serde_json::from_value(row.get::<Value, _>(0))
            .map_err(|err| RebacError::Internal(format!("decode schema: {err}")))
    }

    async fn latest_revision(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        scope: &AuthzScope,
    ) -> Result<u64, RebacError> {
        let revision = sqlx::query_scalar::<_, Option<i64>>(
            r#"SELECT revision
               FROM zanzibar_authz_revision
               WHERE storage_tenant_id = $1 AND authz_realm_id = $2"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .fetch_one(&mut **tx)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
        i64_to_u64(revision, "authz_revision")
    }

    async fn advance_revision(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        scope: &AuthzScope,
    ) -> Result<u64, RebacError> {
        let revision = sqlx::query_scalar::<_, i64>(
            r#"INSERT INTO zanzibar_authz_revision
               (storage_tenant_id, authz_realm_id, revision)
               VALUES ($1, $2, 1)
               ON CONFLICT (storage_tenant_id, authz_realm_id)
               DO UPDATE SET revision = zanzibar_authz_revision.revision + 1
               RETURNING revision"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .fetch_one(&mut **tx)
        .await?;
        i64_to_u64(revision, "authz_revision")
    }

    async fn metadata_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        binding: &SchemaBinding,
        authz_revision: Option<u64>,
    ) -> Result<AuthzDecisionMetadata, RebacError> {
        let authz_revision = match authz_revision {
            Some(revision) => revision,
            None => Self::latest_revision(tx, &binding.scope).await?,
        };
        Ok(AuthzDecisionMetadata {
            scope: binding.scope.clone(),
            schema_ref: binding.schema_ref.clone(),
            authz_revision,
            zookie: zookie(&binding.scope, authz_revision),
        })
    }

    async fn binding_and_schema(
        &self,
        scope: &AuthzScope,
    ) -> Result<(SchemaBinding, Schema, AuthzDecisionMetadata), RebacError> {
        let mut tx = self.pool.begin().await?;
        let binding = Self::binding_in_tx(&mut tx, scope).await?;
        let schema =
            Self::schema_in_tx(&mut tx, &scope.anvil_storage_tenant_id, &binding.schema_ref)
                .await?;
        let metadata = Self::metadata_in_tx(&mut tx, &binding, None).await?;
        tx.commit().await?;
        Ok((binding, schema, metadata))
    }
}

#[async_trait]
impl RebacEngine for PostgresRebacEngine {
    async fn put_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: SchemaId,
        schema: Schema,
    ) -> Result<SchemaRef, RebacError> {
        validate_schema(&schema)?;
        let digest = schema_digest(&schema)?;
        let schema_json = serde_json::to_value(&schema)
            .map_err(|err| RebacError::Internal(format!("encode schema: {err}")))?;
        let mut tx = self.pool.begin().await?;
        Self::lock_schema(&mut tx, storage_tenant, &schema_id).await?;

        if let Some(row) = sqlx::query(
            r#"SELECT schema_revision
               FROM zanzibar_schema
               WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_digest = $3"#,
        )
        .bind(&storage_tenant.0)
        .bind(&schema_id.0)
        .bind(&digest)
        .fetch_optional(&mut *tx)
        .await?
        {
            let revision = i64_to_u64(row.get(0), "schema_revision")?;
            tx.commit().await?;
            return Ok(SchemaRef {
                schema_id,
                schema_revision: SchemaRevision(revision),
                schema_digest: digest,
            });
        }

        let latest = sqlx::query_scalar::<_, Option<i64>>(
            r#"SELECT MAX(schema_revision)
               FROM zanzibar_schema
               WHERE storage_tenant_id = $1 AND schema_id = $2"#,
        )
        .bind(&storage_tenant.0)
        .bind(&schema_id.0)
        .fetch_one(&mut *tx)
        .await?
        .unwrap_or(0);
        let revision = i64_to_u64(latest, "schema_revision")? + 1;

        sqlx::query(
            r#"INSERT INTO zanzibar_schema
               (storage_tenant_id, schema_id, schema_revision, schema_digest, schema_json)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&storage_tenant.0)
        .bind(&schema_id.0)
        .bind(u64_to_i64(revision, "schema_revision")?)
        .bind(&digest)
        .bind(schema_json)
        .execute(&mut *tx)
        .await?;

        for (namespace, config) in &schema.namespaces {
            for (relation, rules) in &config.rules {
                if rules.is_empty() {
                    sqlx::query(
                        r#"INSERT INTO zanzibar_schema_relation_config
                           (storage_tenant_id, schema_id, schema_revision, namespace, relation, rule_index,
                            inherited_relation, inherited_from_target_relation)
                           VALUES ($1, $2, $3, $4, $5, 0, NULL, NULL)"#,
                    )
                    .bind(&storage_tenant.0)
                    .bind(&schema_id.0)
                    .bind(u64_to_i64(revision, "schema_revision")?)
                    .bind(namespace)
                    .bind(relation)
                    .execute(&mut *tx)
                    .await?;
                    continue;
                }

                for (index, rule) in rules.iter().enumerate() {
                    let (inherited_relation, inherited_from_target_relation) = match rule {
                        RelationRule::Inherit(relation) => (Some(relation.as_str()), None),
                        RelationRule::Computed {
                            tuple_relation,
                            target_relation,
                        }
                        | RelationRule::TupleToUserset {
                            tuple_relation,
                            target_relation,
                        } => (
                            Some(target_relation.as_str()),
                            Some(tuple_relation.as_str()),
                        ),
                    };
                    sqlx::query(
                        r#"INSERT INTO zanzibar_schema_relation_config
                           (storage_tenant_id, schema_id, schema_revision, namespace, relation, rule_index,
                            inherited_relation, inherited_from_target_relation)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
                    )
                    .bind(&storage_tenant.0)
                    .bind(&schema_id.0)
                    .bind(u64_to_i64(revision, "schema_revision")?)
                    .bind(namespace)
                    .bind(relation)
                    .bind(index as i32)
                    .bind(inherited_relation)
                    .bind(inherited_from_target_relation)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        tx.commit().await?;
        Ok(SchemaRef {
            schema_id,
            schema_revision: SchemaRevision(revision),
            schema_digest: digest,
        })
    }

    async fn get_schema(
        &self,
        storage_tenant: &AnvilStorageTenantId,
        schema_id: &SchemaId,
        revision: Option<SchemaRevision>,
    ) -> Result<(SchemaRef, Schema), RebacError> {
        let row = if let Some(revision) = revision {
            sqlx::query(
                r#"SELECT schema_revision, schema_digest, schema_json
                   FROM zanzibar_schema
                   WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_revision = $3"#,
            )
            .bind(&storage_tenant.0)
            .bind(&schema_id.0)
            .bind(u64_to_i64(revision.0, "schema_revision")?)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT schema_revision, schema_digest, schema_json
                   FROM zanzibar_schema
                   WHERE storage_tenant_id = $1 AND schema_id = $2
                   ORDER BY schema_revision DESC
                   LIMIT 1"#,
            )
            .bind(&storage_tenant.0)
            .bind(&schema_id.0)
            .fetch_optional(&self.pool)
            .await?
        };
        let Some(row) = row else {
            return Err(RebacError::SchemaNotFound(format!(
                "{} in {}",
                schema_id.0, storage_tenant.0
            )));
        };
        let schema_ref = SchemaRef {
            schema_id: schema_id.clone(),
            schema_revision: SchemaRevision(i64_to_u64(row.get(0), "schema_revision")?),
            schema_digest: row.get(1),
        };
        let schema = serde_json::from_value(row.get::<Value, _>(2))
            .map_err(|err| RebacError::Internal(format!("decode schema: {err}")))?;
        Ok((schema_ref, schema))
    }

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<SchemaBinding, RebacError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_scope(&mut tx, scope).await?;
        let schema =
            Self::schema_in_tx(&mut tx, &scope.anvil_storage_tenant_id, &schema_ref).await?;
        let current = sqlx::query(
            r#"SELECT schema_id, schema_revision, schema_digest, binding_generation
               FROM zanzibar_realm_schema_binding
               WHERE storage_tenant_id = $1 AND authz_realm_id = $2"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        let actual_generation = current
            .as_ref()
            .map(|row| i64_to_u64(row.get(3), "binding_generation").map(BindingGeneration))
            .transpose()?;
        match (expected_generation, actual_generation) {
            (None, None) | (Some(BindingGeneration(0)), None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            (expected, actual) => {
                return Err(RebacError::SchemaBindingGenerationConflict { expected, actual });
            }
        }

        let existing_tuples = read_tuples_in_tx(&mut tx, scope, None, None, None).await?;
        for tuple in &existing_tuples {
            validate_tuple(&schema, tuple)?;
        }

        let new_generation = actual_generation.map(|g| g.0 + 1).unwrap_or(1);
        sqlx::query(
            r#"INSERT INTO zanzibar_realm_schema_binding
               (storage_tenant_id, authz_realm_id, schema_id, schema_revision, schema_digest, binding_generation)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (storage_tenant_id, authz_realm_id)
               DO UPDATE SET
                   schema_id = EXCLUDED.schema_id,
                   schema_revision = EXCLUDED.schema_revision,
                   schema_digest = EXCLUDED.schema_digest,
                   binding_generation = EXCLUDED.binding_generation,
                   updated_at = NOW()"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .bind(&schema_ref.schema_id.0)
        .bind(u64_to_i64(schema_ref.schema_revision.0, "schema_revision")?)
        .bind(&schema_ref.schema_digest)
        .bind(u64_to_i64(new_generation, "binding_generation")?)
        .execute(&mut *tx)
        .await?;
        Self::advance_revision(&mut tx, scope).await?;
        tx.commit().await?;
        Ok(SchemaBinding {
            scope: scope.clone(),
            schema_ref,
            binding_generation: BindingGeneration(new_generation),
        })
    }

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError> {
        let row = sqlx::query(
            r#"SELECT schema_id, schema_revision, schema_digest, binding_generation
               FROM zanzibar_realm_schema_binding
               WHERE storage_tenant_id = $1 AND authz_realm_id = $2"#,
        )
        .bind(&scope.anvil_storage_tenant_id.0)
        .bind(&scope.authz_realm_id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_binding(scope, row))
            .transpose()?
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))
    }

    async fn write_tuples(
        &self,
        scope: &AuthzScope,
        updates: Vec<TupleUpdate>,
    ) -> Result<AuthzWriteResult, RebacError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_scope(&mut tx, scope).await?;
        let binding = Self::binding_in_tx(&mut tx, scope).await?;
        let schema =
            Self::schema_in_tx(&mut tx, &scope.anvil_storage_tenant_id, &binding.schema_ref)
                .await?;

        for update in &updates {
            let tuple = match update {
                TupleUpdate::Write(tuple) | TupleUpdate::Delete(tuple) => tuple,
            };
            validate_tuple(&schema, tuple)?;
        }

        for update in updates {
            match update {
                TupleUpdate::Write(tuple) => {
                    let (sub_ns, sub_id, sub_rel) = subject_parts(tuple.subject);
                    sqlx::query(
                        r#"INSERT INTO zanzibar_scoped_tuple
                           (storage_tenant_id, authz_realm_id, object_namespace, object_id, relation,
                            subject_namespace, subject_id, subject_relation)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                           ON CONFLICT (storage_tenant_id, authz_realm_id, object_namespace, object_id,
                                        relation, subject_namespace, subject_id,
                                        COALESCE(subject_relation, ''))
                           DO NOTHING"#,
                    )
                    .bind(&scope.anvil_storage_tenant_id.0)
                    .bind(&scope.authz_realm_id.0)
                    .bind(tuple.object.namespace)
                    .bind(tuple.object.id)
                    .bind(tuple.relation)
                    .bind(sub_ns)
                    .bind(sub_id)
                    .bind(sub_rel)
                    .execute(&mut *tx)
                    .await?;
                }
                TupleUpdate::Delete(tuple) => {
                    let (sub_ns, sub_id, sub_rel) = subject_parts(tuple.subject);
                    sqlx::query(
                        r#"DELETE FROM zanzibar_scoped_tuple
                           WHERE storage_tenant_id = $1 AND authz_realm_id = $2
                             AND object_namespace = $3 AND object_id = $4 AND relation = $5
                             AND subject_namespace = $6 AND subject_id = $7
                             AND subject_relation IS NOT DISTINCT FROM $8"#,
                    )
                    .bind(&scope.anvil_storage_tenant_id.0)
                    .bind(&scope.authz_realm_id.0)
                    .bind(tuple.object.namespace)
                    .bind(tuple.object.id)
                    .bind(tuple.relation)
                    .bind(sub_ns)
                    .bind(sub_id)
                    .bind(sub_rel)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        let revision = Self::advance_revision(&mut tx, scope).await?;
        let metadata = Self::metadata_in_tx(&mut tx, &binding, Some(revision)).await?;
        tx.commit().await?;
        Ok(AuthzWriteResult { metadata })
    }

    async fn read_tuples(
        &self,
        scope: &AuthzScope,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError> {
        let mut tx = self.pool.begin().await?;
        let tuples = read_tuples_in_tx(&mut tx, scope, object, relation, subject).await?;
        tx.commit().await?;
        Ok(tuples)
    }

    async fn check(
        &self,
        scope: &AuthzScope,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<CheckDecision, RebacError> {
        let (_, schema, metadata) = self.binding_and_schema(scope).await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(CheckDecision {
            allowed: view.check(&schema, object, relation, subject),
            metadata,
        })
    }

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<CheckDecision>, RebacError> {
        let (_, schema, metadata) = self.binding_and_schema(scope).await?;
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
                metadata: metadata.clone(),
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
        let (_, schema, metadata) = self.binding_and_schema(scope).await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(ListObjectsResult {
            object_ids: view.list_objects(&schema, subject, relation, object_namespace),
            metadata,
        })
    }

    async fn list_subjects(
        &self,
        scope: &AuthzScope,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<ListSubjectsResult, RebacError> {
        let (_, schema, metadata) = self.binding_and_schema(scope).await?;
        let tuples = self.read_tuples(scope, None, None, None).await?;
        let view = TupleView::new(tuples);
        Ok(ListSubjectsResult {
            subject_ids: view.list_subjects(&schema, object, relation, subject_namespace),
            metadata,
        })
    }
}

async fn read_tuples_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &AuthzScope,
    object: Option<Object>,
    relation: Option<String>,
    subject: Option<Subject>,
) -> Result<Vec<Tuple>, RebacError> {
    let (sub_ns, sub_id, sub_rel) = subject
        .map(subject_parts)
        .map(|(ns, id, rel)| (Some(ns), Some(id), rel))
        .unwrap_or((None, None, None));
    let rows = sqlx::query(
        r#"SELECT object_namespace, object_id, relation, subject_namespace, subject_id, subject_relation
           FROM zanzibar_scoped_tuple
           WHERE storage_tenant_id = $1 AND authz_realm_id = $2
             AND ($3::TEXT IS NULL OR object_namespace = $3)
             AND ($4::TEXT IS NULL OR object_id = $4)
             AND ($5::TEXT IS NULL OR relation = $5)
             AND ($6::TEXT IS NULL OR subject_namespace = $6)
             AND ($7::TEXT IS NULL OR subject_id = $7)
             AND ($8::TEXT IS NULL OR subject_relation IS NOT DISTINCT FROM $8)"#,
    )
    .bind(&scope.anvil_storage_tenant_id.0)
    .bind(&scope.authz_realm_id.0)
    .bind(object.as_ref().map(|object| object.namespace.as_str()))
    .bind(object.as_ref().map(|object| object.id.as_str()))
    .bind(relation.as_deref())
    .bind(sub_ns.as_deref())
    .bind(sub_id.as_deref())
    .bind(sub_rel.as_deref())
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().map(row_to_tuple).collect())
}

fn row_to_binding(
    scope: &AuthzScope,
    row: sqlx::postgres::PgRow,
) -> Result<SchemaBinding, RebacError> {
    Ok(SchemaBinding {
        scope: scope.clone(),
        schema_ref: SchemaRef {
            schema_id: SchemaId(row.get(0)),
            schema_revision: SchemaRevision(i64_to_u64(row.get(1), "schema_revision")?),
            schema_digest: row.get(2),
        },
        binding_generation: BindingGeneration(i64_to_u64(row.get(3), "binding_generation")?),
    })
}

fn row_to_tuple(row: sqlx::postgres::PgRow) -> Tuple {
    let subject_namespace: String = row.get(3);
    let subject_id: String = row.get(4);
    let subject_relation: Option<String> = row.get(5);
    Tuple {
        object: Object {
            namespace: row.get(0),
            id: row.get(1),
        },
        relation: row.get(2),
        subject: match subject_relation {
            Some(relation) => Subject::Userset {
                object: Object {
                    namespace: subject_namespace,
                    id: subject_id,
                },
                relation,
            },
            None => Subject::Entity(Object {
                namespace: subject_namespace,
                id: subject_id,
            }),
        },
    }
}

fn subject_parts(subject: Subject) -> (String, String, Option<String>) {
    match subject {
        Subject::Entity(object) => (object.namespace, object.id, None),
        Subject::Userset { object, relation } => (object.namespace, object.id, Some(relation)),
    }
}

fn validate_schema(schema: &Schema) -> Result<(), RebacError> {
    for (namespace, config) in &schema.namespaces {
        validate_component(namespace, "namespace")?;
        for (relation, rules) in &config.rules {
            validate_component(relation, "relation")?;
            let mut seen = HashSet::new();
            for rule in rules {
                let key = serde_json::to_string(rule)
                    .map_err(|err| RebacError::Internal(format!("encode relation rule: {err}")))?;
                if !seen.insert(key) {
                    return Err(RebacError::InvalidSchema(format!(
                        "duplicate rule for {namespace}#{relation}"
                    )));
                }
                match rule {
                    RelationRule::Inherit(inherited) => {
                        validate_component(inherited, "relation")?;
                        if !config.rules.contains_key(inherited) {
                            return Err(RebacError::InvalidSchema(format!(
                                "{namespace}#{relation} inherits unknown relation {inherited}"
                            )));
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
                        validate_component(tuple_relation, "tuple relation")?;
                        validate_component(target_relation, "target relation")?;
                        if !config.rules.contains_key(tuple_relation) {
                            return Err(RebacError::InvalidSchema(format!(
                                "{namespace}#{relation} uses unknown tuple relation {tuple_relation}"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_tuple(schema: &Schema, tuple: &Tuple) -> Result<(), RebacError> {
    let namespace = schema
        .namespaces
        .get(&tuple.object.namespace)
        .ok_or_else(|| {
            RebacError::InvalidTuple(format!(
                "unknown object namespace {}",
                tuple.object.namespace
            ))
        })?;
    if !namespace.rules.contains_key(&tuple.relation) {
        return Err(RebacError::InvalidTuple(format!(
            "unknown relation {}#{}",
            tuple.object.namespace, tuple.relation
        )));
    }
    if let Subject::Userset { object, relation } = &tuple.subject {
        let subject_namespace = schema.namespaces.get(&object.namespace).ok_or_else(|| {
            RebacError::InvalidTuple(format!("unknown userset namespace {}", object.namespace))
        })?;
        if !subject_namespace.rules.contains_key(relation) {
            return Err(RebacError::InvalidTuple(format!(
                "unknown userset relation {}#{}",
                object.namespace, relation
            )));
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
        Err(RebacError::InvalidSchema(format!(
            "invalid {name}: {value:?}"
        )))
    } else {
        Ok(())
    }
}

fn schema_digest(schema: &Schema) -> Result<String, RebacError> {
    let canonical = canonical_schema_value(schema);
    let json = serde_json::to_string(&canonical)
        .map_err(|err| RebacError::Internal(format!("encode canonical schema: {err}")))?;
    Ok(format!("fnv1a64:{:016x}", fnv1a64(json.as_bytes())))
}

fn canonical_schema_value(schema: &Schema) -> Value {
    let namespaces = schema
        .namespaces
        .iter()
        .map(|(namespace, config)| {
            let rules = config
                .rules
                .iter()
                .map(|(relation, relation_rules)| {
                    let values = relation_rules
                        .iter()
                        .map(|rule| match rule {
                            RelationRule::Inherit(relation) => json!({
                                "kind": "inherit",
                                "relation": relation,
                            }),
                            RelationRule::Computed {
                                tuple_relation,
                                target_relation,
                            } => json!({
                                "kind": "computed",
                                "tuple_relation": tuple_relation,
                                "target_relation": target_relation,
                            }),
                            RelationRule::TupleToUserset {
                                tuple_relation,
                                target_relation,
                            } => json!({
                                "kind": "tuple_to_userset",
                                "tuple_relation": tuple_relation,
                                "target_relation": target_relation,
                            }),
                        })
                        .collect::<Vec<_>>();
                    (relation.clone(), Value::Array(values))
                })
                .collect::<BTreeMap<_, _>>();
            (namespace.clone(), json!({ "rules": rules }))
        })
        .collect::<BTreeMap<_, _>>();
    let mut root = Map::new();
    root.insert("namespaces".to_string(), json!(namespaces));
    Value::Object(root)
}

fn stable_lock_key(value: &str) -> i64 {
    fnv1a64(value.as_bytes()) as i64
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn u64_to_i64(value: u64, name: &str) -> Result<i64, RebacError> {
    i64::try_from(value).map_err(|_| RebacError::Internal(format!("{name} overflows i64")))
}

fn i64_to_u64(value: i64, name: &str) -> Result<u64, RebacError> {
    u64::try_from(value).map_err(|_| RebacError::Internal(format!("{name} is negative")))
}

fn zookie(scope: &AuthzScope, revision: u64) -> String {
    format!(
        "pg:{}:{}:{revision}",
        scope.anvil_storage_tenant_id.0, scope.authz_realm_id.0
    )
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
