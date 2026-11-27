//! PostgreSQL implementation of the current typed Zanzibar contract.
//!
//! This adapter restores the PostgreSQL backend removed in
//! `64b38f021c3ecab414a28d554b284bfa5f092367`, ported to the typed API used by
//! the Keldra adapter. Tuple and schema history are revisioned so `Exact` and
//! `AtLeast` reads have the same externally visible meaning as Keldra reads.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    AuthzRevision, AuthzScope, BindSchemaResult, BindingGeneration, CheckDecision, CheckManyResult,
    Consistency, MAX_MUTATIONS_PER_REQUEST, MAX_OPERATION_ID_BYTES, MAX_READ_PAGE_SIZE,
    MutateTuplesResult, PermissionRule, PutSchemaResult, RebacEngine, RebacError, SchemaBinding,
    SchemaId, SchemaRef, SchemaRevision, StorageTenantId, TypedCheckRequest,
    TypedMutateTuplesRequest, TypedObject, TypedObjectFilter, TypedReadTuplesPage,
    TypedReadTuplesRequest, TypedRelationDefinition, TypedSchema, TypedSubject,
    TypedSubjectSelector, TypedTuple, TypedTupleUpdate,
};

const DEFAULT_PAGE_SIZE: u32 = 100;
const READ_CURSOR_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_CHECK_DEPTH: usize = 16;
const MAX_CHECK_STEPS: usize = 512;

/// Durable PostgreSQL implementation of [`RebacEngine`].
///
/// The caller supplies a pool and an isolated SQL schema. The schema name is
/// validated before it is interpolated into migration/query identifiers.
#[derive(Clone)]
pub struct PostgresRebacEngine<I = String> {
    pool: PgPool,
    schema: String,
    identity: PhantomData<fn() -> I>,
}

impl<I> std::fmt::Debug for PostgresRebacEngine<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresRebacEngine")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl<I> PostgresRebacEngine<I> {
    pub fn new(pool: PgPool, schema: impl Into<String>) -> Result<Self, RebacError> {
        let schema = schema.into();
        validate_sql_identifier(&schema)?;
        Ok(Self {
            pool,
            schema,
            identity: PhantomData,
        })
    }

    /// Creates this adapter's tables and indexes. Call from explicit admin
    /// bootstrap; normal API attachment must not run schema preparation.
    pub async fn prepare(&self) -> Result<(), RebacError> {
        let quoted_schema = format!("\"{}\"", self.schema);
        let sql = include_str!("postgres/schema.sql").replace("{{schema}}", &quoted_schema);
        sqlx::raw_sql(&sql).execute(&self.pool).await?;
        Ok(())
    }

    fn table(&self, table: &str) -> String {
        format!("\"{}\".\"zanzibar_{}\"", self.schema, table)
    }

    async fn lock_scope(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
    ) -> Result<(), RebacError> {
        let key = format!(
            "scope:{}:{}",
            scope.storage_tenant_id.0, scope.authz_realm_id.0
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn lock_schema(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &StorageTenantId,
        schema_id: &SchemaId,
    ) -> Result<(), RebacError> {
        let key = format!("schema:{}:{}", tenant.0, schema_id.0);
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn latest_revision(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &StorageTenantId,
    ) -> Result<u64, RebacError> {
        let sql = format!(
            "SELECT COALESCE((SELECT revision FROM {} WHERE storage_tenant_id = $1), 0)",
            self.table("authz_revision")
        );
        let revision: i64 = sqlx::query_scalar(&sql)
            .bind(&tenant.0)
            .fetch_one(&mut **tx)
            .await?;
        i64_to_u64(revision, "authorization revision")
    }

    async fn advance_revision(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &StorageTenantId,
    ) -> Result<u64, RebacError> {
        let sql = format!(
            "INSERT INTO {} (storage_tenant_id, revision) VALUES ($1, 1) \
             ON CONFLICT (storage_tenant_id) DO UPDATE \
             SET revision = zanzibar_authz_revision.revision + 1 \
             RETURNING zanzibar_authz_revision.revision",
            self.table("authz_revision")
        );
        let revision: i64 = sqlx::query_scalar(&sql)
            .bind(&tenant.0)
            .fetch_one(&mut **tx)
            .await?;
        i64_to_u64(revision, "authorization revision")
    }

    async fn revision_for_consistency(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &StorageTenantId,
        consistency: Consistency,
    ) -> Result<u64, RebacError> {
        let latest = self.latest_revision(tx, tenant).await?;
        match consistency {
            Consistency::Latest => Ok(latest),
            Consistency::AtLeast(requested) if latest >= requested.0 => Ok(latest),
            Consistency::AtLeast(requested) => Err(RebacError::RevisionUnavailable(format!(
                "PostgreSQL has revision {latest}, before requested revision {}",
                requested.0
            ))),
            Consistency::Exact(requested) if requested.0 <= latest => Ok(requested.0),
            Consistency::Exact(requested) => Err(RebacError::RevisionUnavailable(format!(
                "PostgreSQL has revision {latest}, before requested exact revision {}",
                requested.0
            ))),
        }
    }

    async fn binding_at_revision(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        revision: u64,
    ) -> Result<SchemaBinding, RebacError> {
        let sql = format!(
            "SELECT schema_id, schema_revision, schema_digest, binding_generation \
             FROM {} WHERE storage_tenant_id = $1 AND authz_realm_id = $2 \
               AND valid_from_revision <= $3 \
               AND (valid_until_revision IS NULL OR valid_until_revision > $3) \
             ORDER BY valid_from_revision DESC LIMIT 1",
            self.table("schema_binding_history")
        );
        let row = sqlx::query(&sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0)
            .bind(u64_to_i64(revision, "authorization revision")?)
            .fetch_optional(&mut **tx)
            .await?;
        row.map(|row| row_to_binding(scope, row))
            .transpose()?
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))
    }

    async fn current_binding(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
    ) -> Result<Option<SchemaBinding>, RebacError> {
        let sql = format!(
            "SELECT schema_id, schema_revision, schema_digest, binding_generation \
             FROM {} WHERE storage_tenant_id = $1 AND authz_realm_id = $2 \
               AND valid_until_revision IS NULL",
            self.table("schema_binding_history")
        );
        let row = sqlx::query(&sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0)
            .fetch_optional(&mut **tx)
            .await?;
        row.map(|row| row_to_binding(scope, row)).transpose()
    }

    async fn schema_by_ref(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &StorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<TypedSchema<I>, RebacError>
    where
        I: DeserializeOwned + Ord,
    {
        let sql = format!(
            "SELECT schema_digest, schema_json FROM {} \
             WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_revision = $3",
            self.table("schema")
        );
        let row = sqlx::query(&sql)
            .bind(&tenant.0)
            .bind(&schema_ref.schema_id.0)
            .bind(u64_to_i64(schema_ref.schema_revision.0, "schema revision")?)
            .fetch_optional(&mut **tx)
            .await?;
        let Some(row) = row else {
            return Err(RebacError::SchemaNotFound(format!(
                "{}@{} in {}",
                schema_ref.schema_id.0, schema_ref.schema_revision.0, tenant.0
            )));
        };
        let digest: Vec<u8> = row.try_get("schema_digest")?;
        if digest.as_slice() != schema_ref.schema_digest.as_slice() {
            return Err(RebacError::SchemaNotFound(format!(
                "{}@{} digest does not match",
                schema_ref.schema_id.0, schema_ref.schema_revision.0
            )));
        }
        let value: Value = row.try_get("schema_json")?;
        serde_json::from_value(value)
            .map_err(|_| RebacError::Internal("stored PostgreSQL schema is invalid".into()))
    }
}

#[async_trait]
impl<I> RebacEngine<I> for PostgresRebacEngine<I>
where
    I: Serialize + DeserializeOwned + Clone + Eq + Ord + Send + Sync + 'static,
{
    async fn put_schema(
        &self,
        storage_tenant: &StorageTenantId,
        schema_id: SchemaId,
        schema: TypedSchema<I>,
    ) -> Result<PutSchemaResult, RebacError> {
        validate_schema(&schema)?;
        let schema_value = serde_json::to_value(&schema)
            .map_err(|_| RebacError::InvalidSchema("schema could not be encoded".into()))?;
        let digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&schema_value)
                .map_err(|_| RebacError::InvalidSchema("schema could not be encoded".into()))?,
        )
        .into();

        let mut tx = self.pool.begin().await?;
        self.lock_schema(&mut tx, storage_tenant, &schema_id)
            .await?;
        let find_sql = format!(
            "SELECT schema_revision, created_revision FROM {} \
             WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_digest = $3",
            self.table("schema")
        );
        if let Some(row) = sqlx::query(&find_sql)
            .bind(&storage_tenant.0)
            .bind(&schema_id.0)
            .bind(digest.as_slice())
            .fetch_optional(&mut *tx)
            .await?
        {
            let schema_revision = i64_to_u64(row.try_get("schema_revision")?, "schema revision")?;
            let revision = i64_to_u64(row.try_get("created_revision")?, "authorization revision")?;
            tx.commit().await?;
            return Ok(PutSchemaResult {
                schema_ref: SchemaRef {
                    schema_id,
                    schema_revision: SchemaRevision(schema_revision),
                    schema_digest: digest,
                },
                revision: AuthzRevision(revision),
            });
        }

        let latest_sql = format!(
            "SELECT COALESCE(MAX(schema_revision), 0) FROM {} \
             WHERE storage_tenant_id = $1 AND schema_id = $2",
            self.table("schema")
        );
        let latest: i64 = sqlx::query_scalar(&latest_sql)
            .bind(&storage_tenant.0)
            .bind(&schema_id.0)
            .fetch_one(&mut *tx)
            .await?;
        let schema_revision = i64_to_u64(latest, "schema revision")?
            .checked_add(1)
            .ok_or_else(|| RebacError::Internal("schema revision overflow".into()))?;
        let revision = self.advance_revision(&mut tx, storage_tenant).await?;
        let insert_sql = format!(
            "INSERT INTO {} \
             (storage_tenant_id, schema_id, schema_revision, schema_digest, schema_json, created_revision) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            self.table("schema")
        );
        sqlx::query(&insert_sql)
            .bind(&storage_tenant.0)
            .bind(&schema_id.0)
            .bind(u64_to_i64(schema_revision, "schema revision")?)
            .bind(digest.as_slice())
            .bind(schema_value)
            .bind(u64_to_i64(revision, "authorization revision")?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(PutSchemaResult {
            schema_ref: SchemaRef {
                schema_id,
                schema_revision: SchemaRevision(schema_revision),
                schema_digest: digest,
            },
            revision: AuthzRevision(revision),
        })
    }

    async fn get_schema(
        &self,
        storage_tenant: &StorageTenantId,
        schema_ref: &SchemaRef,
    ) -> Result<(SchemaRef, TypedSchema<I>), RebacError> {
        let sql = format!(
            "SELECT schema_digest, schema_json FROM {} \
             WHERE storage_tenant_id = $1 AND schema_id = $2 AND schema_revision = $3",
            self.table("schema")
        );
        let row = sqlx::query(&sql)
            .bind(&storage_tenant.0)
            .bind(&schema_ref.schema_id.0)
            .bind(u64_to_i64(schema_ref.schema_revision.0, "schema revision")?)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(RebacError::SchemaNotFound(format!(
                "{}@{} in {}",
                schema_ref.schema_id.0, schema_ref.schema_revision.0, storage_tenant.0
            )));
        };
        let digest: Vec<u8> = row.try_get("schema_digest")?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| RebacError::Internal("stored schema digest has invalid size".into()))?;
        if digest != schema_ref.schema_digest {
            return Err(RebacError::SchemaNotFound(format!(
                "{}@{} digest does not match",
                schema_ref.schema_id.0, schema_ref.schema_revision.0
            )));
        }
        let value: Value = row.try_get("schema_json")?;
        let schema = serde_json::from_value(value)
            .map_err(|_| RebacError::Internal("stored PostgreSQL schema is invalid".into()))?;
        Ok((schema_ref.clone(), schema))
    }

    async fn bind_schema(
        &self,
        scope: &AuthzScope,
        schema_ref: SchemaRef,
        expected_generation: Option<BindingGeneration>,
    ) -> Result<BindSchemaResult, RebacError> {
        let mut tx = self.pool.begin().await?;
        self.lock_scope(&mut tx, scope).await?;
        let schema = self
            .schema_by_ref(&mut tx, &scope.storage_tenant_id, &schema_ref)
            .await?;
        let current = self.current_binding(&mut tx, scope).await?;
        let actual = current.as_ref().map(|binding| binding.binding_generation);
        match (expected_generation, actual) {
            (None, None) | (Some(BindingGeneration(0)), None) => {}
            (Some(expected), Some(found)) if expected == found => {}
            (expected, actual) => {
                return Err(RebacError::SchemaBindingGenerationConflict { expected, actual });
            }
        }

        let all_tuples = self.active_tuples_in_tx(&mut tx, scope, None).await?;
        for tuple in &all_tuples {
            validate_tuple(&schema, tuple)?;
        }

        let revision = self
            .advance_revision(&mut tx, &scope.storage_tenant_id)
            .await?;
        let generation = match actual {
            Some(value) => value
                .0
                .checked_add(1)
                .ok_or_else(|| RebacError::Internal("schema binding generation overflow".into()))?,
            None => 1,
        };
        if current.is_some() {
            let close_sql = format!(
                "UPDATE {} SET valid_until_revision = $3 \
                 WHERE storage_tenant_id = $1 AND authz_realm_id = $2 AND valid_until_revision IS NULL",
                self.table("schema_binding_history")
            );
            sqlx::query(&close_sql)
                .bind(&scope.storage_tenant_id.0)
                .bind(&scope.authz_realm_id.0)
                .bind(u64_to_i64(revision, "authorization revision")?)
                .execute(&mut *tx)
                .await?;
        }
        let insert_sql = format!(
            "INSERT INTO {} \
             (storage_tenant_id, authz_realm_id, schema_id, schema_revision, schema_digest, \
              binding_generation, valid_from_revision) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            self.table("schema_binding_history")
        );
        sqlx::query(&insert_sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0)
            .bind(&schema_ref.schema_id.0)
            .bind(u64_to_i64(schema_ref.schema_revision.0, "schema revision")?)
            .bind(schema_ref.schema_digest.as_slice())
            .bind(u64_to_i64(generation, "binding generation")?)
            .bind(u64_to_i64(revision, "authorization revision")?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(BindSchemaResult {
            binding: SchemaBinding {
                scope: scope.clone(),
                schema_ref,
                binding_generation: BindingGeneration(generation),
            },
            revision: AuthzRevision(revision),
        })
    }

    async fn get_schema_binding(&self, scope: &AuthzScope) -> Result<SchemaBinding, RebacError> {
        let mut tx = self.pool.begin().await?;
        let binding = self
            .current_binding(&mut tx, scope)
            .await?
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))?;
        tx.commit().await?;
        Ok(binding)
    }

    async fn mutate_tuples(
        &self,
        request: TypedMutateTuplesRequest<I>,
    ) -> Result<MutateTuplesResult, RebacError> {
        let mut tx = self.pool.begin().await?;
        let result = self.mutate_tuples_in_transaction(&mut tx, request).await?;
        tx.commit().await?;
        Ok(result)
    }

    async fn read_tuples(
        &self,
        request: TypedReadTuplesRequest<I>,
    ) -> Result<TypedReadTuplesPage<I>, RebacError> {
        let page_size = if request.page_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            request.page_size
        };
        if page_size > MAX_READ_PAGE_SIZE {
            return Err(RebacError::InvalidReadRequest(format!(
                "page size must be at most {MAX_READ_PAGE_SIZE}"
            )));
        }
        let filter_digest = digest_serializable(&(&request.scope, &request.filter))?;
        let mut tx = self.pool.begin().await?;
        let (revision, after) = if let Some(token) = request.page_token.as_deref() {
            self.read_cursor(&mut tx, &request.scope, &filter_digest, token)
                .await?
        } else {
            (
                self.revision_for_consistency(
                    &mut tx,
                    &request.scope.storage_tenant_id,
                    request.consistency,
                )
                .await?,
                None,
            )
        };
        let (object_ns, object_id) = match request.filter.object.as_ref() {
            Some(TypedObjectFilter::Namespace(namespace)) => (Some(namespace.clone()), None),
            Some(TypedObjectFilter::Exact(object)) => {
                (Some(object.namespace.clone()), Some(encode(&object.id)?))
            }
            None => (None, None),
        };
        let (subject_kind, subject_ns, subject_id, subject_relation) =
            match request.filter.subject.as_ref() {
                Some(subject) => {
                    let fields = subject_fields(subject)?;
                    (
                        Some(fields.kind),
                        Some(fields.namespace),
                        Some(fields.id),
                        Some(fields.relation),
                    )
                }
                None => (None, None, None, None),
            };
        let has_after = after.is_some();
        let last = after.unwrap_or_default();
        let subject_namespace = request.filter.subject_namespace.clone();
        let sql = format!(
            "SELECT object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation \
             FROM {} WHERE storage_tenant_id=$1 AND authz_realm_id=$2 \
               AND added_revision <= $3 AND (removed_revision IS NULL OR removed_revision > $3) \
               AND ($4::text IS NULL OR object_namespace=$4) AND ($5::text IS NULL OR object_id_json=$5) \
               AND ($6::text IS NULL OR relation=$6) AND ($7::text IS NULL OR subject_kind=$7) \
               AND ($8::text IS NULL OR subject_namespace=$8) AND ($9::text IS NULL OR subject_id_json=$9) \
               AND ($10::text IS NULL OR subject_relation=$10) \
               AND ($11::text IS NULL OR (subject_kind='entity' AND subject_namespace=$11)) \
               AND ($12::text IS NULL OR (object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation) \
                    > ($12,$13,$14,$15,$16,$17,$18)) \
             ORDER BY object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation \
             LIMIT $19",
            self.table("tuple_history")
        );
        let rows = sqlx::query(&sql)
            .bind(&request.scope.storage_tenant_id.0)
            .bind(&request.scope.authz_realm_id.0)
            .bind(u64_to_i64(revision, "authorization revision")?)
            .bind(object_ns)
            .bind(object_id)
            .bind(request.filter.relation)
            .bind(subject_kind)
            .bind(subject_ns)
            .bind(subject_id)
            .bind(subject_relation)
            .bind(subject_namespace)
            .bind(if has_after {
                Some(last.object_namespace.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.object_id_json.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.relation.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.subject_kind.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.subject_namespace.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.subject_id_json.clone())
            } else {
                None
            })
            .bind(if has_after {
                Some(last.subject_relation.clone())
            } else {
                None
            })
            .bind(i64::from(page_size) + 1)
            .fetch_all(&mut *tx)
            .await?;
        let has_more = rows.len() > page_size as usize;
        let page_rows = rows
            .into_iter()
            .take(page_size as usize)
            .collect::<Vec<_>>();
        let tuples = page_rows
            .iter()
            .map(row_to_tuple::<I>)
            .collect::<Result<Vec<_>, _>>()?;
        let next_page_token = if has_more {
            let last = row_to_key(page_rows.last().expect("a non-empty page has a last row"))?;
            Some(
                self.insert_read_cursor(&mut tx, &request.scope, &filter_digest, revision, &last)
                    .await?,
            )
        } else {
            None
        };
        tx.commit().await?;
        Ok(TypedReadTuplesPage {
            tuples,
            revision: AuthzRevision(revision),
            next_page_token,
        })
    }

    async fn check(
        &self,
        scope: &AuthzScope,
        request: TypedCheckRequest<I>,
        consistency: Consistency,
    ) -> Result<CheckDecision, RebacError> {
        let result = self.check_many(scope, vec![request], consistency).await?;
        Ok(CheckDecision {
            allowed: result.decisions[0],
            revision: result.revision,
        })
    }

    async fn check_many(
        &self,
        scope: &AuthzScope,
        requests: Vec<TypedCheckRequest<I>>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError> {
        let mut tx = self.pool.begin().await?;
        let result = self
            .check_many_in_transaction(&mut tx, scope, requests, consistency)
            .await?;
        tx.commit().await?;
        Ok(result)
    }
}

#[async_trait]
impl<I> crate::PostgresTransactionalRebacEngine<I> for PostgresRebacEngine<I>
where
    I: Serialize + DeserializeOwned + Clone + Eq + Ord + Send + Sync + 'static,
{
    async fn mutate_tuples_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        request: TypedMutateTuplesRequest<I>,
    ) -> Result<MutateTuplesResult, RebacError> {
        PostgresRebacEngine::mutate_tuples_in_transaction(self, transaction, request).await
    }

    async fn check_many_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        requests: Vec<TypedCheckRequest<I>>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError> {
        PostgresRebacEngine::check_many_in_transaction(
            self,
            transaction,
            scope,
            requests,
            consistency,
        )
        .await
    }
}

impl<I> PostgresRebacEngine<I>
where
    I: Serialize + DeserializeOwned + Clone + Eq + Ord + Send + Sync + 'static,
{
    async fn mutate_tuples_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: TypedMutateTuplesRequest<I>,
    ) -> Result<MutateTuplesResult, RebacError> {
        let (scope, operation_id, expected_revision, updates) =
            request.into_parts_with_operation_id();
        if updates.is_empty() || updates.len() > MAX_MUTATIONS_PER_REQUEST {
            return Err(RebacError::InvalidMutation(format!(
                "tuple mutation must contain 1 to {MAX_MUTATIONS_PER_REQUEST} updates"
            )));
        }
        if operation_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > MAX_OPERATION_ID_BYTES)
        {
            return Err(RebacError::InvalidMutation(format!(
                "operation ID must contain 1 to {MAX_OPERATION_ID_BYTES} bytes"
            )));
        }
        let payload = serde_json::to_vec(&(&scope, expected_revision, &updates)).map_err(|_| {
            RebacError::InvalidMutation("tuple mutation could not be encoded".into())
        })?;
        let payload_digest: [u8; 32] = Sha256::digest(payload).into();

        self.lock_scope(tx, &scope).await?;
        if let Some(operation_id) = operation_id.as_deref() {
            let key = format!(
                "operation:{}:{}:{operation_id}",
                scope.storage_tenant_id.0, scope.authz_realm_id.0
            );
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(key)
                .execute(&mut **tx)
                .await?;
            let receipt_sql = format!(
                "SELECT payload_digest, result_revision FROM {} \
                 WHERE storage_tenant_id = $1 AND authz_realm_id = $2 AND operation_id = $3",
                self.table("operation_receipt")
            );
            if let Some(row) = sqlx::query(&receipt_sql)
                .bind(&scope.storage_tenant_id.0)
                .bind(&scope.authz_realm_id.0)
                .bind(operation_id)
                .fetch_optional(&mut **tx)
                .await?
            {
                let old_digest: Vec<u8> = row.try_get("payload_digest")?;
                if old_digest.as_slice() != payload_digest {
                    return Err(RebacError::Conflict(
                        "operation ID was already used for a different tuple mutation".into(),
                    ));
                }
                let revision =
                    i64_to_u64(row.try_get("result_revision")?, "authorization revision")?;
                return Ok(MutateTuplesResult {
                    revision: AuthzRevision(revision),
                    replayed: true,
                    replay_guarantee_expires_at: None,
                });
            }
        }

        let latest = self.latest_revision(tx, &scope.storage_tenant_id).await?;
        if let Some(expected) = expected_revision
            && expected.0 != latest
        {
            return Err(RebacError::Conflict(format!(
                "expected authorization revision {}, found {latest}",
                expected.0
            )));
        }
        let binding = self
            .current_binding(tx, &scope)
            .await?
            .ok_or_else(|| RebacError::SchemaBindingNotFound(scope.clone()))?;
        let schema = self
            .schema_by_ref(tx, &scope.storage_tenant_id, &binding.schema_ref)
            .await?;
        for update in &updates {
            let tuple = match update {
                TypedTupleUpdate::Add(tuple) | TypedTupleUpdate::Remove(tuple) => tuple,
            };
            validate_tuple(&schema, tuple)?;
        }

        let revision = self.advance_revision(tx, &scope.storage_tenant_id).await?;
        for update in updates {
            match update {
                TypedTupleUpdate::Add(tuple) => {
                    let fields = tuple_fields(&tuple)?;
                    let exists_sql = format!(
                        "SELECT EXISTS (SELECT 1 FROM {} WHERE storage_tenant_id=$1 AND authz_realm_id=$2 \
                         AND object_namespace=$3 AND object_id_json=$4 AND relation=$5 AND subject_kind=$6 \
                         AND subject_namespace=$7 AND subject_id_json=$8 AND subject_relation=$9 \
                         AND removed_revision IS NULL)",
                        self.table("tuple_history")
                    );
                    let exists: bool = sqlx::query_scalar(&exists_sql)
                        .bind(&scope.storage_tenant_id.0)
                        .bind(&scope.authz_realm_id.0)
                        .bind(&fields.0)
                        .bind(&fields.1)
                        .bind(&fields.2)
                        .bind(&fields.3)
                        .bind(&fields.4)
                        .bind(&fields.5)
                        .bind(&fields.6)
                        .fetch_one(&mut **tx)
                        .await?;
                    if !exists {
                        let insert_sql = format!(
                            "INSERT INTO {} (storage_tenant_id,authz_realm_id,object_namespace,object_id_json,relation, \
                             subject_kind,subject_namespace,subject_id_json,subject_relation,added_revision) \
                             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                            self.table("tuple_history")
                        );
                        sqlx::query(&insert_sql)
                            .bind(&scope.storage_tenant_id.0)
                            .bind(&scope.authz_realm_id.0)
                            .bind(&fields.0)
                            .bind(&fields.1)
                            .bind(&fields.2)
                            .bind(&fields.3)
                            .bind(&fields.4)
                            .bind(&fields.5)
                            .bind(&fields.6)
                            .bind(u64_to_i64(revision, "authorization revision")?)
                            .execute(&mut **tx)
                            .await?;
                    }
                }
                TypedTupleUpdate::Remove(tuple) => {
                    let fields = tuple_fields(&tuple)?;
                    let remove_sql = format!(
                        "UPDATE {} SET removed_revision=$10 WHERE storage_tenant_id=$1 AND authz_realm_id=$2 \
                         AND object_namespace=$3 AND object_id_json=$4 AND relation=$5 AND subject_kind=$6 \
                         AND subject_namespace=$7 AND subject_id_json=$8 AND subject_relation=$9 \
                         AND removed_revision IS NULL",
                        self.table("tuple_history")
                    );
                    sqlx::query(&remove_sql)
                        .bind(&scope.storage_tenant_id.0)
                        .bind(&scope.authz_realm_id.0)
                        .bind(&fields.0)
                        .bind(&fields.1)
                        .bind(&fields.2)
                        .bind(&fields.3)
                        .bind(&fields.4)
                        .bind(&fields.5)
                        .bind(&fields.6)
                        .bind(u64_to_i64(revision, "authorization revision")?)
                        .execute(&mut **tx)
                        .await?;
                }
            }
        }
        if let Some(operation_id) = operation_id {
            let insert_receipt_sql = format!(
                "INSERT INTO {} (storage_tenant_id,authz_realm_id,operation_id,payload_digest,result_revision) \
                 VALUES ($1,$2,$3,$4,$5)",
                self.table("operation_receipt")
            );
            sqlx::query(&insert_receipt_sql)
                .bind(&scope.storage_tenant_id.0)
                .bind(&scope.authz_realm_id.0)
                .bind(operation_id)
                .bind(payload_digest.as_slice())
                .bind(u64_to_i64(revision, "authorization revision")?)
                .execute(&mut **tx)
                .await?;
        }
        Ok(MutateTuplesResult {
            revision: AuthzRevision(revision),
            replayed: false,
            replay_guarantee_expires_at: None,
        })
    }

    async fn check_many_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        requests: Vec<TypedCheckRequest<I>>,
        consistency: Consistency,
    ) -> Result<CheckManyResult, RebacError> {
        if requests.is_empty() {
            return Err(RebacError::InvalidTuple(
                "check batch must not be empty".into(),
            ));
        }
        if requests.len() > 1_000 {
            return Err(RebacError::ResourceExhausted(
                "check batch exceeds 1000 requests".into(),
            ));
        }
        let revision = self
            .revision_for_consistency(tx, &scope.storage_tenant_id, consistency)
            .await?;
        let binding = self.binding_at_revision(tx, scope, revision).await?;
        let schema = self
            .schema_by_ref(tx, &scope.storage_tenant_id, &binding.schema_ref)
            .await?;
        let mut tuple_cache = HashMap::new();
        let mut decisions = Vec::with_capacity(requests.len());
        for request in requests {
            if matches!(request.subject, TypedSubject::Userset { .. }) {
                return Err(RebacError::InvalidTuple(
                    "permission checks require an entity or public subject, not a userset".into(),
                ));
            }
            validate_check(&schema, &request)?;
            let mut steps = 0;
            let allowed = self
                .check_node(
                    tx,
                    scope,
                    &schema,
                    &request.object,
                    &request.relation,
                    &request.subject,
                    revision,
                    &mut HashSet::new(),
                    &mut tuple_cache,
                    0,
                    &mut steps,
                )
                .await?;
            decisions.push(allowed);
        }
        Ok(CheckManyResult {
            decisions,
            revision: AuthzRevision(revision),
        })
    }

    async fn active_tuples_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        revision: Option<u64>,
    ) -> Result<Vec<TypedTuple<I>>, RebacError> {
        let (revision, historical) = match revision {
            Some(revision) => (
                u64_to_i64(revision, "authorization revision")?,
                "added_revision <= $3 AND (removed_revision IS NULL OR removed_revision > $3)",
            ),
            None => (0, "removed_revision IS NULL"),
        };
        let sql = format!(
            "SELECT object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation \
             FROM {} WHERE storage_tenant_id=$1 AND authz_realm_id=$2 AND {} \
             ORDER BY object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation",
            self.table("tuple_history"),
            historical
        );
        let mut query = sqlx::query(&sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0);
        if revision > 0 || historical.starts_with("added_revision") {
            query = query.bind(revision);
        }
        query
            .fetch_all(&mut **tx)
            .await?
            .iter()
            .map(row_to_tuple::<I>)
            .collect()
    }

    async fn tuples_for_node(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        object: &TypedObject<I>,
        relation: &str,
        revision: u64,
        cache: &mut HashMap<String, Vec<TypedTuple<I>>>,
    ) -> Result<Vec<TypedTuple<I>>, RebacError> {
        let key = format!("{}|{}|{}", object.namespace, encode(&object.id)?, relation);
        if let Some(tuples) = cache.get(&key) {
            return Ok(tuples.clone());
        }
        let sql = format!(
            "SELECT object_namespace,object_id_json,relation,subject_kind,subject_namespace,subject_id_json,subject_relation \
             FROM {} WHERE storage_tenant_id=$1 AND authz_realm_id=$2 AND object_namespace=$3 \
               AND object_id_json=$4 AND relation=$5 AND added_revision <= $6 \
               AND (removed_revision IS NULL OR removed_revision > $6)",
            self.table("tuple_history")
        );
        let rows = sqlx::query(&sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0)
            .bind(&object.namespace)
            .bind(encode(&object.id)?)
            .bind(relation)
            .bind(u64_to_i64(revision, "authorization revision")?)
            .fetch_all(&mut **tx)
            .await?;
        let tuples = rows
            .iter()
            .map(row_to_tuple::<I>)
            .collect::<Result<Vec<_>, _>>()?;
        cache.insert(key, tuples.clone());
        Ok(tuples)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_node<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        scope: &'a AuthzScope,
        schema: &'a TypedSchema<I>,
        object: &'a TypedObject<I>,
        relation: &'a str,
        subject: &'a TypedSubject<I>,
        revision: u64,
        visited: &'a mut HashSet<String>,
        cache: &'a mut HashMap<String, Vec<TypedTuple<I>>>,
        depth: usize,
        steps: &'a mut usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, RebacError>> + Send + 'a>>
    {
        Box::pin(async move {
            *steps += 1;
            if *steps > MAX_CHECK_STEPS || depth > MAX_CHECK_DEPTH {
                return Err(RebacError::ResourceExhausted(
                    "authorization evaluation exceeded its depth or step bound".into(),
                ));
            }
            let node_key = format!("{}|{}|{}", object.namespace, encode(&object.id)?, relation);
            if !visited.insert(node_key.clone()) {
                return Ok(false);
            }
            let definition = schema
                .namespaces
                .get(&object.namespace)
                .and_then(|namespace| namespace.relations.get(relation))
                .ok_or_else(|| {
                    RebacError::InvalidTuple(format!(
                        "unknown permission {}#{relation}",
                        object.namespace
                    ))
                })?;
            let result = match definition {
                TypedRelationDefinition::Direct { .. } => {
                    let tuples = self
                        .tuples_for_node(tx, scope, object, relation, revision, cache)
                        .await?;
                    let mut allowed = false;
                    for tuple in tuples {
                        *steps += 1;
                        if *steps > MAX_CHECK_STEPS {
                            return Err(RebacError::ResourceExhausted(
                                "authorization evaluation exceeded its step bound".into(),
                            ));
                        }
                        if &tuple.subject == subject {
                            allowed = true;
                            break;
                        }
                        if let TypedSubject::Userset {
                            object: userset_object,
                            relation: userset_relation,
                        } = &tuple.subject
                            && self
                                .check_node(
                                    tx,
                                    scope,
                                    schema,
                                    userset_object,
                                    userset_relation,
                                    subject,
                                    revision,
                                    visited,
                                    cache,
                                    depth + 1,
                                    steps,
                                )
                                .await?
                        {
                            allowed = true;
                            break;
                        }
                    }
                    allowed
                }
                TypedRelationDefinition::Permission { rules } => {
                    let mut allowed = false;
                    for rule in rules {
                        *steps += 1;
                        if *steps > MAX_CHECK_STEPS {
                            return Err(RebacError::ResourceExhausted(
                                "authorization evaluation exceeded its step bound".into(),
                            ));
                        }
                        match rule {
                            PermissionRule::Inherit {
                                relation: inherited,
                            } => {
                                if self
                                    .check_node(
                                        tx,
                                        scope,
                                        schema,
                                        object,
                                        inherited,
                                        subject,
                                        revision,
                                        visited,
                                        cache,
                                        depth + 1,
                                        steps,
                                    )
                                    .await?
                                {
                                    allowed = true;
                                    break;
                                }
                            }
                            PermissionRule::TupleToUserset {
                                tuple_relation,
                                target_relation,
                            } => {
                                let tuples = self
                                    .tuples_for_node(
                                        tx,
                                        scope,
                                        object,
                                        tuple_relation,
                                        revision,
                                        cache,
                                    )
                                    .await?;
                                for tuple in tuples {
                                    let target = match tuple.subject {
                                        TypedSubject::Entity(target)
                                        | TypedSubject::Userset { object: target, .. } => {
                                            Some(target)
                                        }
                                        TypedSubject::Public => None,
                                    };
                                    if let Some(target) = target
                                        && self
                                            .check_node(
                                                tx,
                                                scope,
                                                schema,
                                                &target,
                                                target_relation,
                                                subject,
                                                revision,
                                                visited,
                                                cache,
                                                depth + 1,
                                                steps,
                                            )
                                            .await?
                                    {
                                        allowed = true;
                                        break;
                                    }
                                }
                                if allowed {
                                    break;
                                }
                            }
                        }
                    }
                    allowed
                }
            };
            visited.remove(&node_key);
            Ok(result)
        })
    }

    async fn read_cursor(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        filter_digest: &[u8; 32],
        token: &str,
    ) -> Result<(u64, Option<TupleKey>), RebacError> {
        let id = Uuid::parse_str(token)
            .map_err(|_| RebacError::InvalidReadRequest("invalid page token".into()))?;
        let sql = format!(
            "SELECT storage_tenant_id,authz_realm_id,filter_digest,revision,after_object_namespace,after_object_id_json,after_relation, \
             after_subject_kind,after_subject_namespace,after_subject_id_json,after_subject_relation \
             FROM {} WHERE id=$1::uuid AND expires_at > now()",
            self.table("read_cursor")
        );
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| {
                RebacError::InvalidReadRequest("expired or unknown page token".into())
            })?;
        let tenant: String = row.try_get("storage_tenant_id")?;
        let realm: String = row.try_get("authz_realm_id")?;
        let digest: Vec<u8> = row.try_get("filter_digest")?;
        if tenant != scope.storage_tenant_id.0
            || realm != scope.authz_realm_id.0
            || digest.as_slice() != filter_digest
        {
            return Err(RebacError::InvalidReadRequest(
                "page token belongs to another query or scope".into(),
            ));
        }
        Ok((
            i64_to_u64(row.try_get("revision")?, "cursor revision")?,
            Some(TupleKey {
                object_namespace: row.try_get("after_object_namespace")?,
                object_id_json: row.try_get("after_object_id_json")?,
                relation: row.try_get("after_relation")?,
                subject_kind: row.try_get("after_subject_kind")?,
                subject_namespace: row.try_get("after_subject_namespace")?,
                subject_id_json: row.try_get("after_subject_id_json")?,
                subject_relation: row.try_get("after_subject_relation")?,
            }),
        ))
    }

    async fn insert_read_cursor(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: &AuthzScope,
        filter_digest: &[u8; 32],
        revision: u64,
        after: &TupleKey,
    ) -> Result<String, RebacError> {
        let sql = format!(
            "INSERT INTO {} (storage_tenant_id,authz_realm_id,filter_digest,revision,after_object_namespace,after_object_id_json, \
             after_relation,after_subject_kind,after_subject_namespace,after_subject_id_json,after_subject_relation,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+($12::double precision * interval '1 second')) RETURNING id::text",
            self.table("read_cursor")
        );
        let id: String = sqlx::query_scalar(&sql)
            .bind(&scope.storage_tenant_id.0)
            .bind(&scope.authz_realm_id.0)
            .bind(filter_digest.as_slice())
            .bind(u64_to_i64(revision, "authorization revision")?)
            .bind(&after.object_namespace)
            .bind(&after.object_id_json)
            .bind(&after.relation)
            .bind(&after.subject_kind)
            .bind(&after.subject_namespace)
            .bind(&after.subject_id_json)
            .bind(&after.subject_relation)
            .bind(READ_CURSOR_TTL.as_secs() as i64)
            .fetch_one(&mut **tx)
            .await?;
        Ok(id)
    }
}

#[derive(Default)]
struct TupleKey {
    object_namespace: String,
    object_id_json: String,
    relation: String,
    subject_kind: String,
    subject_namespace: String,
    subject_id_json: String,
    subject_relation: String,
}

struct SubjectFields {
    kind: String,
    namespace: String,
    id: String,
    relation: String,
}

fn subject_fields<I: Serialize>(subject: &TypedSubject<I>) -> Result<SubjectFields, RebacError> {
    Ok(match subject {
        TypedSubject::Entity(object) => SubjectFields {
            kind: "entity".into(),
            namespace: object.namespace.clone(),
            id: encode(&object.id)?,
            relation: String::new(),
        },
        TypedSubject::Userset { object, relation } => SubjectFields {
            kind: "userset".into(),
            namespace: object.namespace.clone(),
            id: encode(&object.id)?,
            relation: relation.clone(),
        },
        TypedSubject::Public => SubjectFields {
            kind: "public".into(),
            namespace: "app".into(),
            id: "null".into(),
            relation: String::new(),
        },
    })
}

fn tuple_fields<I: Serialize>(
    tuple: &TypedTuple<I>,
) -> Result<(String, String, String, String, String, String, String), RebacError> {
    let subject = subject_fields(&tuple.subject)?;
    Ok((
        tuple.object.namespace.clone(),
        encode(&tuple.object.id)?,
        tuple.relation.clone(),
        subject.kind,
        subject.namespace,
        subject.id,
        subject.relation,
    ))
}

fn row_to_binding(
    scope: &AuthzScope,
    row: sqlx::postgres::PgRow,
) -> Result<SchemaBinding, RebacError> {
    let digest: Vec<u8> = row.try_get("schema_digest")?;
    let schema_digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| RebacError::Internal("stored schema digest has invalid size".into()))?;
    Ok(SchemaBinding {
        scope: scope.clone(),
        schema_ref: SchemaRef {
            schema_id: SchemaId(row.try_get("schema_id")?),
            schema_revision: SchemaRevision(i64_to_u64(
                row.try_get("schema_revision")?,
                "schema revision",
            )?),
            schema_digest,
        },
        binding_generation: BindingGeneration(i64_to_u64(
            row.try_get("binding_generation")?,
            "binding generation",
        )?),
    })
}

fn row_to_tuple<I: DeserializeOwned>(
    row: &sqlx::postgres::PgRow,
) -> Result<TypedTuple<I>, RebacError> {
    let object_id_json: String = row.try_get("object_id_json")?;
    let subject_id_json: String = row.try_get("subject_id_json")?;
    let object_id = decode(&object_id_json)?;
    let subject_namespace: String = row.try_get("subject_namespace")?;
    let subject_kind: String = row.try_get("subject_kind")?;
    let subject_relation: String = row.try_get("subject_relation")?;
    let subject = match subject_kind.as_str() {
        "entity" => TypedSubject::Entity(TypedObject {
            namespace: subject_namespace,
            id: decode(&subject_id_json)?,
        }),
        "userset" => TypedSubject::Userset {
            object: TypedObject {
                namespace: subject_namespace,
                id: decode(&subject_id_json)?,
            },
            relation: subject_relation,
        },
        "public" => TypedSubject::Public,
        _ => {
            return Err(RebacError::Internal(
                "stored tuple subject kind is invalid".into(),
            ));
        }
    };
    Ok(TypedTuple {
        object: TypedObject {
            namespace: row.try_get("object_namespace")?,
            id: object_id,
        },
        relation: row.try_get("relation")?,
        subject,
    })
}

fn row_to_key(row: &sqlx::postgres::PgRow) -> Result<TupleKey, RebacError> {
    Ok(TupleKey {
        object_namespace: row.try_get("object_namespace")?,
        object_id_json: row.try_get("object_id_json")?,
        relation: row.try_get("relation")?,
        subject_kind: row.try_get("subject_kind")?,
        subject_namespace: row.try_get("subject_namespace")?,
        subject_id_json: row.try_get("subject_id_json")?,
        subject_relation: row.try_get("subject_relation")?,
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String, RebacError> {
    let value = serde_json::to_string(value)
        .map_err(|_| RebacError::Internal("authorization identity could not be encoded".into()))?;
    Ok(value)
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, RebacError> {
    serde_json::from_str(value)
        .map_err(|_| RebacError::Internal("stored authorization identity is invalid".into()))
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<[u8; 32], RebacError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| RebacError::InvalidReadRequest("query could not be encoded".into()))?;
    Ok(Sha256::digest(encoded).into())
}

fn validate_sql_identifier(value: &str) -> Result<(), RebacError> {
    if value.is_empty()
        || value.len() > 63
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(RebacError::Internal(
            "PostgreSQL schema must be a lowercase SQL identifier of at most 63 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_component(value: &str, kind: &str) -> Result<(), RebacError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.chars().any(char::is_control)
    {
        return Err(RebacError::InvalidSchema(format!(
            "invalid {kind}: {value:?}"
        )));
    }
    Ok(())
}

fn validate_schema<I: Serialize + Ord>(schema: &TypedSchema<I>) -> Result<(), RebacError> {
    if schema.namespaces.is_empty() {
        return Err(RebacError::InvalidSchema(
            "schema must contain a namespace".into(),
        ));
    }
    for (namespace_name, namespace) in &schema.namespaces {
        validate_component(namespace_name, "namespace")?;
        for (relation_name, definition) in &namespace.relations {
            validate_component(relation_name, "relation")?;
            match definition {
                TypedRelationDefinition::Direct { allowed_subjects } => {
                    if allowed_subjects.is_empty() {
                        return Err(RebacError::InvalidSchema(
                            "a direct relation must allow a subject selector".into(),
                        ));
                    }
                    for selector in allowed_subjects {
                        match selector {
                            TypedSubjectSelector::AnyObject { namespace }
                            | TypedSubjectSelector::SameResourceId { namespace } => {
                                validate_component(namespace, "subject namespace")?
                            }
                            TypedSubjectSelector::AnyUserset {
                                namespace,
                                relation,
                            } => {
                                validate_component(namespace, "subject namespace")?;
                                validate_component(relation, "userset relation")?;
                                if !schema
                                    .namespaces
                                    .get(namespace)
                                    .is_some_and(|n| n.relations.contains_key(relation))
                                {
                                    return Err(RebacError::InvalidSchema(format!(
                                        "unknown userset {namespace}#{relation}"
                                    )));
                                }
                            }
                            TypedSubjectSelector::Exact(subject) => {
                                validate_component(subject.namespace(), "exact subject namespace")?;
                                if let TypedSubject::Userset { object, relation } = subject
                                    && !schema
                                        .namespaces
                                        .get(&object.namespace)
                                        .is_some_and(|n| n.relations.contains_key(relation))
                                {
                                    return Err(RebacError::InvalidSchema(format!(
                                        "unknown exact userset {}#{relation}",
                                        object.namespace
                                    )));
                                }
                            }
                            TypedSubjectSelector::Public => {}
                        }
                    }
                }
                TypedRelationDefinition::Permission { rules } => {
                    if rules.is_empty() {
                        return Err(RebacError::InvalidSchema(
                            "a permission must contain a rule".into(),
                        ));
                    }
                    for rule in rules {
                        match rule {
                            PermissionRule::Inherit { relation } => {
                                validate_component(relation, "inherited relation")?;
                                if !namespace.relations.contains_key(relation) {
                                    return Err(RebacError::InvalidSchema(format!(
                                        "unknown inherited relation {namespace_name}#{relation}"
                                    )));
                                }
                            }
                            PermissionRule::TupleToUserset {
                                tuple_relation,
                                target_relation,
                            } => {
                                validate_component(tuple_relation, "tuple relation")?;
                                validate_component(target_relation, "target relation")?;
                                if !namespace.relations.contains_key(tuple_relation) {
                                    return Err(RebacError::InvalidSchema(format!(
                                        "unknown tuple relation {namespace_name}#{tuple_relation}"
                                    )));
                                }
                                if !schema
                                    .namespaces
                                    .values()
                                    .any(|n| n.relations.contains_key(target_relation))
                                {
                                    return Err(RebacError::InvalidSchema(format!(
                                        "unknown target relation {target_relation}"
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_tuple<I: Serialize + Eq + Ord>(
    schema: &TypedSchema<I>,
    tuple: &TypedTuple<I>,
) -> Result<(), RebacError> {
    validate_component(&tuple.object.namespace, "object namespace")?;
    validate_component(&tuple.relation, "relation")?;
    let definition = schema
        .namespaces
        .get(&tuple.object.namespace)
        .and_then(|namespace| namespace.relations.get(&tuple.relation))
        .ok_or_else(|| {
            RebacError::InvalidTuple(format!(
                "unknown relation {}#{}",
                tuple.object.namespace, tuple.relation
            ))
        })?;
    let TypedRelationDefinition::Direct { allowed_subjects } = definition else {
        return Err(RebacError::InvalidTuple(
            "tuple relation must be declared direct".into(),
        ));
    };
    let matches = allowed_subjects
        .iter()
        .any(|selector| match (selector, &tuple.subject) {
            (TypedSubjectSelector::AnyObject { namespace }, TypedSubject::Entity(subject)) => {
                namespace == &subject.namespace
            }
            (
                TypedSubjectSelector::AnyUserset {
                    namespace,
                    relation,
                },
                TypedSubject::Userset {
                    object,
                    relation: actual,
                },
            ) => namespace == &object.namespace && relation == actual,
            (TypedSubjectSelector::Exact(expected), actual) => expected == actual,
            (TypedSubjectSelector::SameResourceId { namespace }, TypedSubject::Entity(subject)) => {
                namespace == &subject.namespace && subject.id == tuple.object.id
            }
            (TypedSubjectSelector::Public, TypedSubject::Public) => true,
            _ => false,
        });
    if !matches {
        return Err(RebacError::InvalidTuple(format!(
            "subject is not admitted by {}#{}",
            tuple.object.namespace, tuple.relation
        )));
    }
    Ok(())
}

fn validate_check<I>(
    schema: &TypedSchema<I>,
    request: &TypedCheckRequest<I>,
) -> Result<(), RebacError> {
    validate_component(&request.object.namespace, "object namespace")
        .map_err(|_| RebacError::InvalidTuple("invalid object namespace".into()))?;
    let Some(namespace) = schema.namespaces.get(&request.object.namespace) else {
        return Err(RebacError::InvalidTuple(format!(
            "unknown object namespace {}",
            request.object.namespace
        )));
    };
    if !namespace.relations.contains_key(&request.relation) {
        return Err(RebacError::InvalidTuple(format!(
            "unknown permission {}#{}",
            request.object.namespace, request.relation
        )));
    }
    Ok(())
}

fn u64_to_i64(value: u64, kind: &str) -> Result<i64, RebacError> {
    i64::try_from(value)
        .map_err(|_| RebacError::Internal(format!("{kind} exceeds PostgreSQL BIGINT")))
}

fn i64_to_u64(value: i64, kind: &str) -> Result<u64, RebacError> {
    u64::try_from(value).map_err(|_| RebacError::Internal(format!("stored {kind} is negative")))
}

impl From<sqlx::Error> for RebacError {
    fn from(error: sqlx::Error) -> Self {
        // SQLx/database diagnostics can include connection configuration. Keep
        // credentials, query text and values out of returned errors and logs.
        // SQLSTATE is safe to expose and gives operators a useful diagnostic.
        let code = error
            .as_database_error()
            .and_then(|database| database.code())
            .map(|code| format!(" (SQLSTATE {code})"))
            .unwrap_or_default();
        Self::Unavailable(format!(
            "PostgreSQL authorization storage operation failed{code}"
        ))
    }
}
