use crate::{
    CheckRequest, Object, RebacEngine, RebacError, RelationRule, Schema, Subject, Tuple,
    TupleUpdate,
};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresRebacEngine {
    pool: PgPool,
}

impl PostgresRebacEngine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RebacEngine for PostgresRebacEngine {
    async fn check(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object: &Object,
    ) -> Result<bool, RebacError> {
        let (sub_ns, sub_id, sub_rel) = match subject {
            Subject::Entity(obj) => (obj.namespace.clone(), obj.id.clone(), None),
            Subject::Userset { object, relation } => (
                object.namespace.clone(),
                object.id.clone(),
                Some(relation.clone()),
            ),
        };

        // Fully compliant Zanzibar Recursive CTE: expands the graph from the target Object#Relation
        // through userset jumps and schema inheritance to find the Subject.
        let query = r#"
            WITH RECURSIVE reachable_usersets AS (
                -- 1. Base Case: The initial permission node we are checking
                SELECT 
                    $2::TEXT AS namespace, 
                    $3::TEXT AS object_id, 
                    $4::TEXT AS relation

                UNION

                -- 2. Recursive Case: Expand through schema and tuples
                SELECT 
                    next_node.namespace, next_node.object_id, next_node.relation
                FROM reachable_usersets ru
                CROSS JOIN LATERAL (
                    -- A. Same-object Inheritance (Rewrites)
                    SELECT 
                        ru.namespace, ru.object_id, rc.inherited_relation AS relation
                    FROM zanzibar_relation_config rc
                    WHERE rc.tenant_id = $1 
                        AND rc.namespace = ru.namespace 
                        AND rc.relation = ru.relation
                        AND rc.inherited_relation IS NOT NULL 
                        AND rc.inherited_from_target_relation IS NULL

                    UNION ALL

                    -- B. Tuple Traversal (Walk to a new userset)
                    SELECT 
                        t.subject_namespace, t.subject_id, t.subject_relation
                    FROM zanzibar_tuple t
                    WHERE t.tenant_id = $1 
                        AND t.object_namespace = ru.namespace 
                        AND t.object_id = ru.object_id 
                        AND t.relation = ru.relation

                    UNION ALL

                    -- C. Userset Jumps (Computed / Tuple-to-Userset)
                    SELECT 
                        t.subject_namespace, t.subject_id, rc.inherited_relation
                    FROM zanzibar_relation_config rc
                    JOIN zanzibar_tuple t ON t.tenant_id = $1 
                        AND t.object_namespace = ru.namespace 
                        AND t.object_id = ru.object_id 
                        AND t.relation = rc.inherited_from_target_relation
                    WHERE rc.tenant_id = $1 
                        AND rc.namespace = ru.namespace 
                        AND rc.relation = ru.relation
                        AND rc.inherited_from_target_relation IS NOT NULL
                        AND rc.inherited_relation IS NOT NULL
                ) next_node
            )
            SELECT EXISTS (
                -- terminal check: any reachable userset points directly to the subject
                SELECT 1 
                FROM reachable_usersets ru
                JOIN zanzibar_tuple t ON t.tenant_id = $1 
                    AND t.object_namespace = ru.namespace 
                    AND t.object_id = ru.object_id 
                    AND t.relation = ru.relation
                WHERE (t.subject_namespace = $5 OR t.subject_namespace = '*')
                  AND (t.subject_id = $6 OR t.subject_id = '*')
                  AND (t.subject_relation IS NOT DISTINCT FROM $7)

                UNION ALL

                -- terminal check: the subject itself was reached as a userset node
                SELECT 1 
                FROM reachable_usersets ru
                WHERE (ru.namespace = $5 OR ru.namespace = '*')
                  AND (ru.object_id = $6 OR ru.object_id = '*')
                  AND (ru.relation IS NOT DISTINCT FROM $7)
            )
        "#;

        let row = sqlx::query(query)
            .bind(tenant_id)
            .bind(&object.namespace)
            .bind(&object.id)
            .bind(relation)
            .bind(&sub_ns)
            .bind(&sub_id)
            .bind(sub_rel)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;

        Ok(row.get(0))
    }

    async fn check_many(
        &self,
        tenant_id: i64,
        requests: Vec<CheckRequest>,
    ) -> Result<Vec<bool>, RebacError> {
        let mut results = Vec::with_capacity(requests.len());
        for req in requests {
            results.push(
                self.check(tenant_id, &req.subject, &req.relation, &req.object)
                    .await?,
            );
        }
        Ok(results)
    }

    async fn write_tuples(
        &self,
        tenant_id: i64,
        updates: Vec<TupleUpdate>,
    ) -> Result<(), RebacError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;
        for update in updates {
            match update {
                TupleUpdate::Write(t) => {
                    let (sub_ns, sub_id, sub_rel) = match t.subject {
                        Subject::Entity(obj) => (obj.namespace, obj.id, None),
                        Subject::Userset { object, relation } => {
                            (object.namespace, object.id, Some(relation))
                        }
                    };
                    sqlx::query(
                        r#"INSERT INTO zanzibar_tuple 
                           (tenant_id, object_namespace, object_id, relation, subject_namespace, subject_id, subject_relation)
                           VALUES ($1, $2, $3, $4, $5, $6, $7)
                           ON CONFLICT (tenant_id, object_namespace, object_id, relation, subject_namespace, subject_id, COALESCE(subject_relation, '')) 
                           DO NOTHING"#
                    )
                    .bind(tenant_id)
                    .bind(t.object.namespace)
                    .bind(t.object.id)
                    .bind(t.relation)
                    .bind(sub_ns)
                    .bind(sub_id)
                    .bind(sub_rel)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| RebacError::Internal(e.to_string()))?;
                }
                TupleUpdate::Delete(t) => {
                    let (sub_ns, sub_id, sub_rel) = match t.subject {
                        Subject::Entity(obj) => (obj.namespace, obj.id, None),
                        Subject::Userset { object, relation } => {
                            (object.namespace, object.id, Some(relation))
                        }
                    };
                    sqlx::query(
                        r#"DELETE FROM zanzibar_tuple 
                           WHERE tenant_id = $1 AND object_namespace = $2 AND object_id = $3 
                           AND relation = $4 AND subject_namespace = $5 AND subject_id = $6 
                           AND (subject_relation IS NOT DISTINCT FROM $7)"#,
                    )
                    .bind(tenant_id)
                    .bind(t.object.namespace)
                    .bind(t.object.id)
                    .bind(t.relation)
                    .bind(sub_ns)
                    .bind(sub_id)
                    .bind(sub_rel)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| RebacError::Internal(e.to_string()))?;
                }
            }
        }
        tx.commit()
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn read_tuples(
        &self,
        tenant_id: i64,
        object: Option<Object>,
        relation: Option<String>,
        subject: Option<Subject>,
    ) -> Result<Vec<Tuple>, RebacError> {
        let (sub_ns, sub_id, sub_rel) = match subject {
            Some(Subject::Entity(obj)) => (Some(obj.namespace), Some(obj.id), None),
            Some(Subject::Userset { object, relation }) => {
                (Some(object.namespace), Some(object.id), Some(relation))
            }
            None => (None, None, None),
        };

        let rows = sqlx::query(
            r#"SELECT object_namespace, object_id, relation, subject_namespace, subject_id, subject_relation 
               FROM zanzibar_tuple 
               WHERE tenant_id = $1 
               AND ($2::TEXT IS NULL OR object_namespace = $2)
               AND ($3::TEXT IS NULL OR object_id = $3)
               AND ($4::TEXT IS NULL OR relation = $4)
               AND ($5::TEXT IS NULL OR subject_namespace = $5)
               AND ($6::TEXT IS NULL OR subject_id = $6)
               AND ($7::TEXT IS NULL OR subject_relation IS NOT DISTINCT FROM $7)"#
        )
        .bind(tenant_id)
        .bind(object.as_ref().map(|o| &o.namespace))
        .bind(object.as_ref().map(|o| &o.id))
        .bind(relation)
        .bind(sub_ns)
        .bind(sub_id)
        .bind(sub_rel)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RebacError::Internal(e.to_string()))?;

        let mut tuples = Vec::with_capacity(rows.len());
        for row in rows {
            let obj_ns: String = row.get(0);
            let obj_id: String = row.get(1);
            let rel: String = row.get(2);
            let s_ns: String = row.get(3);
            let s_id: String = row.get(4);
            let s_rel: Option<String> = row.get(5);

            let subject = match s_rel {
                Some(r) => Subject::Userset {
                    object: Object {
                        namespace: s_ns,
                        id: s_id,
                    },
                    relation: r,
                },
                None => Subject::Entity(Object {
                    namespace: s_ns,
                    id: s_id,
                }),
            };

            tuples.push(Tuple {
                object: Object {
                    namespace: obj_ns,
                    id: obj_id,
                },
                relation: rel,
                subject,
            });
        }
        Ok(tuples)
    }

    async fn apply_schema(&self, tenant_id: i64, schema: Schema) -> Result<(), RebacError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;

        sqlx::query("DELETE FROM zanzibar_relation_config WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;

        for (ns, config) in schema.namespaces {
            for (rel, rules) in config.rules {
                for rule in rules {
                    let (inh_rel, inh_from) = match rule {
                        RelationRule::Inherit(r) => (Some(r), None),
                        RelationRule::Computed {
                            tuple_relation,
                            target_relation,
                        } => (Some(target_relation), Some(tuple_relation)),
                        RelationRule::TupleToUserset {
                            tuple_relation,
                            target_relation,
                        } => (Some(target_relation), Some(tuple_relation)),
                    };

                    sqlx::query(
                        r#"INSERT INTO zanzibar_relation_config 
                           (tenant_id, namespace, relation, inherited_relation, inherited_from_target_relation)
                           VALUES ($1, $2, $3, $4, $5)"#
                    )
                    .bind(tenant_id)
                    .bind(&ns)
                    .bind(&rel)
                    .bind(inh_rel)
                    .bind(inh_from)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| RebacError::Internal(e.to_string()))?;
                }
            }
        }
        tx.commit()
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn list_objects(
        &self,
        tenant_id: i64,
        subject: &Subject,
        relation: &str,
        object_namespace: &str,
    ) -> Result<Vec<String>, RebacError> {
        let (sub_ns, sub_id, sub_rel) = match subject {
            Subject::Entity(obj) => (obj.namespace.clone(), obj.id.clone(), None),
            Subject::Userset { object, relation } => (
                object.namespace.clone(),
                object.id.clone(),
                Some(relation.clone()),
            ),
        };

        // REVERSE recursion: Find all nodes (Object, Relation) that can REACH the target Subject.
        let query = r#"
            WITH RECURSIVE nodes_reaching_subject AS (
                -- 1. Base Case: Nodes that point DIRECTLY to the subject
                SELECT 
                    t.object_namespace, 
                    t.object_id, 
                    t.relation
                FROM zanzibar_tuple t
                WHERE t.tenant_id = $1
                  AND (t.subject_namespace = $4 OR t.subject_namespace = '*')
                  AND (t.subject_id = $5 OR t.subject_id = '*')
                  AND (t.subject_relation IS NOT DISTINCT FROM $6)

                UNION

                -- 2. Recursive Case: Nodes that point to previously found nodes
                SELECT 
                    parent.object_namespace, parent.object_id, parent.relation
                FROM nodes_reaching_subject child
                CROSS JOIN LATERAL (
                    -- A. Tuple Traversal: Object points to Child Node as its subject
                    SELECT 
                        t.object_namespace, t.object_id, t.relation
                    FROM zanzibar_tuple t
                    WHERE t.tenant_id = $1 
                        AND t.subject_namespace = child.object_namespace 
                        AND t.subject_id = child.object_id 
                        AND (t.subject_relation IS NOT DISTINCT FROM child.relation)

                    UNION ALL

                    -- B. Schema Inheritance: Object#Relation inherits from Child Node
                    SELECT 
                        child.object_namespace, child.object_id, rc.relation
                    FROM zanzibar_relation_config rc
                    WHERE rc.tenant_id = $1 
                        AND rc.namespace = child.object_namespace 
                        AND (
                            -- Direct Inheritance: O#R inherits from O#child.R
                            (rc.inherited_relation = child.relation AND rc.inherited_from_target_relation IS NULL)
                            OR
                            -- Computed/Tuple Jumps: O#R inherits from O#child.R (where child.R is the result of a tuple jump)
                            (rc.inherited_from_target_relation = child.relation AND rc.inherited_relation IS NOT NULL)
                        )
                ) parent
            )
            SELECT DISTINCT object_id 
            FROM nodes_reaching_subject 
            WHERE object_namespace = $3 AND relation = $2;
        "#;

        let rows = sqlx::query(query)
            .bind(tenant_id)
            .bind(relation)
            .bind(object_namespace)
            .bind(&sub_ns)
            .bind(&sub_id)
            .bind(sub_rel)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    async fn list_subjects(
        &self,
        tenant_id: i64,
        object: &Object,
        relation: &str,
        subject_namespace: &str,
    ) -> Result<Vec<String>, RebacError> {
        let query = r#"
            WITH RECURSIVE expanded_subjects AS (
                SELECT subject_namespace, subject_id, subject_relation
                FROM zanzibar_tuple
                WHERE tenant_id = $1 AND object_namespace = $2 AND object_id = $3 AND relation = $4
                UNION
                SELECT t.subject_namespace, t.subject_id, t.subject_relation
                FROM expanded_subjects es
                JOIN zanzibar_tuple t ON t.tenant_id = $1 
                    AND t.object_namespace = es.subject_namespace 
                    AND t.object_id = es.subject_id 
                    AND t.relation = es.subject_relation
                WHERE es.subject_relation IS NOT NULL
            )
            SELECT DISTINCT subject_id FROM expanded_subjects 
            WHERE (subject_namespace = $5 OR subject_namespace = '*') AND subject_relation IS NULL
        "#;

        let rows = sqlx::query(query)
            .bind(tenant_id)
            .bind(&object.namespace)
            .bind(&object.id)
            .bind(relation)
            .bind(subject_namespace)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RebacError::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }
}
