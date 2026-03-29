use sqlx::{Executor, PgPool};
use tokio::sync::OnceCell;

static SCHEMA_INIT: OnceCell<()> = OnceCell::const_new();

pub async fn ensure_schema(pool: &PgPool) {
    let pool = pool.clone();
    SCHEMA_INIT
        .get_or_init(move || async move {
            pool.execute(
                r#"
                CREATE TABLE IF NOT EXISTS zanzibar_tuple (
                    tenant_id BIGINT NOT NULL,
                    object_namespace TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    subject_namespace TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    subject_relation TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .await
            .expect("Failed to create zanzibar_tuple table");

            pool.execute(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_tuple_unique_idx ON zanzibar_tuple (
                    tenant_id, object_namespace, object_id, relation, subject_namespace, subject_id,
                    COALESCE(subject_relation, '')
                )
                "#,
            )
            .await
            .expect("Failed to create zanzibar_tuple_unique_idx");

            pool.execute(
                r#"
                CREATE INDEX IF NOT EXISTS zanzibar_tuple_subject_idx
                    ON zanzibar_tuple (tenant_id, subject_namespace, subject_id, subject_relation)
                "#,
            )
            .await
            .expect("Failed to create zanzibar_tuple_subject_idx");

            pool.execute(
                r#"
                CREATE TABLE IF NOT EXISTS zanzibar_relation_config (
                    tenant_id BIGINT NOT NULL,
                    namespace TEXT NOT NULL,
                    relation TEXT NOT NULL
                )
                "#,
            )
            .await
            .expect("Failed to create zanzibar_relation_config table");

            pool.execute(
                r#"
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM information_schema.columns
                        WHERE table_name = 'zanzibar_relation_config'
                          AND column_name = 'inherited_relation'
                    ) THEN
                        ALTER TABLE zanzibar_relation_config ADD COLUMN inherited_relation TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1
                        FROM information_schema.columns
                        WHERE table_name = 'zanzibar_relation_config'
                          AND column_name = 'inherited_from_target_relation'
                    ) THEN
                        ALTER TABLE zanzibar_relation_config ADD COLUMN inherited_from_target_relation TEXT;
                    END IF;
                END
                $$;
                "#,
            )
            .await
            .expect("Failed to initialize zanzibar_relation_config columns");

            pool.execute(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_relation_config_unique_idx ON zanzibar_relation_config (
                    tenant_id, namespace, relation,
                    COALESCE(inherited_relation, ''),
                    COALESCE(inherited_from_target_relation, '')
                )
                "#,
            )
            .await
            .expect("Failed to create zanzibar_relation_config_unique_idx");
        })
        .await;
}
