-- -----------------------------------------------------------------------------
-- ReBAC (Relationship-Based Access Control) Core Schema
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS zanzibar_tuple (
    tenant_id BIGINT NOT NULL,
    object_namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject_namespace TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_relation TEXT, -- NULL if Entity, otherwise the relation for Userset
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- We need a constraint to prevent duplicate tuples
CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_tuple_unique_idx ON zanzibar_tuple (
    tenant_id, object_namespace, object_id, relation, subject_namespace, subject_id, 
    COALESCE(subject_relation, '')
);

CREATE INDEX IF NOT EXISTS zanzibar_tuple_subject_idx 
    ON zanzibar_tuple (tenant_id, subject_namespace, subject_id, subject_relation);

-- -----------------------------------------------------------------------------
-- ReBAC Relation Algebra (Schema Configuration)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS zanzibar_relation_config (
    tenant_id BIGINT NOT NULL,
    namespace TEXT NOT NULL,
    relation TEXT NOT NULL
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='zanzibar_relation_config' AND column_name='inherited_relation') THEN
        ALTER TABLE zanzibar_relation_config ADD COLUMN inherited_relation TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='zanzibar_relation_config' AND column_name='inherited_from_target_relation') THEN
        ALTER TABLE zanzibar_relation_config ADD COLUMN inherited_from_target_relation TEXT;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_relation_config_unique_idx ON zanzibar_relation_config (
    tenant_id, namespace, relation,
   -- By using COALESCE, we are forcing NULL values to participate in the uniqueness check
    COALESCE(inherited_relation, ''), 
    COALESCE(inherited_from_target_relation, '')
);
