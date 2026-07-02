-- -----------------------------------------------------------------------------
-- ReBAC (Relationship-Based Access Control) scope-aware schema
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS zanzibar_schema (
    storage_tenant_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_revision BIGINT NOT NULL,
    schema_digest TEXT NOT NULL,
    schema_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (storage_tenant_id, schema_id, schema_revision)
);

CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_schema_digest_unique_idx
    ON zanzibar_schema (storage_tenant_id, schema_id, schema_digest);

CREATE TABLE IF NOT EXISTS zanzibar_schema_relation_config (
    storage_tenant_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_revision BIGINT NOT NULL,
    namespace TEXT NOT NULL,
    relation TEXT NOT NULL,
    rule_index INTEGER NOT NULL,
    inherited_relation TEXT,
    inherited_from_target_relation TEXT,
    PRIMARY KEY (
        storage_tenant_id, schema_id, schema_revision, namespace, relation, rule_index
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_schema_relation_config_unique_idx
    ON zanzibar_schema_relation_config (
        storage_tenant_id, schema_id, schema_revision, namespace, relation,
        COALESCE(inherited_relation, ''), COALESCE(inherited_from_target_relation, '')
    );

CREATE TABLE IF NOT EXISTS zanzibar_realm_schema_binding (
    storage_tenant_id TEXT NOT NULL,
    authz_realm_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_revision BIGINT NOT NULL,
    schema_digest TEXT NOT NULL,
    binding_generation BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (storage_tenant_id, authz_realm_id)
);

CREATE TABLE IF NOT EXISTS zanzibar_scoped_tuple (
    storage_tenant_id TEXT NOT NULL,
    authz_realm_id TEXT NOT NULL,
    object_namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject_namespace TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_relation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_scoped_tuple_unique_idx
    ON zanzibar_scoped_tuple (
        storage_tenant_id, authz_realm_id, object_namespace, object_id, relation,
        subject_namespace, subject_id, COALESCE(subject_relation, '')
    );

CREATE INDEX IF NOT EXISTS zanzibar_scoped_tuple_subject_idx
    ON zanzibar_scoped_tuple (
        storage_tenant_id, authz_realm_id, subject_namespace, subject_id, subject_relation
    );

CREATE TABLE IF NOT EXISTS zanzibar_authz_revision (
    storage_tenant_id TEXT NOT NULL,
    authz_realm_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    PRIMARY KEY (storage_tenant_id, authz_realm_id)
);
