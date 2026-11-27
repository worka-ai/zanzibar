CREATE SCHEMA IF NOT EXISTS {{schema}};

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_authz_revision (
    storage_tenant_id text PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision >= 0)
);

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_schema (
    storage_tenant_id text NOT NULL,
    schema_id text NOT NULL,
    schema_revision bigint NOT NULL CHECK (schema_revision > 0),
    schema_digest bytea NOT NULL CHECK (octet_length(schema_digest) = 32),
    schema_json jsonb NOT NULL,
    created_revision bigint NOT NULL CHECK (created_revision > 0),
    PRIMARY KEY (storage_tenant_id, schema_id, schema_revision),
    UNIQUE (storage_tenant_id, schema_id, schema_digest)
);

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_schema_binding_history (
    storage_tenant_id text NOT NULL,
    authz_realm_id text NOT NULL,
    schema_id text NOT NULL,
    schema_revision bigint NOT NULL,
    schema_digest bytea NOT NULL CHECK (octet_length(schema_digest) = 32),
    binding_generation bigint NOT NULL CHECK (binding_generation > 0),
    valid_from_revision bigint NOT NULL CHECK (valid_from_revision > 0),
    valid_until_revision bigint,
    PRIMARY KEY (storage_tenant_id, authz_realm_id, binding_generation),
    FOREIGN KEY (storage_tenant_id, schema_id, schema_revision)
        REFERENCES {{schema}}.zanzibar_schema(storage_tenant_id, schema_id, schema_revision),
    CHECK (valid_until_revision IS NULL OR valid_until_revision > valid_from_revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_one_current_binding
    ON {{schema}}.zanzibar_schema_binding_history(storage_tenant_id, authz_realm_id)
    WHERE valid_until_revision IS NULL;
CREATE INDEX IF NOT EXISTS zanzibar_binding_at_revision
    ON {{schema}}.zanzibar_schema_binding_history
       (storage_tenant_id, authz_realm_id, valid_from_revision DESC, valid_until_revision);

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_tuple_history (
    storage_tenant_id text NOT NULL,
    authz_realm_id text NOT NULL,
    object_namespace text NOT NULL,
    object_id_json text NOT NULL,
    relation text NOT NULL,
    subject_kind text NOT NULL CHECK (subject_kind IN ('entity', 'userset', 'public')),
    subject_namespace text NOT NULL,
    subject_id_json text NOT NULL,
    subject_relation text NOT NULL,
    added_revision bigint NOT NULL CHECK (added_revision > 0),
    removed_revision bigint,
    CHECK (removed_revision IS NULL OR removed_revision > added_revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS zanzibar_one_active_tuple
    ON {{schema}}.zanzibar_tuple_history
       (storage_tenant_id, authz_realm_id, object_namespace, object_id_json,
        relation, subject_kind, subject_namespace, subject_id_json, subject_relation)
    WHERE removed_revision IS NULL;
CREATE INDEX IF NOT EXISTS zanzibar_tuple_object_relation_revision
    ON {{schema}}.zanzibar_tuple_history
       (storage_tenant_id, authz_realm_id, object_namespace, object_id_json, relation,
        added_revision, removed_revision, subject_kind, subject_namespace,
        subject_id_json, subject_relation);
CREATE INDEX IF NOT EXISTS zanzibar_tuple_subject_revision
    ON {{schema}}.zanzibar_tuple_history
       (storage_tenant_id, authz_realm_id, subject_kind, subject_namespace,
        subject_id_json, subject_relation, added_revision, removed_revision,
        object_namespace, object_id_json, relation);

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_operation_receipt (
    storage_tenant_id text NOT NULL,
    authz_realm_id text NOT NULL,
    operation_id text NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    PRIMARY KEY (storage_tenant_id, authz_realm_id, operation_id)
);

CREATE TABLE IF NOT EXISTS {{schema}}.zanzibar_read_cursor (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    storage_tenant_id text NOT NULL,
    authz_realm_id text NOT NULL,
    filter_digest bytea NOT NULL CHECK (octet_length(filter_digest) = 32),
    revision bigint NOT NULL CHECK (revision >= 0),
    after_object_namespace text NOT NULL,
    after_object_id_json text NOT NULL,
    after_relation text NOT NULL,
    after_subject_kind text NOT NULL,
    after_subject_namespace text NOT NULL,
    after_subject_id_json text NOT NULL,
    after_subject_relation text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS zanzibar_read_cursor_expiry
    ON {{schema}}.zanzibar_read_cursor(expires_at);
