use sqlx::{Executor, PgPool};
use tokio::sync::OnceCell;

static SCHEMA_INIT: OnceCell<()> = OnceCell::const_new();

pub async fn ensure_schema(pool: &PgPool) {
    let pool = pool.clone();
    SCHEMA_INIT
        .get_or_init(move || async move {
            pool.execute(zanzibar::POSTGRES_SCHEMA)
                .await
                .expect("Failed to initialize Zanzibar Postgres schema");
        })
        .await;
}
