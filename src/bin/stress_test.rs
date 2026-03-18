use sqlx::PgPool;
use std::env;
use std::time::Instant;
use tokio::task::JoinSet;
use zanzibar::postgres::PostgresRebacEngine;
use zanzibar::{
    NamespaceConfig, Object, RebacEngine, RelationRule, SchemaBuilder, Subject,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    let mut rows = 10_000_000;
    let mut database_url = "postgresql://worka:worka@localhost:5432/worka".to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rows" => {
                if let Some(val) = args.next() {
                    rows = val.parse().unwrap_or(10_000_000);
                }
            }
            "--database-url" => {
                if let Some(val) = args.next() {
                    database_url = val;
                }
            }
            _ => {}
        }
    }

    println!("Starting Zanzibar enterprise stress test...");
    println!("Target rows: {}", rows);

    let pool = PgPool::connect(&database_url).await?;
    let engine = PostgresRebacEngine::new(pool.clone());
    let tenant_id = 888888; // Dedicated tenant for enterprise stress test

    // 1. Setup Enterprise Schema (GitHub style)
    let schema = SchemaBuilder::new()
        .namespace(
            "repo",
            NamespaceConfig {
                rules: HashMap::from([
                    (
                        "reader".to_string(),
                        vec![RelationRule::Inherit("writer".to_string())],
                    ),
                    (
                        "writer".to_string(),
                        vec![RelationRule::Inherit("admin".to_string())],
                    ),
                    (
                        "admin".to_string(),
                        vec![RelationRule::Computed {
                            tuple_relation: "organization".to_string(),
                            target_relation: "admin".to_string(),
                        }],
                    ),
                ]),
            },
        )
        .namespace(
            "organization",
            NamespaceConfig {
                rules: HashMap::from([
                    ("admin".to_string(), vec![]),
                    ("member".to_string(), vec![]),
                ]),
            },
        )
        .build();

    engine.apply_schema(tenant_id, schema).await?;

    // 2. Clear old data
    sqlx::query("DELETE FROM zanzibar_tuple WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await?;

    // 3. Fast Bulk Generation via COPY
    println!("Generating and writing {} rows via COPY CSV...", rows);
    let start_insert = Instant::now();
    
    let mut tx = pool.begin().await?;
    let mut copy_in = tx.copy_in_raw(
        "COPY zanzibar_tuple (tenant_id, object_namespace, object_id, relation, subject_namespace, subject_id, subject_relation) FROM STDIN WITH (FORMAT csv)"
    ).await?;

    let batch_size = 100_000;
    let mut current = 0;
    
    while current < rows {
        let mut buf = String::new();
        for i in 0..batch_size {
            if current + i >= rows {
                break;
            }
            
            let org_id = (current + i) % 100;
            let repo_id = (current + i) % 10_000;
            let user_id = current + i;
            
            // Add to org
            buf.push_str(&format!("{},organization,org_{},member,user,user_{},\n", tenant_id, org_id, user_id));
            
            // Add repo to org (only once per repo to avoid unique constraint violations)
            if (current + i) < 10_000 {
                buf.push_str(&format!("{},repo,repo_{},organization,organization,org_{},\n", tenant_id, repo_id, org_id));
            }

            // Direct read access to repo
            buf.push_str(&format!("{},repo,repo_{},reader,user,user_{},\n", tenant_id, repo_id, user_id));
        }
        
        copy_in.send(buf.as_bytes()).await?;
        current += batch_size;
        println!("  Copied {} rows...", current);
    }
    
    copy_in.finish().await?;
    tx.commit().await?;

    let duration = start_insert.elapsed();
    println!("Bulk insertion complete in {:.2?}", duration);

    // 4. Concurrent Load Testing
    println!("Running concurrent load queries...");
    
    let concurrency = 100;
    let requests_per_worker = 100;
    
    let mut join_set = JoinSet::new();
    let start_queries = Instant::now();

    for worker_id in 0..concurrency {
        let engine = engine.clone();
        join_set.spawn(async move {
            let mut latencies = Vec::with_capacity(requests_per_worker);
            for req in 0..requests_per_worker {
                let user_id = format!("user_{}", (worker_id * 1000) + req);
                let repo_id = format!("repo_{}", req % 100);
                
                let user = Subject::Entity(Object { namespace: "user".into(), id: user_id });
                let repo = Object { namespace: "repo".into(), id: repo_id };
                
                let start = Instant::now();
                let _ = engine.check(tenant_id, &user, "reader", &repo).await;
                latencies.push(start.elapsed().as_micros());
            }
            latencies
        });
    }

    let mut all_latencies = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(lats) = res {
            all_latencies.extend(lats);
        }
    }

    let query_duration = start_queries.elapsed();
    all_latencies.sort_unstable();
    
    let p50 = all_latencies[all_latencies.len() / 2];
    let p90 = all_latencies[(all_latencies.len() as f64 * 0.90) as usize];
    let p99 = all_latencies[(all_latencies.len() as f64 * 0.99) as usize];
    
    println!("Finished {} requests in {:.2?}", concurrency * requests_per_worker, query_duration);
    println!("Latencies (us): P50: {}us | P90: {}us | P99: {}us", p50, p90, p99);

    println!("Cleaning up test data...");
    sqlx::query("DELETE FROM zanzibar_tuple WHERE tenant_id = $1").bind(tenant_id).execute(&pool).await?;

    Ok(())
}
