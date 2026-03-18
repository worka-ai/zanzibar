# Zanzibar Enterprise Scaling Benchmarks

This directory contains the testing and validation infrastructure required to scale the `zanzibar` crate to handle enterprise workloads (10M+ rows, deeply nested hierarchies, concurrent Zipfian access patterns).

## Current Status (Phase 1)

We are currently testing the absolute physical limits of the **PostgreSQL Recursive CTE** architecture.

*   `postgres_scale.rs`: Contains micro-benchmarks measuring the algorithmic overhead of the recursive CTE loops under specific pathological conditions (e.g. 100-levels deep, wide flat joins).
*   `stress_test.rs`: Contains a high-volume load generator that utilizes Postgres `COPY BINARY`/`COPY CSV` to instantly load tens of millions of tuples representing a complex enterprise domain (like GitHub Orgs/Teams or AWS IAM), followed by concurrent query flooding to test connection pooling, cache eviction, and index traversal.

### The Limits of PostgreSQL

While highly optimized, relying solely on PostgreSQL recursive CTEs for a globally distributed authorization system has known architectural limits:
1.  **Memory Constraints (`work_mem`)**: Wide fan-outs (e.g., a "Global Employees" group with 2 million users) require holding massive intermediate datasets in RAM during recursive joins. If it spills to disk, latency spikes drastically.
2.  **B-Tree Depth**: At 1 billion rows, the B-Tree index becomes deep enough that un-cached random reads incur physical disk IO overhead.
3.  **Compute Monolith**: Database compute scales vertically (making the DB larger and more expensive). Authorization checks usually scale with application traffic, which scales horizontally. 

To overcome these limits, the architecture must evolve.

---

## Future Architecture Roadmap

### Phase 2: Application-Layer Compute Engine (The True Zanzibar Model)

Instead of forcing PostgreSQL to calculate the entire graph in a single SQL query, the `zanzibar` crate will move graph traversal into the application layer (Rust/Tokio).

*   **Dumb Storage, Smart Compute**: Postgres is relegated to simple point-lookups (`SELECT * FROM zanzibar_tuple WHERE object = $1`).
*   **Horizontal Scaling**: Graph traversal happens concurrently using Tokio tasks. If you need more authorization throughput, you deploy more stateless API servers, rather than paying for a larger database.
*   **Leopard Indexing**: Incorporating Leopard indexing principles, we can utilize highly compact skip-lists in memory.

### Phase 3: Reachability Caching & Tuple Flattening

To achieve sub-millisecond p99 latencies globally, we must avoid traversing the graph entirely on the read-path.

*   **Bloom Filters (Reachability Caching)**: When a tuple is written, a Bloom Filter is updated. When a read comes in, the filter is checked. If it returns "No", access is denied instantly without touching Postgres.
*   **Tuple Flattening (Materialization)**: Instead of recursively calculating `User A -> Group B -> Folder C` at read time, a background async worker materializes the graph at write time by inserting a direct `User A -> viewer -> Folder C` tuple. Reads become true `O(1)` index lookups.