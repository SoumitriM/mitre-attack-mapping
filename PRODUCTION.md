# Production deployment

Deploy the FastAPI service with Neo4j 5.x and pinned Enterprise ATT&CK 19.1.
The default API returns the compact response described in [README.md](README.md)
and [tests/fixtures/compact-results.json](tests/fixtures/compact-results.json).

## Initial deployment

Requirements: Python 3.11+, Docker Compose, and outbound access to NVD, the CVE List V5
repository, OpenCVE, MITRE dataset hosting, selected advisory domains, and FH Genie.

```bash
git clone <repository-url>
cd mitre-attack-chain
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cp .env.example .env
```

Populate secrets using the deployment platform's secret manager or environment injection.
When using `.env`, protect its filesystem permissions and never commit it.
Configure:

```env
FH_GENIE_KEY=<secret>
FH_GENIE_BASE_URL=<openai-compatible-provider-url>
FH_GENIE_MODEL=MiniMaxAI/MiniMax-M2.5
FH_GENIE_EMBEDDING_MODEL=BAAI/bge-m3
INFERENCE_PROVIDER=fh_genie
NEO4J_URI=bolt://127.0.0.1:7688
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<strong-secret>
ENABLE_CTID_MAPPING=true
ATTACK_EMBEDDING_CACHE_PATH=data/cache/attack-embeddings.json
```

An NVD API key is recommended for higher rate limits. `ADVISORY_ALLOWED_DOMAINS`
controls additional untagged advisory sources; add only trusted domains needed by the deployment.
OpenRouter is optional and changes only extraction: set `INFERENCE_PROVIDER=openrouter`
and its key, URL, and model settings. Other stages still use FH Genie.

Load runtime data explicitly:

```bash
docker compose pull neo4j
docker compose up -d neo4j
docker compose ps
python -m app.data.sync_mitre
python -m app.cli initialize-attack-embedding-cache
```

The stack uses `neo4j:5.26-community`, HTTP port 7475, Bolt port 7688, and the named
`mitre-attack-chain-neo4j-data` volume. If the API runs in a container on the same
network, use `NEO4J_URI=bolt://neo4j:7687`. Restrict Neo4j to the application network.

Synchronization loads taxonomy and removes obsolete CWE/CAPEC graph data. CVE metadata
can still retain CWE/CAPEC IDs; their full taxonomies are not loaded. Runtime startup
does not download datasets. Repeat synchronization for a new database or a changed
pinned version. Persist the database volume and embedding cache across restarts.

## Start and restart

```bash
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Use exactly one worker because jobs and retained results are process-local.
Do not use `--reload` in production. Put TLS, authentication, request-size limits,
and rate limiting in a reverse proxy or API gateway; the service has no built-in authentication.
Configure forwarded-header trust only for proxies controlled by the deployment.

On later restarts, reuse the database and cache:

```bash
docker compose up -d neo4j
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

## Verify the API contract

Check process liveness:

```bash
curl --fail http://127.0.0.1:8000/healthz
```

Expected: `{"status":"ok"}`. This does not check Neo4j or model-provider availability.
Submit a full workflow dependency check:

```bash
curl --fail-with-body -X POST http://127.0.0.1:8000/api/cve-analysis \
  -H 'Content-Type: application/json' \
  -d '{"cve_ids":["CVE-2026-33557","CVE-2026-57112"],"description_source":"auto"}'
```

POST returns HTTP 202 with `job_id`, `status: "pending"`, and `poll_url`.
Poll that URL with GET about every three seconds:

```bash
curl --fail-with-body http://127.0.0.1:8000/api/cve-analysis/<job_id>
```

GET returns HTTP 200. While processing, it reports `pending`; completion reports
`completed` and `results`, an array matching the compact response fixture.
Each result contains `cve_id`, `attack_chain`, and `ctid_map`. Both structures include
`technique_id`, `tactic_id`, `technique_name`, and `tactic_name`. Names come from the
stored official taxonomy and do not change mapping decisions. Unmapped IDs/names remain null.
PI/SI nodes expose `enabled_by` to preserve causality.

The example fixture is a reviewed contract sample; live predictions can vary.
Polling does not repeat source or model calls. Keep the returned job URL rather than
submitting again. Failures return `status: "failed"` with an error object and no partial
batch results. Add `?compact=false` on the initial POST for full diagnostic evidence and
warnings. Compact results omit warnings, so a completed job alone does not establish that
every extracted behavior has an ATT&CK mapping or that CTID succeeded for every CVE.

`description_source` supports `auto`, `opencve`, and `advisories`. Auto tries extraction
from substantive descriptions without mechanism keywords, then uses new advisory evidence
if extraction is empty. CTID classifies the existing chain into ET -> PI -> SI and only
reuses source mappings; it makes no second ATT&CK mapping pass. Set
`ENABLE_CTID_MAPPING=false` to disable CTID. The obsolete `CTID_ONLY_MODE` is not supported.

## Capacity and retention

```env
ANALYSIS_JOB_RETENTION_SECONDS=3600
ANALYSIS_JOB_CAPACITY=100
ANALYSIS_JOB_CONCURRENCY=2
HTTP_TIMEOUT_SECONDS=15
HTTP_MAX_RETRIES=3
MAPPING_MIN_CONFIDENCE=0.50
ADVISORY_MAX_BYTES=2000000
```

CVEs run sequentially within a batch. Queued batches report `pending`. Capacity counts
active and retained jobs; new submissions return 503 when full. Results expire after the
retention interval measured from completion/failure; unknown or expired IDs return 404.
Restarting loses pending and retained jobs. Measure provider limits before increasing concurrency.
A durable shared job store would be needed for multiple workers or replicas.

## Files, backups, and releases

Commit source, configuration examples, dependency definitions, documentation, setup scripts,
and tests with their reviewed fixtures. Runtime installations do not need development tools.
Do not include `.env`, virtual environments, Neo4j data, generated inputs/results, logs,
downloaded datasets, or embedding caches in Git or release artifacts.

There are no required `input/`, `out/`, or `output/` folders. API results stay in process
memory; the CLI prints compact JSON by default. To save an operational result outside the
source tree, use:

```bash
python -m app.cli analyze CVE-2026-33557 CVE-2026-57112 --output /tmp/analyses.json
```

Runtime diagnostics under `logs/` may contain CVE-derived evidence and provider responses.
Protect and retain them according to deployment needs. Keep `data/manifest.json` with
diagnostics. Back up the Neo4j volume and test restore procedures. Preserve the embedding
cache where practical; it can be regenerated with the initialization command.

Before release, run in a development environment or CI:

```bash
python -m pip install -e '.[dev]'
pytest
ruff check app tests scripts
mypy app
```

Deploy the validated source with `python -m pip install .`. Repeat dataset synchronization
only when required, then verify liveness and one polled analysis. Roll back by restoring
the previous application build; restore Neo4j from backup if a migration changed the graph.
