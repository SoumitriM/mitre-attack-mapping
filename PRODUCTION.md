# Production deployment

This guide deploys the FastAPI service with Neo4j and the pinned Enterprise ATT&CK dataset.
Development tools and tests are not required at runtime.

## Requirements

- Python 3.11 or newer
- Neo4j 5.x
- Network access to NVD, CVE List V5, OpenCVE, configured advisory domains, and FH Genie
- An FH Genie API key and base URL
- An NVD API key is recommended for production rate limits

OpenRouter is optional. FH Genie MiniMax is the default inference provider.

## GitHub-to-production handoff

GitHub should contain the reproducible source and deployment definitions, not a running database,
downloaded datasets, generated results, caches, logs, or credentials.

Commit and distribute:

- Application source under `app/`
- `pyproject.toml` and `uv.lock`
- `docker-compose.yml`
- `.env.example`
- `README.md` and `PRODUCTION.md`
- Dataset synchronization and configuration scripts under `scripts/`
- Tests for CI and release validation; they do not need to run on the production server

Do not commit or transfer through GitHub:

- `.env` or any API/database credentials
- The Neo4j database or Docker volume
- `data/raw/`, `data/cache/`, or `data/manifest.json`
- Runtime logs under `logs/`
- Generated analysis files under `output/`
- Local virtual environments, Python caches, or build artifacts

These local paths must remain covered by `.gitignore`. Production secrets should be delivered
through the hosting platform's secret manager or another approved secure channel.

The production operator reconstructs runtime state after cloning the repository:

```bash
git clone <repository-url>
cd mitre-attack-chain

cp .env.example .env
# Replace placeholders with production secrets; never commit this file.

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .

docker compose pull neo4j
docker compose up -d neo4j
docker compose ps

python -m app.data.sync_mitre
python -m app.cli initialize-attack-embedding-cache

uvicorn app.main:app --host 0.0.0.0 --port 8000
```

During the first `docker compose pull`, Docker downloads `neo4j:5.26-community`. The named
`neo4j-data` volume is created on the production server and must be persisted there. The ATT&CK
synchronization command downloads pinned Enterprise ATT&CK data and loads it into that database.
Neither the image, database volume, nor downloaded ATT&CK content needs to be packaged in GitHub.

On later restarts, reuse the existing Neo4j volume and embedding cache:

```bash
docker compose up -d neo4j
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Run dataset synchronization again for a new empty database, after restoring a database without
ATT&CK data, or when the application pins a new ATT&CK version. Do not run one synchronization job
per API worker.

## Install runtime dependencies

Create a dedicated virtual environment and install the application without the `dev` extra:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Do not install `.[dev]` in the production image. The development extra contains pytest, Ruff,
mypy, and other test-only packages.

## Configure the environment

Supply secrets through the deployment platform's secret manager or environment injection. Do not
commit a populated `.env` file.

Required settings for the default FH Genie deployment:

```env
FH_GENIE_KEY=<secret>
FH_GENIE_BASE_URL=<fh-genie-openai-compatible-url>
FH_GENIE_MODEL=MiniMaxAI/MiniMax-M2.5
FH_GENIE_EMBEDDING_MODEL=BAAI/bge-m3
INFERENCE_PROVIDER=fh_genie

NEO4J_URI=bolt://127.0.0.1:7688
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<strong-secret>
```

Recommended application settings:

```env
NVD_API_KEY=<secret>
HTTP_TIMEOUT_SECONDS=30
HTTP_MAX_RETRIES=3
ANALYSIS_JOB_RETENTION_SECONDS=3600
ANALYSIS_JOB_CAPACITY=100
ANALYSIS_JOB_CONCURRENCY=2
MAPPING_MIN_CONFIDENCE=0.50
ENABLE_CTID_MAPPING=true
CTID_ONLY_MODE=false
ADVISORY_ALLOWED_DOMAINS=offseq.com
ADVISORY_MAX_BYTES=2000000
ATTACK_EMBEDDING_CACHE_PATH=data/cache/attack-embeddings.json
```

`ADVISORY_ALLOWED_DOMAINS` is a comma-separated allowlist. Add only domains whose advisory
content the deployment is expected to retrieve.

### Switching to OpenRouter

Only exploit-step extraction switches providers. Embeddings, ATT&CK reranking, ATT&CK mapping,
and CTID mapping continue to use FH Genie. In the default description-first mode,
extraction receives the OpenCVE description directly when it explains a concrete mechanism. Sparse descriptions or empty extraction
fall back to at most two successful vendor-prioritized advisories. For those advisories,
the service removes boilerplate and duplicate or unrelated passages, and uses
FH Genie MiniMax to create the compact attack passage. OpenRouter receives that passage
on the advisory path; on the description-only first pass it receives the description.
The extractor emits atomic retrieval-ready actions. Vector retrieval uses the step fields and
evidence directly without a second LLM rewrite.

```env
INFERENCE_PROVIDER=openrouter
OPENROUTER_KEY=<secret>
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=anthropic/claude-opus-4.6
```

Set `INFERENCE_PROVIDER=fh_genie` to return to MiniMax. Merely defining an OpenRouter key does not
select OpenRouter.

## Start Neo4j

For a single-host deployment, the included Compose service provides an isolated Neo4j instance:

```bash
docker compose up -d neo4j
docker compose ps
```

The default host ports are HTTP `7475` and Bolt `7688`. The named `neo4j-data` volume must be
included in production backups.

If the API runs in another container on the same Compose network, use:

```env
NEO4J_URI=bolt://neo4j:7687
```

Do not expose Neo4j ports publicly. Restrict them to the application network or host firewall.

## Load Enterprise ATT&CK

Dataset synchronization is an explicit deployment step and is not performed during API startup:

```bash
python -m app.data.sync_mitre
```

This downloads and loads pinned Enterprise ATT&CK 19.1. It also removes obsolete CWE/CAPEC graph
data from older deployments. CWE and CAPEC identifiers remain in normalized CVE metadata for model
context, but their complete taxonomies are not stored.

Run synchronization during initial deployment and whenever the pinned dataset version changes.
Keep the generated `data/manifest.json` with deployment diagnostics, but do not bake downloaded raw
data or model caches into source control.

Optionally precompute the ATT&CK embedding cache before serving traffic:

```bash
python -m app.cli initialize-attack-embedding-cache
```

Persist `data/cache/attack-embeddings.json` between application restarts when practical.

## Start the API

Run the application without auto-reload:

```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips='<trusted-proxy-addresses>'
```

Only trust proxy addresses controlled by the deployment. Place TLS termination, authentication,
request-size limits, request timeouts, and rate limiting in a reverse proxy or API gateway. The
application endpoint itself does not implement authentication.

Run **one application worker**: polling jobs are process-local and are not shared across
processes. To allow more simultaneous batches, tune `ANALYSIS_JOB_CONCURRENCY` after
measuring FH Genie, NVD, and Neo4j limits. Each batch processes CVEs in input order.
A shared durable queue/store would be needed before adding workers or replicas.

## Health and smoke checks

The liveness endpoint verifies that the HTTP process is responding:

```bash
curl --fail http://127.0.0.1:8000/healthz
```

Expected response:

```json
{"status":"ok"}
```

The health endpoint does not verify Neo4j or external model providers. Use a small analysis request
as a post-deployment dependency check:

```bash
curl --fail-with-body \
  --request POST \
  'http://127.0.0.1:8000/api/cve-analysis' \
  --header 'content-type: application/json' \
  --data '{"cve_ids":["CVE-2021-44228"]}'
```

The POST returns HTTP 202 with a job identifier and polling URL:

```json
{"job_id":"<uuid>","status":"pending","poll_url":"/api/cve-analysis/<uuid>"}
```

Poll using GET, waiting approximately three seconds between calls:

```bash
curl --fail-with-body 'http://127.0.0.1:8000/api/cve-analysis/<uuid>'
```

Pending GET responses remain HTTP 200 with `status: "pending"` and no results.
After the entire batch finishes, GET returns `status: "completed"` with a
`results` array of the existing compact CVE/attack-chain/CTID views. The returned
URL can be polled again without repeating model or source calls. Each new POST
starts a new job. A batch failure becomes `status: "failed"` with an `error`
containing its code and message; partial results are not returned.

Use `?compact=false` on the initial POST for full diagnostic results. The body
can set `description_source` to `auto` (default), `opencve`, or `advisories`.
Auto first uses description evidence; sparse descriptions or successful empty
extraction trigger advisory retrieval and compression. OpenCVE fetch failures
fall back to the authoritative description. No same-evidence extraction retry
is introduced by this fallback. Source reasons and empty-extraction warnings are
available in full results.

Jobs are retained in server memory for `ANALYSIS_JOB_RETENTION_SECONDS` after
completion or failure (default one hour). Expired/unknown jobs return 404.
`ANALYSIS_JOB_CAPACITY` bounds active and retained jobs together (default 100);
when full, submission returns 503. `ANALYSIS_JOB_CONCURRENCY` limits simultaneous
batches (default two); queued jobs also return pending. Shutdown cancels active
jobs and releases resources. A restart clears all jobs, including completed results.

## CTID modes

The normal attack-chain response with CTID output is produced with:

```env
ENABLE_CTID_MAPPING=true
CTID_ONLY_MODE=false
```

Set `ENABLE_CTID_MAPPING=false` only when CTID calculation must be disabled. Set
`CTID_ONLY_MODE=true` only for a dedicated description-based CTID workflow; that mode does not
produce the normal attack-chain response.

## Operational data

- Neo4j stores only Enterprise ATT&CK techniques, tactics, their relationships, and the ATT&CK
  dataset-release marker.
- CVE records, advisories, evidence, exploit steps, mappings, validation results, and CTID results
  remain in process memory for a running job and its result retention window. They are never
  written to Neo4j.
- Each new job retrieves CVE source data again. Polling reads retained job state. Restarting
  the API loses pending and retained jobs; those polling URLs then return 404.
- Runtime diagnostic logs are written below `logs/` and may contain CVE-derived model responses.
  Protect them, apply retention limits, and do not ship them to public storage.
- Output written with the CLI `--output` option may contain security-analysis data. Treat it as an
  operational artifact rather than source code.
- Back up the Neo4j volume according to the database's supported backup procedure and test restore
  operations regularly.

## Upgrades and rollback

Before an upgrade:

1. Back up the Neo4j volume and deployment configuration.
2. Build a new immutable application artifact with `pip install .`.
3. Run the repository test suite in CI, not on the production host.
4. Deploy the new artifact and run `python -m app.data.sync_mitre` if dataset code changed.
5. Verify `/healthz` and one analysis request.

Rollback by restoring the previous application artifact. Restore Neo4j from backup if an upgrade
performed an incompatible graph migration.

## Production checklist

- Runtime dependencies installed without `.[dev]`
- Secrets injected outside source control
- FH Genie MiniMax selected unless OpenRouter is intentionally configured
- Neo4j inaccessible from the public internet
- Enterprise ATT&CK synchronization completed
- Embedding cache persisted or initialized
- TLS, authentication, rate limits, and request limits enforced upstream
- Neo4j backups and log retention configured
- Health and analysis smoke checks passing
