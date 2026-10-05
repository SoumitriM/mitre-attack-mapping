# MITRE Attack Chain

Analyze CVEs into evidence-grounded attack chains and CTID causal structure.
The CLI and FastAPI service use live NVD/CVE List records, OpenCVE descriptions,
trusted advisories, FH Genie, and the pinned Enterprise ATT&CK 19.1 taxonomy in Neo4j.

See [PRODUCTION.md](PRODUCTION.md) for deployment, secrets, and operations.

## Install and configure

Requirements: Python 3.11+, Docker Compose, and access to CVE sources, MITRE dataset
hosting, advisory domains, and the configured FH Genie endpoint.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Set `FH_GENIE_KEY`, `FH_GENIE_BASE_URL`, and `NEO4J_PASSWORD` in `.env`.
The included Compose stack exposes Neo4j at HTTP port 7475 and Bolt port 7688;
use `NEO4J_URI=bolt://127.0.0.1:7688`. An NVD API key is optional.
Never commit `.env`.

To create isolated Neo4j settings and reuse FH Genie credentials from the sibling
`incident-resolution-ai` project, optionally run:

```bash
python scripts/configure_from_incident_env.py
```

Initialize the database and optional embedding cache:

```bash
docker compose up -d neo4j
python -m app.data.sync_mitre
python -m app.cli initialize-attack-embedding-cache
```

Synchronization explicitly downloads and loads Enterprise ATT&CK 19.1. Runtime startup
never downloads datasets. Neo4j stores taxonomy only; analysis data is kept in memory.
The Compose database uses its own `mitre-attack-chain-neo4j-data` volume.

## Run the API and poll from a terminal

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Submit the two CVEs:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/cve-analysis \
  -H 'Content-Type: application/json' \
  -d '{"cve_ids":["CVE-2026-33557","CVE-2026-57112"]}'
```

The API immediately returns HTTP 202:

```json
{"job_id":"<uuid>","status":"pending","poll_url":"/api/cve-analysis/<uuid>"}
```

Poll the returned URL, waiting about three seconds between calls:

```bash
curl -sS http://127.0.0.1:8000/api/cve-analysis/<uuid>
```

When finished, GET returns HTTP 200 with:

```json
{"job_id":"<uuid>","status":"completed","poll_url":"/api/cve-analysis/<uuid>","results":[]}
```

`results` is the compact analysis array, in requested CVE order. Its exact example is
[tests/fixtures/compact-results.json](tests/fixtures/compact-results.json).
Each result has `cve_id`, `attack_chain`, and `ctid_map`:

- Attack-chain steps contain `step`, `action`, `technique_id`, `tactic_id`,
  `technique_name`, `tactic_name`, `confidence`, and `mapped`.
- CTID contains `exploitation_techniques`, `primary_impacts`, and `secondary_impacts`.
  Each node has `id`, `action`, technique/tactic IDs and names, and `status`;
  PI/SI also have `enabled_by` causal references.
- Names are resolved from existing IDs in Neo4j after analysis. Unmapped nodes keep
  null IDs and names; unavailable names remain null without changing the IDs.

The example documents the response contract, not fixed model predictions.
Use `?compact=false` on POST for full evidence, warnings, and diagnostic fields.
Each POST creates a new job. Polling never reruns analysis. A failed batch returns
`status: "failed"` and an `error`; partial batch results are not published.

Jobs are process-local. Use one Uvicorn worker. Restarting clears jobs. Finished jobs
expire after `ANALYSIS_JOB_RETENTION_SECONDS` (default 3600); expired IDs return 404.
`ANALYSIS_JOB_CAPACITY` defaults to 100, and new submissions return 503 at capacity.
`ANALYSIS_JOB_CONCURRENCY` defaults to two simultaneous batches. CVEs within a batch
run sequentially. Pending polls include `Retry-After: 3`.

## Frontend team handoff

Run these commands from the cloned repository root. For a first-time setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp .env.example .env
```

Populate `FH_GENIE_KEY`, `FH_GENIE_BASE_URL`, `NEO4J_PASSWORD`, and
`NEO4J_URI=bolt://127.0.0.1:7688` in `.env` before continuing:

```bash
docker compose up -d neo4j
python -m app.data.sync_mitre
python -m app.cli initialize-attack-embedding-cache
```

For subsequent starts, reuse the configured environment and database:

```bash
source .venv/bin/activate
docker compose up -d neo4j
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Use `http://localhost:8000` when the frontend runs on the same machine, or
`http://<backend-host>:8000` when it runs elsewhere. `0.0.0.0` is the listening
address, not the URL to use in the frontend.

| Purpose | Method | Path |
| --- | --- | --- |
| Check liveness | GET | `/healthz` |
| Submit a CVE batch | POST | `/api/cve-analysis` |
| Poll an existing job | GET | `/api/cve-analysis/{job_id}` |
| Explore API documentation | GET | `/docs` |

Send `Content-Type: application/json` with this POST body:

```json
{"cve_ids":["CVE-2026-33557","CVE-2026-57112"]}
```

Store `job_id` and `poll_url` from the HTTP 202 response. Poll `poll_url` against
the same backend every three seconds (or follow `Retry-After`). Continue on
`pending`, render `results` on `completed`, and show `error.message` on `failed`.
Stop polling after completion or failure. A 404 means the job is unknown or expired;
a server restart also loses jobs. Submit once per user request rather than POSTing
again during polling. The default `results` format is the compact fixture linked above.

For browser integration, configure the frontend development server or reverse proxy
to forward `/api` requests to this backend. The API currently has no CORS middleware,
so direct requests from a different browser origin require proxying or explicit CORS
configuration. Keep provider and database credentials on the backend.

## CLI

The CLI prints the same compact analysis array directly to the terminal:

```bash
python -m app.cli analyze CVE-2026-33557 CVE-2026-57112
```

Add `--full` for full diagnostics. `--output /tmp/analyses.json` optionally saves JSON.
The API server is not required for CLI analysis; Neo4j and provider access are required.

## Analysis and CTID

`description_source=auto` first fetches the OpenCVE description, falling back to the
normalized authoritative description if OpenCVE is unavailable. Descriptions with at
least eight whitespace-separated words go directly to extraction. Short descriptions
use advisories first. Empty extraction triggers advisory retrieval and another extraction
only when new advisory evidence was fetched. Failed model calls do not trigger that fallback.

Choose `opencve` to use only the OpenCVE description without advisory fallback, or
`advisories` to fetch advisory evidence first. The CLI uses `--description-source`.
The advisory path retrieves at most two successful sources, prioritizes vendors, and
cleans/compresses evidence before extraction. Requests reject private networks and enforce
redirect, content, and size constraints.

ATT&CK retrieval uses BM25 and semantic embeddings, then FH Genie reranks candidates and
maps the extracted steps. Existing mapping checks determine the final chain. CTID makes
one causal-classification call over those results; it does not retrieve candidates,
rerank, or map techniques again. It builds ET -> PI -> SI, with structural schema and
reference validation. Unmapped behaviors can still become CTID nodes.

ET may reuse an existing source-step mapping. PI/SI reuse mappings only when they identify
their own distinct source behavior with the same action. Summarized consequences and
reused upstream sources retain null IDs. Shared supporting evidence is allowed.
Set `ENABLE_CTID_MAPPING=false` to skip CTID; the obsolete `CTID_ONLY_MODE` workflow
has been removed.

FH Genie is the default extraction provider. Optional OpenRouter extraction uses
`INFERENCE_PROVIDER=openrouter` plus `OPENROUTER_KEY`, `OPENROUTER_BASE_URL`, and
`OPENROUTER_MODEL`. Other model stages continue to use FH Genie.

## Development

```bash
pytest
ruff check app tests scripts
mypy app
```

Runtime code is under `app/`, tests and the reviewed response fixture are under `tests/`,
and setup/preview helpers are under `scripts/`. The `evaluations/dataset.json` fixture and
`python -m app.cli evaluate` support offline scoring of saved full analyses.
Generated inputs, results, logs, datasets, caches, and environments are excluded from Git.
