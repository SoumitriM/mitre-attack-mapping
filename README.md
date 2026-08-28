# MITRE Attack Chain

Production-oriented foundation for building evidence-grounded attack paths from a CVE ID.
Phase 1 retrieves CVE records from CVE.org and NVD, tolerates a single-source outage, and returns
a typed normalized record with explicit unknown values, source attribution, and warnings.

## Current scope

Implemented: CVE metadata, affected products/platforms/versions, CVSS, CWE IDs, explicitly supplied
CAPEC IDs, references, FastAPI, and CLI. Neo4j, CWE/CAPEC/ATT&CK dataset ingestion, LangGraph,
advisory extraction, LLM mapping, validation, and complete attack-path output belong to later phases.

## Requirements and installation

- Python 3.11+
- Network access to `cveawg.mitre.org` and `services.nvd.nist.gov`

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

An NVD API key is optional but recommended for higher rate limits. Never commit `.env`.

## Run

```bash
python -m app.cli analyze CVE-2024-3094
uvicorn app.main:app --reload
```

Then call:

```bash
curl -X POST http://127.0.0.1:8000/api/attack-path \
  -H 'content-type: application/json' \
  -d '{"cve_id":"CVE-2024-3094"}'
```

## Quality checks

```bash
pytest
ruff check .
mypy app
```

## Design notes

Source-specific clients return raw authoritative data; normalization is isolated and deterministic.
The service queries CVE.org and NVD concurrently and records partial-source failures as warnings.
No LLM is used in Phase 1, and missing fields remain `null` or empty instead of being inferred.
