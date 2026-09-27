# MITRE Attack Chain

Evidence-grounded CVE analysis that combines live NVD and CVE List V5 records,
trusted security advisories, FH Genie structured extraction, bounded ATT&CK mapping,
independent validation, and Neo4j provenance.

See [PRODUCTION.md](PRODUCTION.md) for deployment and operations guidance.

## Current scope

Implemented: normalized CVE metadata, pinned Enterprise ATT&CK synchronization,
trusted advisory retrieval, evidence-linked exploit-step extraction, bounded ATT&CK mapping,
independent validation, final ordered attack-chain generation, additive CTID CVE-level mappings,
Neo4j storage, FastAPI, and CLI.

## Requirements and installation

- Python 3.11+
- Network access to NVD, MITRE dataset downloads, trusted advisory domains, and FH Genie
- Docker with Compose for the local Neo4j service

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

To reuse the FH Genie credentials from the sibling `incident-resolution-ai` project while
creating isolated Neo4j credentials and ports, run:

```bash
python scripts/configure_from_incident_env.py
```

Configure Neo4j and FH Genie in `.env`. An NVD API key is optional but recommended for
higher rate limits. Never commit `.env`.

Exploit extraction defaults to FH Genie MiniMax with `INFERENCE_PROVIDER=fh_genie`. To switch
extraction back to OpenRouter, set `INFERENCE_PROVIDER=openrouter` and configure
`OPENROUTER_KEY`, `OPENROUTER_BASE_URL`, and `OPENROUTER_MODEL`. ATT&CK retrieval, reranking,
mapping, and CTID mapping continue to use FH Genie.

This Compose stack is named `mitre-attack-chain`, uses its own
`mitre-attack-chain-neo4j-data` volume, and publishes Neo4j on HTTP port 7475 and Bolt port
7688. It does not share the sibling project's Neo4j container or data.

Start Neo4j and explicitly synchronize the pinned datasets:

```bash
docker compose up -d neo4j
python -m app.data.sync_mitre
```

This command stores only Enterprise ATT&CK 19.1 locally. CWE and CAPEC IDs remain part of
normalized CVE metadata for model context, but their full taxonomies are not downloaded or stored.
It does not download or retain the CVE corpus.

Use `--download-only` to verify and extract the datasets without loading Neo4j. Runtime
startup never downloads datasets. Archives and the generated checksum manifest are stored
under ignored `data/` paths.

## Run

```bash
python -m app.cli analyze CVE-2026-22306 CVE-2025-0282 \
  --output output/analyses.json
uvicorn app.main:app --reload
```

Then call:

```bash
curl -X POST http://127.0.0.1:8000/api/cve-analysis \
  -H 'content-type: application/json' \
  -d '{"cve_ids":["CVE-2026-22306","CVE-2025-0282"]}'
```

The default response is a JSON array containing one result per requested CVE, in the same order as
`cve_ids`. Each result contains only `cve_id` and `attack_chain`. Every chain step has the required
`step`, `action`, `tactic_id`, `technique_id`, `confidence`, and `mapped` fields; IDs are null when
`mapped` is false. The request must contain at least one CVE ID. Use `?compact=false` only when the
complete analysis, including source advisories and internal evidence, is required.

Each entry in `attack_mappings` contains exactly the step/action, nullable technique and
tactic IDs, evidence-grounded reasoning, confidence, and supporting evidence IDs. A step
without a suitable official candidate is returned with null IDs and low confidence.

`attack_chain` is the final ordered result. Each proposed mapping is independently checked
against the active official ATT&CK technique, its tactics and platforms, advisory evidence,
and CVSS constraints. Only validated mappings remain connected with `MAPS_TO`; weak,
contradictory, unavailable, and exact duplicate mappings are returned with null IDs and an
explanation. The original exploit step always remains, and validation cannot add steps or infer
post-exploitation behavior.

`cve_level_attack_mappings` is an additional result following CTID's CVE Mapping Methodology. It
contains `exploitation_techniques`, `primary_impacts`, and `secondary_impacts` arrays, each of which
may contain zero or more independently evidenced behaviors. Secondary impacts identify their
causal primary impacts through `enabled_by`. Each behavior is derived only from evidence already
attached to the extracted steps,
then passed through the same hybrid ATT&CK retrieval, closed-set reranking, mapping, and independent
validation used by the step pipeline. Unsupported categories remain explicitly unmapped. This
stage does not use deterministic CWE, CAPEC, CVSS, vulnerability-class, or keyword-to-technique
rules, and it does not modify `attack_chain`. An evidenced behavior remains in the output with null
ATT&CK IDs when no suitable technique exists or validation fails; `processing_status` distinguishes
that semantic result from retrieval, mapping, or validation failures.

## Quality checks

```bash
pytest
ruff check .
mypy app
```

## Design notes

NVD is the primary per-CVE API. The official CVE List V5 repository supplies each requested
record live as fallback and supplementary data; CVE.org HTML is never scraped and CVEs are never
bulk-downloaded. Tagged advisory references are prioritized,
and untagged references require a configured allowlisted domain. Advisory requests reject private
networks, revalidate redirects, and enforce content and size limits.

Normalized CVE records are cached on their Neo4j `CVE` node with the structured-source retrieval
timestamp and full field provenance. `CACHE_TTL_SECONDS` controls freshness (default one hour);
fresh records avoid source requests, stale records are fetched again, and `0` disables the cache.
Refreshing a CVE replaces its scoped evidence relationships so outdated source context is not
retained.

FH Genie receives the normalized authoritative CVE description and fetched advisory text as
untrusted evidence. Each returned exploit step must cite an exact excerpt from a supplied source.
Description evidence is reported separately from advisory fetch status, so extraction can proceed
when advisory pages are unavailable. Invalid output is retried once, then represented as an empty
step list with a warning. No CWE/CAPEC relationship is generated by the model.

Enterprise ATT&CK 19.1 techniques and tactics are loaded from the pinned official STIX bundle.
For every extracted step, the system retrieves the top 20 official techniques with BM25 and the
top 20 with semantic embeddings, deduplicates the union, and asks FH Genie to rerank it to five.
BM25 uses the raw evidence-grounded step text, while vector retrieval uses an FH Genie-generated
behavioral abstraction. Technique documents include official ATT&CK descriptions and procedure
examples loaded from the pinned STIX bundle; runtime retrieval never scrapes MITRE pages.
FH Genie may select only one of those candidates and one of its official tactics, or return null
IDs with low confidence. The Mapping Agent validates candidate membership,
platform support, tactic membership, step identity, and evidence IDs. A separate fail-closed
Validation Agent then re-queries the official ATT&CK graph and asks FH Genie only whether the
unchanged proposal is supported by the supplied action, evidence, and CVSS context. It may retain,
lower confidence, or reject a mapping, but it cannot replace it with a different technique or
invent post-exploitation behavior.
