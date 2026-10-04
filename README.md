# MITRE Attack Chain

Evidence-grounded CVE analysis that combines live NVD and CVE List V5 records,
trusted security advisories, FH Genie structured extraction, bounded ATT&CK mapping,
deterministic mapping checks, and Neo4j taxonomy retrieval.

See [PRODUCTION.md](PRODUCTION.md) for deployment and operations guidance.

## Current scope

Implemented: normalized CVE metadata, pinned Enterprise ATT&CK synchronization,
trusted advisory retrieval, evidence-linked exploit-step extraction, bounded ATT&CK mapping,
deterministic mapping checks, final ordered attack-chain generation, additive CTID CVE-level
mappings, Neo4j taxonomy storage, FastAPI, and CLI.

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
mapping, and CTID mapping continue to use FH Genie. Advisory preprocessing and compression also
always use FH Genie MiniMax, so OpenRouter receives only the compact attack-relevant passage.
Extracted actions are canonicalized into atomic, attacker-controlled behaviors, and vector
retrieval embeds those actions directly. There is no additional LLM query-normalization stage.
CTID-only mode still normalizes the CVE description into role-specific behaviors before retrieval.

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
`cve_ids`. Each result contains `cve_id`, `attack_chain`, and `ctid_map`. Every chain step has the
required `step`, `action`, `tactic_id`, `technique_id`, `confidence`, and `mapped` fields; IDs are
null when `mapped` is false. `ctid_map` contains `exploitation_techniques`, `primary_impacts`, and
`secondary_impacts`. The request must contain at least one CVE ID. Use `?compact=false` only when
the complete in-memory analysis, including source advisories and evidence, is required.

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
then passed through hybrid ATT&CK retrieval and mapping. CTID responses undergo JSON schema
validation only; candidate membership, evidence provenance, causal links, platform compatibility,
and confidence thresholds are not checked, and no independent validator is called. Schema-valid
behaviors and links are preserved as returned. `processing_status` distinguishes retrieval and
mapping failures. This stage does not modify `attack_chain` or its deterministic mapping checks.

To compare description-only extraction with the advisory workflow, use:

```bash
python -m app.cli analyze CVE-2024-3400 --description-source opencve \
  --full --output output/opencve-analysis.json
```

The alternative `CVEAnalysisService.analyze_opencve` fetches the public OpenCVE
page once and uses only its Description section as extraction evidence. It skips
advisory fetching and compression, then uses the same ATT&CK and CTID pipeline.
Authoritative NVD/CVE List metadata still supplies CVSS and platform context.
Description provenance and exact evidence excerpts point to OpenCVE. Fetch or
page-format failures are explicit; this path does not fall back to advisories.
CTID-only mode must be disabled. The CLI otherwise retains the normal pipeline
retry policy; the saved comparison runner explicitly disables retries.
Short descriptions may omit exploit details supplied by advisories.

## Quality checks

```bash
pytest
ruff check .
mypy app
```

## Design notes

NVD is the primary per-CVE API. The official CVE List V5 repository supplies each requested
record live as fallback and supplementary data; CVE.org HTML is never scraped and CVEs are never
bulk-downloaded. The service reads at most two successfully fetched advisories per CVE, prioritizing
vendor sources and deprioritizing exploit mirrors. Untagged references require a configured
allowlisted domain. Advisory requests reject private networks, revalidate redirects, and enforce
content and size limits.

Neo4j stores only the pinned Enterprise ATT&CK matrix. CVE records, advisory content, evidence,
exploit steps, mappings, validation results, and CTID results exist only in request memory and are
released after the response is produced. Every request fetches current CVE source data; no
per-CVE record or analysis is retained in the database.

The service removes advisory boilerplate, unrelated CVEs, and duplicate passages before FH Genie
MiniMax compresses the evidence into a short chronological attack passage. The selected extraction
provider receives that passage; with `INFERENCE_PROVIDER=openrouter`, this is the only stage that
uses Claude. Original advisory text remains request-local and is used to attach exact evidence to
the extracted steps. Description evidence is included as fallback when an advisory is unavailable.
No CWE/CAPEC relationship is generated by the model.

Enterprise ATT&CK 19.1 techniques and tactics are loaded from the pinned official STIX bundle.
For every extracted step, the system retrieves the top 20 official techniques with BM25 and the
top 20 with semantic embeddings, deduplicates the union, and asks FH Genie to rerank it to five.
BM25 and vector retrieval both use the atomic step fields and attached evidence directly.
Technique documents include official ATT&CK descriptions and procedure
examples loaded from the pinned STIX bundle; runtime retrieval never scrapes MITRE pages.
FH Genie may select only one of those candidates and one of its official tactics, or return null
IDs with low confidence. The Mapping Agent validates candidate membership,
platform support, tactic membership, step identity, and evidence IDs. The accepted mapping is
presented directly in the attack chain; no separate grounding or semantic-validation LLM call
is made.
