# CaseWeave Integration

> **Developer preview:** CaseWeave is pending its own public release. TraceQuarry
> currently emits this bundle for contract validation; the end-to-end importer
> and collaborative workflow are not yet a supported public-beta feature.

TraceQuarry emits a versioned CaseWeave producer-preview bundle for every parsed
collection. The bundle is a future integration handoff, not an analyst decision log:
CaseWeave remains authoritative for case lifecycle, timeline promotion, finding
confirmation, responder identity, assignments, comments, and reportability.

## Contract

- Bundle schema: `caseweave.tracequarry-import-bundle` version `1.0.0`
- Event baseline: `tracequarry.normalized-event` version `1.2`
- File: `caseweave_import_bundle.zip`
- Multi-collection index: `caseweave_exports.json`
- Custody registry: `caseweave_custody.json`, persisted in the case workspace
- Evidence bytes: external by default; the complete evidence inventory is
  included with SHA-256 hashes and parser coverage states
- Directory inputs: materialized as a deterministic sibling
  `caseweave_source_package.tar` so the declared package SHA-256 resolves to a
  real immutable byte object

Each ZIP contains:

```text
manifest.json
events.jsonl
timeline-candidates.jsonl
finding-candidates.jsonl
omissions.jsonl
```

The manifest records the producer, case intent, collection identity, acquisition
time provenance, host, complete evidence inventory, dataset hashes, record
counts, package fingerprint, and stable bundle identity. An unknown acquisition
time remains null with `unknown` confidence; TraceQuarry never substitutes bundle
creation time. Events include the original raw record or an exact line/record
source locator. Events without a defensible time basis or source record are not
exported as evidence.

Every omission is recorded in the hashed `omissions.jsonl` accounting dataset
with its producer record ID, parser, source path, and reason. Finding candidates
without an exported supporting event are omitted through the same mechanism.
This makes filtering reconcilable without inventing source evidence.

Timeline and finding records are explicitly **producer candidates**. TraceQuarry
does not populate CaseWeave analyst IDs, confirmations, reportability, finding
status, or actor attribution. Actor-related output remains capped profile
similarity with limitations attached.

## Usage

Supply the immutable reference of the destination CaseWeave case:

```bash
tracequarry /cases/host01.tar.gz --out out/host01 \
  --case-reference IR-2026-0711 \
  --year 2026 --timezone UTC
```

For a multi-collection workspace, all per-collection bundles use the same case
reference:

```bash
tracequarry --case-out out/IR-2026-0711 \
  --case-name "Linux intrusion" \
  --case-reference IR-2026-0711 \
  --input /cases/host01.tar.gz \
  --input /cases/host02.tar.gz
```

When `--case-reference` or the GUI **Case reference** field is blank,
TraceQuarry derives a stable `TQ-...` reference from sorted collection
fingerprints. A collection receives a custody UUID that is persisted in
`caseweave_custody.json`; retries, input renames, and case input reordering reuse
that identity. Byte-identical acquisitions therefore retain distinct collection
and event IDs while sharing a package ID for content deduplication. Paths in
`caseweave_exports.json` are relative to the case workspace.
CaseWeave should import each ZIP
through the same validate/plan/commit service used by its future HTTP endpoint.
Repeated imports are safe when CaseWeave applies the bundle, package, collection,
event, timeline-candidate, and finding-candidate idempotency keys carried by the
contract.

## Trust Boundary

Before promotion, responders should validate pivotal candidates against the raw
record and the inventoried evidence member. A source locator is emitted only
when its member SHA-256 matches the event source hash. Derived records that span
multiple evidence members retain raw producer context and do not claim an exact
single-file locator. External evidence members resolve through a versioned
`external_ref` containing the source package identity, package SHA-256, and
member path; the original package must remain available to CaseWeave or the
responder for verification. When an archive contains one wrapper directory,
TraceQuarry preserves that prefix in `member_path` so source navigation resolves
inside the original archive. Non-regular members are never followed or
materialized; they remain explicit unsupported inventory members with typed,
hashed metadata so package accounting stays complete.
