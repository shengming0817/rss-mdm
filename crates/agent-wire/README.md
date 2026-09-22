# RSS MDM Agent wire

`rss-mdm-agent-wire` owns the strict JSON contract between the RSS MDM service and its Rust
Agent. Version 1 contains Agent bootstrap registration, basic inventory snapshots/partial/failure
reports, durable acknowledgements and processing status. It contains no database, HTTP server,
product domain or RSS provider dependency.

The package is consumed from one exact Git revision. Candidate verification also packages the
crate and binds the archive SHA-256; neither proof is a registry publication.

V1 rejects unknown fields, enum values, capabilities and versions. A semantic extension requires
a new wire version and fixtures rather than an in-place fallback.

`schema/agent-v1.schema-manifest.json` is the complete versioned surface: registration request and
receipt, report request/ack/status, and the closed error body. `SCHEMA_FINGERPRINT` binds those
ordered schema bytes, and source/candidate consumers deserialize representative server outputs in
addition to constructing requests.

Local `make ci` runs `hack/agent_wire_compat.py` against the immutable Git candidate
`0637e0c4024673d79aaa6562018c96e667e694e3` from PR #1082. This is the reviewed V1
baseline, not a claim of registry publication. The commit must be available locally;
a shallow checkout must fetch it before CI (missing history fails closed).

The gate compares all six JSON schemas and the manifest structurally with that commit,
independently of `SCHEMA_FINGERPRINT`. Formatting and object key order may change.
Because V1 is closed, all structural changes are conservatively rejected, including
request narrowing, response expansion, enum/required-field changes and nested constraints.
Even a semantically equivalent schema rewrite needs review; this gate does not attempt
general JSON Schema implication. Updating the fingerprint alone never waives the gate.
A semantic change requires a new wire major, versioned schemas/fixtures and an explicit
new baseline in the gate; do not repoint the frozen V1 baseline to a mutable branch.
