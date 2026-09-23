# RSS MDM Agent wire

`rss-mdm-agent-wire` 2.0.0 owns the closed Agent registration, basic reports and enterprise task
contract. V1 is removed. The package has no database, HTTP server, product domain or RSS provider
dependency. It uses ring for Ed25519 verification; no signing authority is provided to the Agent.

`schema/agent-v2.schema-manifest.json` lists all twelve request/response schemas.
`SCHEMA_FINGERPRINT` binds their ordered bytes. Task signatures bind key ID, immutable executor
inputs, exact platform/architecture, artifact digest, tenant, device, registration, generation,
task, attempt, permit and expiry. Verification requires the trusted local context; deserializing
an offer is not execution authorization.

The immutable current-major baseline in `hack/agent_wire_compat.py` is checked independently of
the fingerprint. Missing history fails closed; JSON formatting/key order may change but structural
changes require a new major and explicit baseline. Candidate packaging and fixed-Git consumption
are manually verified by `hack/agent-wire-consumer.py`, not by CI and not as registry publication.

See [the product guide](../../docs/guides/202609230001-2468-enterprise-tasks.md) for task semantics
and [upgrade rules](../../docs/deployment/202609230002-2468-enterprise-task-upgrade.md).
