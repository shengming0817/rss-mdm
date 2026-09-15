# MDM backend PostgreSQL support

Product-internal storage execution for Policy, Resource and Software Release only.
Borrowed transactions retain the caller's owner, tenant and settlement. No runtime,
connection pool, business core, schema migration or generic repository is owned here.
The adapters own admission declarations, catalog baselines and change event identities.
