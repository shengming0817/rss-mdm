# RSS MDM Agent wire

`rss-mdm-agent-wire` owns the strict JSON contract between the RSS MDM service and its Rust
Agent. Version 1 contains Agent bootstrap registration, basic inventory snapshots/partial/failure
reports, durable acknowledgements and processing status. It contains no database, HTTP server,
product domain or RSS provider dependency.

The package is consumed from one exact Git revision. Candidate verification also packages the
crate and binds the archive SHA-256; neither proof is a registry publication.

V1 rejects unknown fields, enum values, capabilities and versions. A semantic extension requires
a new wire version and fixtures rather than an in-place fallback.
