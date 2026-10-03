ARG RUST_IMAGE
ARG RUNTIME_IMAGE
FROM ${RUST_IMAGE} AS build
ARG TARGETPLATFORM
ARG CACHE_NAMESPACE
ARG CARGO_BUILD_JOBS=4
RUN test -n "$CACHE_NAMESPACE"
RUN apt-get update && apt-get install -y --no-install-recommends libxml2-dev clang pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY source/ .
ENV RUSTC_WRAPPER="" CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# Only dependency acquisition sees the read credential. It is never persisted in Git config.
RUN --mount=type=cache,id=mdm-${CACHE_NAMESPACE}-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=mdm-${CACHE_NAMESPACE}-git-${TARGETPLATFORM},target=/usr/local/cargo/git,sharing=locked \
    --mount=type=secret,id=azure_header,required=true \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=http.https://dev.azure.com/shengming0923/rss/_git/rss.extraheader \
    GIT_CONFIG_VALUE_0="$(cat /run/secrets/azure_header)" \
    GIT_CONFIG_KEY_1=http.https://dev.azure.com/shengming0923/rss/_git/rss-identity.extraheader \
    GIT_CONFIG_VALUE_1="$(cat /run/secrets/azure_header)" \
    GIT_CONFIG_KEY_2=http.https://dev.azure.com/shengming0923/rss/_git/rss-audit.extraheader \
    GIT_CONFIG_VALUE_2="$(cat /run/secrets/azure_header)" \
    cargo fetch --locked
RUN --network=none --mount=type=cache,id=mdm-${CACHE_NAMESPACE}-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=mdm-${CACHE_NAMESPACE}-git-${TARGETPLATFORM},target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=mdm-${CACHE_NAMESPACE}-target-${TARGETPLATFORM}-rust196,target=/build/target,sharing=locked \
    rustc -vV && cargo build --offline --locked --release -p rss-mdm-app --bin rss-mdm && mkdir /out && cp /build/target/release/rss-mdm /out/rss-mdm
FROM ${RUNTIME_IMAGE} AS server
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/rss-mdm /usr/local/bin/rss-mdm
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-mdm"]
