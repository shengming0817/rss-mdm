ARG RUST_IMAGE
ARG RUNTIME_IMAGE
ARG POSTGRES_IMAGE
FROM ${RUST_IMAGE} AS build
ARG TARGETPLATFORM
ARG CACHE_NAMESPACE
ARG CARGO_BUILD_JOBS=4
ARG PRODUCT=mdm
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
    case "$PRODUCT" in mdm) package=rss-mdm-app; binary=rss-mdm ;; da) package=rss-da-app; binary=rss-da ;; *) exit 2 ;; esac && rustc -vV && cargo build --offline --locked --release -p "$package" --bin "$binary" && mkdir /out && cp "/build/target/release/$binary" /out/server
FROM ${RUNTIME_IMAGE} AS server
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 && rm -rf /var/lib/apt/lists/*
RUN install -d -o 10001 -g 10001 -m 700 /var/lib/rss-mdm-temporary
COPY --from=build /out/server /usr/local/bin/rss-mdm
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-mdm"]

# One-shot initialization and maintenance; no container runtime client.
FROM ${POSTGRES_IMAGE} AS installer
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 python3 openssl && rm -rf /var/lib/apt/lists/*
RUN install -d -o 10001 -g 10001 -m 700 /var/lib/rss-mdm-temporary
COPY --from=build /out/server /usr/local/bin/rss-mdm-installer
COPY source/deployment/initialize.py source/deployment/render_gateway.py /usr/local/lib/rss-mdm/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-mdm-installer"]

# DA is a concrete product process with direct TLS listeners and its own operator inputs.
FROM ${RUNTIME_IMAGE} AS da-server
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/server /usr/local/bin/rss-da
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-da"]
FROM ${POSTGRES_IMAGE} AS da-installer
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 python3 openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/server /usr/local/bin/rss-da-installer
COPY source/deployment/initialize_da.py /usr/local/lib/rss-da/initialize.py
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-da-installer"]
