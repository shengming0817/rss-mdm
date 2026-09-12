ARG RUST_IMAGE
ARG RUNTIME_IMAGE
FROM ${RUST_IMAGE} AS build
WORKDIR /build
COPY source/ .
ENV RUSTC_WRAPPER="" CARGO_BUILD_JOBS=4
# Only dependency acquisition sees the read credential. It is never persisted in Git config.
RUN --mount=type=cache,id=mdm-registry-arm64,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=mdm-git-arm64,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=secret,id=azure_header,required=true \
    GIT_CONFIG_COUNT=2 \
    GIT_CONFIG_KEY_0=http.https://dev.azure.com/shengming0923/rss/_git/rss.extraheader \
    GIT_CONFIG_VALUE_0="$(cat /run/secrets/azure_header)" \
    GIT_CONFIG_KEY_1=http.https://dev.azure.com/shengming0923/rss/_git/rss-identity.extraheader \
    GIT_CONFIG_VALUE_1="$(cat /run/secrets/azure_header)" \
    cargo fetch --locked
RUN --network=none --mount=type=cache,id=mdm-registry-arm64,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=mdm-git-arm64,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=mdm-target-arm64-rust196,target=/build/target,sharing=locked \
    cargo build --offline --locked --release -p rss-mdm-app --bin rss-mdm && mkdir /out && cp /build/target/release/rss-mdm /out/rss-mdm
RUN --network=none --mount=type=cache,id=mdm-registry-arm64,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=mdm-git-arm64,target=/usr/local/cargo/git,sharing=locked cargo metadata --offline --locked --format-version=1 > /metadata.json
RUN rustc -vV > /toolchain.txt
FROM ${RUNTIME_IMAGE} AS server
ARG MDM_REVISION
LABEL org.opencontainers.image.revision=${MDM_REVISION}
COPY --from=build /out/rss-mdm /usr/local/bin/rss-mdm
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rss-mdm"]
FROM scratch AS evidence
COPY --from=build /toolchain.txt /toolchain.txt
COPY --from=build /metadata.json /metadata.json
COPY --from=build /out/rss-mdm /rss-mdm
