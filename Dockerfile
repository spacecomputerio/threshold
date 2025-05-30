# syntax=docker/dockerfile:1

################################################################################

ARG RUST_VERSION=1.85

FROM rust:${RUST_VERSION}-slim-bullseye AS build

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \ 
    protobuf-compiler

# Leverage a cache mount to /usr/local/cargo/registry/
# for downloaded dependencies and a cache mount to /app/target/ for 
# compiled dependencies which will speed up subsequent builds.
# Leverage a bind mount to the src directory to avoid having to copy the
# source code into the container. Once built, copy the executable to an
# output directory before the cache mounted /app/target is unmounted.
RUN --mount=type=bind,source=tgrpc/src,target=tgrpc/src \
    --mount=type=bind,source=tgrpc/proto,target=tgrpc/proto \
    --mount=type=bind,source=tgrpc/build.rs,target=tgrpc/build.rs \
    --mount=type=bind,source=tgrpc/Cargo.toml,target=tgrpc/Cargo.toml \
    --mount=type=bind,source=cli/src,target=cli/src \
    --mount=type=bind,source=cli/Cargo.toml,target=cli/Cargo.toml \
    --mount=type=bind,source=threshold/src,target=threshold/src \
    --mount=type=bind,source=threshold/Cargo.toml,target=threshold/Cargo.toml \
    --mount=type=bind,source=threshold/Cargo.lock,target=threshold/Cargo.lock \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release --bin plugincore 
cp ./target/release/plugincore /bin/tgrpc
EOF

################################################################################

FROM debian:bullseye-slim AS final


COPY --from=build /bin/tgrpc /bin/tgrpc

ENTRYPOINT ["/bin/tgrpc"]