# Multi-stage build: musl static binary -> distroless-static, plus a plain
# binary export. See docs/ARCHITECTURE.md "Deployment". One binary;
# check/bench/rewrap/rebind are subcommands, not sibling binaries — every
# stage of this build produces the single `s3armor` binary.
#
# The `release` stage is deliberately last: `docker build .` with no
# --target runs only a stage's ancestry (BuildKit does not build sibling
# stages), so plain `docker build .` still produces the stripped release
# image, never `debug` or `binary`. Build the profiling image explicitly:
#   docker build --target debug -t s3armor:debug .
# Export the static binary alone, with no image around it, into dist/:
#   docker buildx build --target binary --output type=local,dest=dist/ .

FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p s3armor

# `profiling` (docs/ARCHITECTURE.md "Profiling support") + `pprof` feature: real stacks for
# `perf`/flamegraphs, plus the metrics listener's `/debug/pprof/flamegraph`
# endpoint. Never in `release`. `force-frame-pointers` is a rustc codegen
# flag, not a Cargo profile key (see Cargo.toml's `[profile.profiling]`
# comment) — set here via RUSTFLAGS instead.
FROM builder AS builder-debug
ENV RUSTFLAGS="-C force-frame-pointers=yes"
RUN cargo build --profile profiling --locked -p s3armor --features pprof

# `debug-nonroot` bundles a busybox shell (`/busybox/sh`) — the point of a
# `-debug` image is to be able to get in and look around, which distroless
# `nonroot` deliberately does not allow.
FROM gcr.io/distroless/static-debian13:debug-nonroot AS debug
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.source="https://github.com/amsys/s3armor" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.title="s3armor" \
      org.opencontainers.image.description="Client-side S3 encryption proxy" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder-debug /build/target/profiling/s3armor /s3armor
EXPOSE 8080 9090
USER 65532:65532
ENTRYPOINT ["/s3armor"]
CMD ["serve"]
# Exec form, no shell — distroless has none. "Deployment"'s spec; docker-compose.yml
# already runs the same probe as its own healthcheck, this is the image
# carrying it itself so `docker run` outside that compose file still gets
# a health signal.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/s3armor", "health-probe"]

# Plain static binary, no image around it — the same artifact the LXC /
# systemd deployment and the .deb / .apk packages use (docs/ARCHITECTURE.md
# "Deployment"). `FROM scratch` so buildx has nothing to export but the
# file itself.
FROM scratch AS binary
COPY --from=builder /build/target/release/s3armor /s3armor

FROM gcr.io/distroless/static-debian13:nonroot AS release
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.source="https://github.com/amsys/s3armor" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.title="s3armor" \
      org.opencontainers.image.description="Client-side S3 encryption proxy" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /build/target/release/s3armor /s3armor
EXPOSE 8080 9090
USER 65532:65532
ENTRYPOINT ["/s3armor"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/s3armor", "health-probe"]
