# syntax=docker/dockerfile:1.7
FROM rust:1.96-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY sqlx-postgres-only/ sqlx-postgres-only/
COPY src/ src/
# All three are build inputs rather than runtime assets: Askama compiles the
# templates in, `sqlx::migrate!` embeds the migrations, and the stylesheet is
# included with `include_bytes!`. Leaving any of them out fails the build, which
# is the right direction.
COPY templates/ templates/
COPY migrations/ migrations/
COPY static/ static/

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked \
 && mkdir -p /out \
 && cp target/release/mcp-usage-plane /out/mcp-usage-plane

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /out/mcp-usage-plane /usr/local/bin/mcp-usage-plane
# Nothing is copied beside the binary. The migrations, the templates and the
# stylesheet are all compiled into it, which is what lets the same artifact work
# whether it was built here, installed from crates.io, or dropped into a
# scratch image.
EXPOSE 8081

# The service binds loopback by default, which is right for a binary somebody
# installs and wrong inside a container: loopback here is inside the network
# namespace and unreachable from outside it, and publishing the port above is
# already the deliberate act of exposing this. The dashboard mints credentials,
# so whatever publishes that port should have authentication or a private network
# in front of it.
ENV PLANE_BIND=0.0.0.0

ENTRYPOINT ["/usr/local/bin/mcp-usage-plane"]
