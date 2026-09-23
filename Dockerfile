# syntax=docker/dockerfile:1.7
FROM rust:1.96-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY sqlx-postgres-only/ sqlx-postgres-only/
COPY src/ src/
# Askama compiles templates into the binary, so these are a build input rather
# than a runtime asset. Leaving them out fails the build, which is the right
# direction: the alternative would be a binary that cannot render a page.
COPY templates/ templates/

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked \
 && mkdir -p /out \
 && cp target/release/mcp-usage-plane /out/mcp-usage-plane

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /out/mcp-usage-plane /usr/local/bin/mcp-usage-plane
# Migrations are read from disk at startup, so they ship with the binary.
COPY migrations/ /app/migrations/
# The stylesheet is served from disk, unlike the templates. `ASSETS_DIR` is set
# explicitly rather than relying on the working directory, because `ServeDir`
# resolves a relative path against wherever the process happens to be started
# and a silently unstyled page is a bad way to discover that.
COPY static/ /app/static/

ENV MIGRATIONS_DIR=/app/migrations \
    ASSETS_DIR=/app/static/assets
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/mcp-usage-plane"]
