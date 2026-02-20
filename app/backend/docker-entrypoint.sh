#!/bin/sh
# docker-entrypoint.sh — Read Docker Swarm secrets and export as env vars.
# Secrets are mounted at /run/secrets/<name> by docker stack deploy.
# This script runs before uvicorn so pydantic-settings picks up the values.

set -e

# ── SECRET_KEY ────────────────────────────────────────────────────────────────
if [ -f "${SECRET_KEY_FILE:-/run/secrets/mxtac_secret_key}" ]; then
    SECRET_KEY="$(cat "${SECRET_KEY_FILE:-/run/secrets/mxtac_secret_key}")"
    export SECRET_KEY
fi

# ── POSTGRES_PASSWORD (injected into DATABASE_URL) ───────────────────────────
if [ -f "${POSTGRES_PASSWORD_FILE:-/run/secrets/mxtac_postgres_password}" ]; then
    POSTGRES_PASSWORD="$(cat "${POSTGRES_PASSWORD_FILE:-/run/secrets/mxtac_postgres_password}")"
    # Replace the bare username@host URL with user:password@host URL.
    # DATABASE_URL is expected in the form: postgresql+asyncpg://mxtac@db:5432/mxtac
    if [ -n "${DATABASE_URL}" ]; then
        DATABASE_URL="$(echo "${DATABASE_URL}" | sed "s|://mxtac@|://mxtac:${POSTGRES_PASSWORD}@|")"
        export DATABASE_URL
    fi
fi

exec "$@"
