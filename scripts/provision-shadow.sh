#!/usr/bin/env bash
#
# Create an account on a running control plane and print the two secrets that
# turn on shadow export in a metered application.
#
# This is step 2 of the shadow migration. Step 1 is deploying the plane; this
# script checks that it is actually there rather than failing halfway through.
#
#   PLANE_URL=https://mcp-usage-plane.fly.dev \
#   PLANE_PROVISION_SECRET=... \
#     scripts/provision-shadow.sh --name aggors
#
# Optional:
#   --rate-bps 150          terms to set on the new account
#   --floor-micros 49000000
#   --stripe-customer cus_x link the account to a Stripe customer
#   --app aggors            emit `fly secrets set` for that app
#
# The tokens are printed once and are not recoverable afterwards, which is the
# same property `POST /v1/accounts` has. Capture them when you run this.

set -euo pipefail

name=""
rate_bps=""
floor_micros=""
stripe_customer=""
fly_app=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)            name="${2:-}"; shift 2 ;;
    --rate-bps)        rate_bps="${2:-}"; shift 2 ;;
    --floor-micros)    floor_micros="${2:-}"; shift 2 ;;
    --stripe-customer) stripe_customer="${2:-}"; shift 2 ;;
    --app)             fly_app="${2:-}"; shift 2 ;;
    -h|--help)         sed -n '2,20p' "$0" | sed -e 's/^# //' -e 's/^#$//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

: "${PLANE_URL:?PLANE_URL is required, e.g. https://mcp-usage-plane.fly.dev}"
: "${PLANE_PROVISION_SECRET:?PLANE_PROVISION_SECRET is required; it is the value PLANE_PROVISION_SECRET is set to on the plane}"
[[ -n "$name" ]] || { echo "--name is required" >&2; exit 2; }

plane="${PLANE_URL%/}"

case "$plane" in
  https://*) ;;
  http://127.0.0.1*|http://localhost*)
    echo "warning: plaintext plane URL; acceptable only for a local plane" >&2 ;;
  *)
    echo "refusing a plaintext PLANE_URL: the tokens below would go over the wire in clear" >&2
    exit 1 ;;
esac

# Fail here rather than halfway through. A plane that is deployed but cannot
# reach its database answers this with a 500, which is worth knowing before an
# account is created against it.
echo "checking the plane is reachable and healthy..."
health_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$plane/healthz" 2>/dev/null || true)"
health_status="${health_status:-000}"
if [[ "$health_status" != "200" ]]; then
  echo "the plane at $plane is not healthy (HTTP ${health_status})." >&2
  echo "if it has never been deployed, that is step 1:" >&2
  echo "  fly apps create mcp-usage-plane && fly deploy" >&2
  exit 1
fi

echo "creating an account named ${name}..."
created="$(
  curl -fsS -X POST "$plane/v1/accounts" \
    -H 'content-type: application/json' \
    -d "$(jq -nc --arg n "$name" --arg s "$PLANE_PROVISION_SECRET" \
            '{name: $n, provision_secret: $s}')"
)" || {
  echo "provisioning failed. Two usual causes:" >&2
  echo "  - PLANE_PROVISION_SECRET does not match the plane's, which answers 401" >&2
  echo "  - the plane has no PLANE_PROVISION_SECRET set at all, which answers 404" >&2
  exit 1
}

account_id="$(jq -r '.account_id' <<<"$created")"
admin_token="$(jq -r '.admin_token' <<<"$created")"
edge_token="$(jq -r '.edge_token' <<<"$created")"

[[ "$account_id" != "null" && -n "$account_id" ]] || {
  echo "the plane did not return an account; response was: $created" >&2
  exit 1
}

if [[ -n "$stripe_customer" ]]; then
  echo "linking the account to ${stripe_customer}..."
  curl -fsS -X PUT "$plane/v1/billing" \
    -H "authorization: Bearer $admin_token" \
    -H 'content-type: application/json' \
    -d "$(jq -nc --arg c "$stripe_customer" '{stripe_customer_id: $c}')" >/dev/null
fi

if [[ -n "$rate_bps" || -n "$floor_micros" ]]; then
  echo "setting terms (${rate_bps:-0} bps, floor ${floor_micros:-0} micros)..."
  curl -fsS -X PUT "$plane/v1/pricing" \
    -H "authorization: Bearer $admin_token" \
    -H 'content-type: application/json' \
    -d "$(jq -nc --argjson r "${rate_bps:-0}" --argjson f "${floor_micros:-0}" \
            '{rate_bps: $r, floor_micros: $f}')" >/dev/null
fi

cat <<REPORT

Account created.

  account_id   $account_id

These appear once. The plane stores only their digests and cannot show them
again; losing the admin token means editing the database by hand.

  admin_token  $admin_token
  edge_token   $edge_token

Shadow export is off in the metered application until BOTH of the following are
set. Nothing about what anyone is charged changes when they are: the mirror is
a copy, and it never fails a flush.

  USAGE_PLANE_URL=$plane
  USAGE_PLANE_EDGE_TOKEN=$edge_token
REPORT

if [[ -n "$fly_app" ]]; then
  cat <<REPORT

To apply them:

  fly secrets set --app $fly_app \\
    USAGE_PLANE_URL='$plane' \\
    USAGE_PLANE_EDGE_TOKEN='$edge_token'
REPORT
fi

cat <<'REPORT'

Then generate some traffic and compare the two ledgers:

  AGGORS_DATABASE_URL=... PLANE_DATABASE_URL=... scripts/reconcile-shadow.sh

REPORT
