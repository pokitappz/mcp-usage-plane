#!/usr/bin/env bash
#
# Work the access request queue on a running control plane.
#
# Somebody fills in the form on the landing page; this is the other end of it.
# Granting creates the account and the person, and that person can then sign in
# at /signin with an emailed code. No credentials are minted: the owner mints
# what they need from their own dashboard.
#
#   PLANE_URL=https://usagekit.cloud \
#   PLANE_PROVISION_SECRET=... \
#     scripts/access-queue.sh list
#
#   scripts/access-queue.sh grant 12 [--name "Northwind Tools"]
#   scripts/access-queue.sh decline 13
#
# `list` shows pending requests by default; pass --state granted, declined or
# all to see the rest. A request that shows an `existing_account` belongs to
# somebody who already has one, and granting it will be refused.

set -euo pipefail

action="${1:-list}"
shift || true

id=""
name=""
state="pending"

case "$action" in
  grant|decline)
    id="${1:-}"; shift || true
    [[ "$id" =~ ^[0-9]+$ ]] || { echo "$action needs a request id, e.g. $action 12" >&2; exit 2; }
    ;;
  list) ;;
  -h|--help) sed -n '2,20p' "$0" | sed -e 's/^# //' -e 's/^#$//'; exit 0 ;;
  *) echo "unknown action: $action (expected list, grant or decline)" >&2; exit 2 ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)    name="${2:-}"; shift 2 ;;
    --state)   state="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed -e 's/^# //' -e 's/^#$//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

: "${PLANE_URL:?PLANE_URL is required, e.g. https://usagekit.cloud}"
: "${PLANE_PROVISION_SECRET:?PLANE_PROVISION_SECRET is required; it is the value the plane was deployed with}"

plane="${PLANE_URL%/}"

# The secret travels in a header on every call below. Over plaintext that is a
# shared secret in the clear, which would hand somebody the ability to create
# accounts.
case "$plane" in
  https://*) ;;
  http://127.0.0.1*|http://localhost*)
    echo "warning: plaintext plane URL; acceptable only for a local plane" >&2 ;;
  *)
    echo "refusing a plaintext PLANE_URL: the operator secret would go over the wire in clear" >&2
    exit 1 ;;
esac

# The reason for a refusal is in the response body, not in curl's exit code:
# "already granted", "already declined", or an address that already has an
# account are all 409, and an operator needs to know which. So the status is
# read from `-w` and the body is kept either way, rather than letting `--fail`
# discard it. No `-f`: combining it with `-w` is how you end up printing a
# status of `000`.
call() {
  local method="$1" path="$2"
  shift 2

  local response status body
  if ! response="$(curl -sS --max-time 20 -w $'\n%{http_code}' -X "$method" "$plane$path" \
                     -H "x-provision-secret: $PLANE_PROVISION_SECRET" "$@")"; then
    echo "could not reach $plane" >&2
    return 1
  fi

  status="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if [[ "$status" != 2?? ]]; then
    printf '%s %s failed with HTTP %s\n' "$method" "$path" "$status" >&2
    printf '  %s\n' "$(jq -r '.error // "no reason given"' <<<"$body" 2>/dev/null || echo "$body")" >&2
    return 1
  fi

  printf '%s' "$body"
}

case "$action" in
  list)
    call GET "/v1/access-requests?state=$state" \
      | jq -r '
          if length == 0 then "no \($ARGS.named.state) requests" else
          (["ID","WHEN","EMAIL","COMPANY","EVENTS/MO","EXISTING"] | @tsv),
          (.[] | [
             .id,
             (.created_at | split("T")[0]),
             .email,
             (.company // "-"),
             (if .expected_events == null then "-" else (.expected_events | tostring) end),
             (.granted_account // .existing_account // "-")
           ] | @tsv)
          end' --args state "$state" \
      | column -t -s "$(printf '\t')"
    ;;

  grant)
    body='{}'
    [[ -n "$name" ]] && body="$(jq -nc --arg n "$name" '{name: $n}')"
    result="$(call POST "/v1/access-requests/$id/grant" \
                -H 'content-type: application/json' -d "$body")"
    echo "$result" | jq -r '
      "granted request \(.id)",
      "  account  \(.account_id)  (\(.name))",
      "  owner    \(.email)",
      if .notified then "  emailed  yes"
      else "  emailed  NO - tell them by hand; the account exists either way" end'
    printf '\nThey sign in at %s/signin with that address.\n' "$plane"
    printf 'No tokens were minted; they create their own from the dashboard.\n'
    ;;

  decline)
    call POST "/v1/access-requests/$id/decline" >/dev/null
    echo "declined request $id"
    ;;
esac
