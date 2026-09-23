#!/usr/bin/env bash
#
# Compare a metered application's own usage ledger against the control plane's.
#
# This is the point of shadow export. Both sides key on the aggregate
# `identifier`, so the comparison is exact rather than statistical: the same
# identifier must carry the same units on both sides.
#
#   AGGORS_DATABASE_URL=postgres://... \
#   PLANE_DATABASE_URL=postgres://... \
#     scripts/reconcile-shadow.sh
#
# Optional:
#   --since '2026-09-01'   only aggregates at or after this instant
#   --account acct_x       restrict the plane side to one account
#
# Three kinds of disagreement, and they mean different things:
#
#   missing from the plane   The mirror did not deliver. Check the application's
#                            logs for "usage-plane mirror has gaps" - a shadow
#                            drops rather than failing, by design, so this is
#                            expected after any period the plane was down and is
#                            NOT a metering disagreement.
#
#   missing from the source  Should not happen. The plane holds an aggregate the
#                            application does not, which means something other
#                            than this mirror wrote to that account.
#
#   unit mismatch            The interesting one. The same identifier metered to
#                            different numbers on the two sides. That is a real
#                            disagreement between the implementations and the
#                            reason this comparison exists.

set -euo pipefail

since=""
account=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)   since="${2:-}"; shift 2 ;;
    --account) account="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0" | sed -e 's/^# //' -e 's/^#$//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
: "${AGGORS_DATABASE_URL:?AGGORS_DATABASE_URL is required}"
: "${PLANE_DATABASE_URL:?PLANE_DATABASE_URL is required}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

source_filter="TRUE"
plane_filter="TRUE"
if [[ -n "$since" ]]; then
  source_filter="event_timestamp >= '${since}'::timestamptz"
  plane_filter="event_at >= '${since}'::timestamptz"
fi
if [[ -n "$account" ]]; then
  plane_filter="${plane_filter} AND account_id = '${account}'"
fi

# Tab separated, sorted by identifier, no headers, so `join` and `comm` work.
psql "$AGGORS_DATABASE_URL" -At -F $'\t' -c \
  "SELECT identifier, units FROM mcp_usage_events
   WHERE ${source_filter} ORDER BY identifier" > "$workdir/source.tsv"

psql "$PLANE_DATABASE_URL" -At -F $'\t' -c \
  "SELECT identifier, units FROM usage_events
   WHERE ${plane_filter} ORDER BY identifier" > "$workdir/plane.tsv"

cut -f1 "$workdir/source.tsv" > "$workdir/source.ids"
cut -f1 "$workdir/plane.tsv"  > "$workdir/plane.ids"

source_count=$(wc -l < "$workdir/source.tsv" | tr -d ' ')
plane_count=$(wc -l < "$workdir/plane.tsv" | tr -d ' ')
source_units=$(awk -F'\t' '{s+=$2} END {print s+0}' "$workdir/source.tsv")
plane_units=$(awk -F'\t' '{s+=$2} END {print s+0}' "$workdir/plane.tsv")

comm -23 "$workdir/source.ids" "$workdir/plane.ids" > "$workdir/missing_from_plane"
comm -13 "$workdir/source.ids" "$workdir/plane.ids" > "$workdir/missing_from_source"

# Same identifier on both sides, different units.
join -t $'\t' "$workdir/source.tsv" "$workdir/plane.tsv" \
  | awk -F'\t' '$2 != $3 {print $1"\tsource="$2"\tplane="$3}' > "$workdir/mismatched"

missing_plane=$(wc -l < "$workdir/missing_from_plane" | tr -d ' ')
missing_source=$(wc -l < "$workdir/missing_from_source" | tr -d ' ')
mismatched=$(wc -l < "$workdir/mismatched" | tr -d ' ')

printf '\n%-26s %10s %14s\n' '' 'aggregates' 'units'
printf '%-26s %10s %14s\n' 'application ledger' "$source_count" "$source_units"
printf '%-26s %10s %14s\n' 'control plane ledger' "$plane_count" "$plane_units"
printf '\n'
printf '%-26s %10s\n' 'missing from the plane' "$missing_plane"
printf '%-26s %10s\n' 'missing from the source' "$missing_source"
printf '%-26s %10s\n' 'unit mismatches' "$mismatched"
printf '\n'

show() {
  local file="$1" label="$2" limit=20
  [[ -s "$file" ]] || return 0
  echo "--- $label ---"
  head -n "$limit" "$file"
  local total
  total=$(wc -l < "$file" | tr -d ' ')
  (( total > limit )) && echo "... and $(( total - limit )) more"
  echo
}

show "$workdir/mismatched" "unit mismatches (a real metering disagreement)"
show "$workdir/missing_from_plane" "missing from the plane (delivery gap, or the mirror was off)"
show "$workdir/missing_from_source" "missing from the source (unexpected: who else wrote these?)"

if (( mismatched > 0 || missing_source > 0 )); then
  echo "RECONCILIATION FAILED: the two ledgers disagree about metering."
  exit 1
fi

if (( missing_plane > 0 )); then
  echo "Delivery gap only. Every aggregate the plane holds agrees with the source;"
  echo "$missing_plane never arrived. A shadow drops rather than failing, so this is"
  echo "expected if the plane was unreachable, or if the mirror was enabled after"
  echo "some usage had already been recorded. Use --since to exclude that window."
  exit 0
fi

echo "Ledgers agree exactly. The plane metered the same aggregates, to the same units."
