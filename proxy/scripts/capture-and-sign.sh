#!/usr/bin/env bash
# Pulls the init segment and the latest N media segments of one representation from a running
# livesim2, signs them with c2patool's Verifiable Segment Info (VSI) method, then validates them.
#
# usage: scripts/capture-and-sign.sh [N] [REPRESENTATION]
# env:   LIVESIM2 (default http://localhost:8888/livesim2/testpic_2s)
#        C2PATOOL (default: c2patool on PATH, built with the unstable_live_video feature)
set -euo pipefail

N=${1:-5}
REP=${2:-V300}
LIVESIM2=${LIVESIM2:-http://localhost:8888/livesim2/testpic_2s}
C2PATOOL=${C2PATOOL:-c2patool}
SEG_DUR=2

root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/work/$REP"
rm -rf "$work"
mkdir -p "$work/raw" "$work/signed"

# livesim2 numbers segments from the Unix epoch: segment k covers [k*2s, (k+1)*2s).
# The newest complete one is floor(now/2) - 1.
last=$(( $(date +%s) / SEG_DUR - 1 ))
first=$(( last - N + 1 ))

curl -sfS -o "$work/raw/init.mp4" "$LIVESIM2/$REP/init.mp4"
for ((k = first; k <= last; k++)); do
  curl -sfS -o "$work/raw/seg_$k.m4s" "$LIVESIM2/$REP/$k.m4s"
done
echo "fetched init + segments $first..$last of $REP"

# live-video-sign doesn't resolve key paths relative to the manifest, so make them absolute.
sed -e "s#\"es256_private.key\"#\"$root/config/es256_private.key\"#" \
    -e "s#\"es256_certs.pem\"#\"$root/config/es256_certs.pem\"#" \
    "$root/config/live-manifest.json" > "$work/manifest.json"

"$C2PATOOL" "$work/raw" live-video-sign \
  --segments_glob 'seg_*.m4s' \
  -o "$work/signed" \
  -m "$work/manifest.json" \
  --method vsi \
  --session-key "$root/config/session.key" \
  --init init.mp4

"$C2PATOOL" "$work/signed/init.mp4" live-video --segments_glob 'seg_*.m4s' > "$work/report.json"
echo "report: $work/report.json"
