#!/usr/bin/env bash
# Prints every result file (already masked unless RAW=1 was used) for pasting back.
source "$(dirname "$0")/lib.sh"
for f in "$RESULTS"/00-env.txt "$RESULTS"/s1-baseline-cli.txt "$RESULTS"/s1-summary.txt "$RESULTS"/s1-*.json \
         "$RESULTS"/s1-*-finish.txt "$RESULTS"/s1b-summary.txt "$RESULTS"/s1b-bundle-signature.txt "$RESULTS"/s1b-*.json "$RESULTS"/s2-capture.jsonl "$RESULTS"/s3-notarize.txt; do
  [[ -f "$f" ]] || continue
  printf '\n######## %s\n' "${f#$SPIKE_DIR/}"; cat "$f"
done
