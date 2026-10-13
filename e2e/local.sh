#!/usr/bin/env bash
# Starts the grpc stack (e2e/stack.sh) plus vws-console-api and keeps it running for manual
# testing. Ctrl-C stops everything. Same env vars as stack.sh. Logs are in $stack.
set -euo pipefail
cd "$(dirname "$0")/.."
source e2e/stack.sh
go build -o "$stack/vws-console-api" ./cmd/vws-console-api
trap 'kill $(jobs -p)' EXIT
sleep 1
"$stack/vws-console-api" -backend grpc -console-token dev-token -access-key AKIDEXAMPLE -secret secret >"$stack/api.log" 2>&1 &
echo "stack up, work dir $stack"
wait
