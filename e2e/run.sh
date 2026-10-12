#!/usr/bin/env bash
# Runs the e2e suite. VWS_E2E_BACKEND=fake (default) starts this process with the
# in-memory backend. grpc expects the services and this process already running.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${VWS_E2E_BACKEND:-fake}" = fake ]; then
  go build -o "${TMPDIR:-/tmp}/vws-console-api-e2e" ./cmd/vws-console-api
  "${TMPDIR:-/tmp}/vws-console-api-e2e" -backend fake >/dev/null 2>&1 &
  pid=$!
  trap 'kill $pid' EXIT
  sleep 1
fi
python3 e2e/e2e.py
