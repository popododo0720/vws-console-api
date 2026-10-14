#!/usr/bin/env bash
# Runs the e2e suite. VWS_E2E_BACKEND=fake (default) starts this process with the
# in-memory backend. grpc starts the services with e2e/stack.sh when VWS_E2E_BIN
# is set, then this process. Without VWS_E2E_BIN it expects both already running.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${VWS_E2E_BACKEND:-fake}" = fake ]; then
  go build -o "${TMPDIR:-/tmp}/vws-console-api-e2e" ./cmd/vws-console-api
  "${TMPDIR:-/tmp}/vws-console-api-e2e" -backend fake -iam fake >/dev/null 2>&1 &
  pid=$!
  # A second process on the default -iam static checks that sign-in is off.
  "${TMPDIR:-/tmp}/vws-console-api-e2e" -backend fake -console-addr 127.0.0.1:8090 -ec2-addr 127.0.0.1:8091 \
    -s3-addr 127.0.0.1:8092 -iam-addr 127.0.0.1:8094 -ops-addr= >/dev/null 2>&1 &
  spid=$!
  export VWS_E2E_STATIC_CONSOLE=${VWS_E2E_STATIC_CONSOLE:-http://127.0.0.1:8090}
  trap 'kill $pid $spid' EXIT
  sleep 1
fi
if [ "${VWS_E2E_BACKEND:-fake}" = grpc ] && [ -n "${VWS_E2E_BIN:-}" ]; then
  source e2e/stack.sh
  go build -o "${TMPDIR:-/tmp}/vws-console-api-e2e" ./cmd/vws-console-api
  trap 'kill $(jobs -p)' EXIT
  sleep 1
  "${TMPDIR:-/tmp}/vws-console-api-e2e" -backend grpc -iam fake -console-token dev-token -access-key AKIDEXAMPLE -secret secret >"$stack/api.log" 2>&1 &
  sleep 2
fi
python3 e2e/e2e.py
