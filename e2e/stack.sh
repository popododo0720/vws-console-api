#!/usr/bin/env bash
# Sourced by run.sh. Starts the three services for VWS_E2E_BACKEND=grpc as jobs of the caller.
# vws-compute gets -storage; without it CreateInstance answers DEPENDENCY_MISSING.
#   VWS_E2E_BIN     directory holding vws-compute, vws-storage, vws-network (required)
#   VWS_E2E_IMAGES  image seed file for vws-compute (required)
#   VWS_E2E_WORK    state and log directory. Default is a new temp dir.
#   stack is set to the work dir.

bin=${VWS_E2E_BIN:?set VWS_E2E_BIN}
images=${VWS_E2E_IMAGES:?set VWS_E2E_IMAGES}
work=${VWS_E2E_WORK:-$(mktemp -d)}
mkdir -p "$work"
"$bin/vws-storage" -db "$work/storage.db" -listen 127.0.0.1:19002 >>"$work/storage.log" 2>&1 &
"$bin/vws-network" -db "$work/network.db" -listen 127.0.0.1:19003 -pool 10.99.0.0/24 >>"$work/network.log" 2>&1 &
"$bin/vws-compute" -listen 127.0.0.1:19001 -seed-images "$images" \
  -storage 127.0.0.1:19002 >>"$work/compute.log" 2>&1 &
stack=$work
