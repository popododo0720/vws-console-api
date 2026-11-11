#!/usr/bin/env bash
# Exercises the runner's process boundary without Java or a downloaded jar.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-$root}/tla-instance-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fails=0

for key in TLA_VERSION TLA_URL TLA_SHA256; do
  pin=$(sed -n "s/^${key}=//p" "$root/scripts/tla-detach.sh")
  [[ -n $pin && $(sed -n "s/^${key}=//p" "$root/scripts/tla-instance.sh") == "$pin" ]] ||
    { echo "FAIL: ${key} differs from the detach runner"; exit 1; }
done
mkdir -p "$tmp/scripts" "$tmp/docs/formal"
cp "$root/scripts/tla-instance.sh" "$tmp/scripts/"
cp "$root/docs/formal/instance."{tla,cfg} "$tmp/docs/formal/"
touch "$tmp/tools.jar"
sum=$(sha256sum "$tmp/tools.jar")
sed -i "s/^TLA_SHA256=.*/TLA_SHA256=${sum%% *}/" "$tmp/scripts/tla-instance.sh"

java() {
  local config= prev= arg prop rc
  for arg; do
    [[ $prev == -config ]] && config=$arg
    prev=$arg
  done
  if [[ $FAKE_TLC_MODE == missing-verdict ]]; then
    return 0
  fi
  if [[ $FAKE_TLC_MODE == error-only ]]; then
    echo 'Error: injected process failure'
    return 42
  fi
  if [[ ${config##*/} == instance.cfg ]]; then
    echo 'Model checking completed. No error has been found.'
    rc=0
    case $FAKE_TLC_MODE in
      model-exit) rc=42 ;;
      model-error) echo 'Error: injected post-check failure' ;;
    esac
  else
    prop=$(awk 'END {print $1}' "$config")
    [[ $FAKE_TLC_MODE == wrong-invariant ]] && prop=WrongInvariant
    printf 'Error: Invariant %s is violated.\n' "$prop"
    echo 'Error: The behavior up to this point is:'
    rc=12
    case $FAKE_TLC_MODE in
      seed-exit) rc=42 ;;
      seed-zero) rc=0 ;;
      seed-error) echo 'Error: injected post-check failure' ;;
    esac
  fi
  if [[ $FAKE_TLC_MODE == misleading-all ]]; then
    echo 'Error: injected post-check failure'
    rc=42
  fi
  return "$rc"
}
export -f java

run() {
  local mode=$1 want=$2 rc=0
  shift 2
  FAKE_TLC_MODE=$mode TLA_TOOLS_JAR="$tmp/tools.jar" TLA_OUT="$tmp/out" \
    bash "$tmp/scripts/tla-instance.sh" "$@" >"$tmp/result.log" 2>&1 || rc=$?
  if { [[ $want == pass && $rc -eq 0 ]] && grep -q '^model (real design): pass;' "$tmp/result.log" &&
       [[ $(grep -c '^seeded ' "$tmp/result.log") -eq 4 ]]; } ||
     { [[ $want == fail && $rc -eq 1 ]] && grep -q 'broken (exit ' "$tmp/result.log"; }; then
    echo "ok: ${mode} (${want})"
  else
    echo "FAIL: ${mode}: want ${want}, exit ${rc}"
    sed 's/^/    /' "$tmp/result.log"
    fails=$((fails + 1))
  fi
}

run healthy pass
run model-exit fail model
run model-error fail model
run seed-exit fail
run seed-zero fail
run seed-error fail
run wrong-invariant fail
run misleading-all fail
run missing-verdict fail model
run error-only fail model

[[ $fails -eq 0 ]] || { echo "tla-instance_test: ${fails} case(s) failed" >&2; exit 1; }
echo 'tla-instance_test: all cases passed'
