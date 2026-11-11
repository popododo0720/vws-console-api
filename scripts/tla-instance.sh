#!/usr/bin/env bash
# Checks the proposed lifecycle design and one counterexample per guard.
# Needs Java 11+; uses the same verified jar as the detach and IAM models.
# TLA_OUT keeps logs/configs; "model" runs only the real design.
set -euo pipefail

die() { echo "tla-instance: $*" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
TLA_VERSION=1.8.0
TLA_URL=https://github.com/popododo0720/vws-console-api/releases/download/tla2tools-v1.8.0-20261103/tla2tools.jar
TLA_SHA256=e20447644bfabd29d6bd0fc2c0eb1473fb301c1a0e4dfe1961938ce5a191edbf

command -v java >/dev/null || die "java not found"
jar=${TLA_TOOLS_JAR:-${TLA_CACHE:-${HOME}/.cache/vws}/tla2tools-${TLA_SHA256}.jar}
if [[ ! -f $jar ]]; then
  mkdir -p "$(dirname "$jar")"
  curl -fsSL -o "${jar}.part" "$TLA_URL"
  mv "${jar}.part" "$jar"
fi
echo "${TLA_SHA256}  ${jar}" | sha256sum -c --quiet - || die "${jar} is not tla2tools ${TLA_VERSION}"

spec_dir=${root}/docs/formal
cfg=${spec_dir}/instance.cfg
out=${TLA_OUT:-$(mktemp -d)}
mkdir -p "$out"

tlc() {
  local name=$1 config=$2 expected=$3 log=${out}/$1.log rc=0 errors violation
  (cd "$spec_dir" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -noGenerateSpecTE \
    -metadir "${out}/${name}.states" -config "$config" instance.tla) >"$log" 2>&1 || rc=$?
  rm -rf "${out}/${name}.states"
  errors=$(grep 'Error:' "$log" || true)
  if [[ $expected == pass && $rc -eq 0 && -z $errors ]] &&
    grep -Fxq 'Model checking completed. No error has been found.' "$log"; then
    echo pass
  # EC.ExitStatus.VIOLATION_SAFETY in the pinned jar is 12. TLC prefixes
  # its counterexample trace with a second Error line; it is not a new error.
  elif [[ $expected != pass && $rc -eq 12 ]]; then
    violation="Error: Invariant ${expected} is violated."
    if [[ $errors == "$violation" || $errors == "$violation"$'\nError: The behavior up to this point is:' ]]; then
      echo "$expected"
    else
      echo "broken (exit ${rc})"
    fi
  else
    echo "broken (exit ${rc})"
  fi
}

variant() {
  local name=$1 flip=$2 prop=$3 file=${out}/$1.cfg
  cp "$cfg" "$file"
  sed -i '/^INVARIANTS/,$d' "$file"
  sed -i "s/^\( *${flip} = \)TRUE$/\1FALSE/" "$file"
  grep -q "^ *${flip} = FALSE$" "$file" || die "${flip} is not a TRUE constant in ${cfg}"
  printf 'INVARIANTS\n    %s\n' "$prop" >>"$file"
  echo "$file"
}

fail=0
got=$(tlc model "$cfg" pass)
echo "model (real design): ${got}; $(grep -E '^[0-9]+ states generated' "${out}/model.log" || true)"
[[ $got == pass ]] || { fail=1; sed -n '/^Error:/,$p' "${out}/model.log" | head -80; }

if [[ ${1:-all} == all ]]; then
  while read -r name flip prop; do
    got=$(tlc "$name" "$(variant "$name" "$flip" "$prop")" "$prop")
    echo "seeded ${name} (${flip}=FALSE): ${got}, want ${prop}"
    [[ $got == "$prop" ]] || fail=1
  done <<'SEEDS'
seed-replay FixReplay OneVMPerClientToken
seed-start FixStart AllowedEdges
seed-destroy FixDestroy NoOrphanAfterTerminate
seed-fence FixFence MutationsFenced
SEEDS
fi

echo "logs: ${out}"
exit "$fail"
