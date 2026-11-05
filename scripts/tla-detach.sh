#!/usr/bin/env bash
# Model-checks docs/formal/detach.tla, the DetachVolume recovery path (#343).
#
#   tla-detach.sh           the real design passes, every seeded bug fails its
#                           property, and each known finding still fails
#   tla-detach.sh model     only the real design (docs/formal/detach.cfg)
#
# Needs java (11 or later) and curl. tla2tools.jar is TLA_TOOLS_JAR, or is
# downloaded once to TLA_CACHE (default ~/.cache/vws) and checked by sha256.
# Logs go to TLA_OUT (default a new temporary directory).
set -euo pipefail

# Our own copy of the upstream tlaplus v1.8.0 prerelease jar (#563): the
# release tla2tools-v1.8.0-20261103 of this repo, whose notes give the upstream
# URL, the date fetched and the sha256. Upstream republishes prerelease assets
# (v1.8.0 was rebuilt on 2026-11-03), so an upstream URL is never pinned. This
# copy is never replaced; a new version gets a new tag. The newest stable
# release, v1.7.4, checks this spec about 15 times slower and misses the job
# timeout. .github/workflows/tla.yml reads TLA_SHA256 from this line as its
# cache key.
TLA_VERSION=1.8.0
TLA_URL=https://github.com/popododo0720/vws-console-api/releases/download/tla2tools-v1.8.0-20261103/tla2tools.jar
TLA_SHA256=e20447644bfabd29d6bd0fc2c0eb1473fb301c1a0e4dfe1961938ce5a191edbf

die() { echo "tla-detach: $*" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
spec_dir=${root}/docs/formal
cfg=${spec_dir}/detach.cfg
out=${TLA_OUT:-$(mktemp -d)}
mkdir -p "$out"

command -v java >/dev/null || die "java not found"
jar=${TLA_TOOLS_JAR:-${TLA_CACHE:-${HOME}/.cache/vws}/tla2tools-${TLA_SHA256}.jar}
if [[ ! -f $jar ]]; then
  mkdir -p "$(dirname "$jar")"
  curl -fsSL -o "${jar}.part" "$TLA_URL"
  mv "${jar}.part" "$jar"
fi
echo "${TLA_SHA256}  ${jar}" | sha256sum -c --quiet - || die "${jar} is not tla2tools ${TLA_VERSION}"

# tlc NAME CFG: runs TLC, keeps the log in $out/NAME.log, prints its verdict.
tlc() {
  local name=$1 config=$2 log=${out}/$1.log
  (cd "$spec_dir" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -noGenerateSpecTE \
    -metadir "${out}/${name}.states" -config "$config" detach.tla) >"$log" 2>&1 || true
  rm -rf "${out}/${name}.states"
  if grep -q '^Model checking completed. No error has been found.' "$log"; then
    echo pass
  elif grep -Eo '^Error: (Invariant|Temporal property) [A-Za-z]+ (is|was) violated' "$log" |
    sed -E 's/^Error: (Invariant|Temporal property) ([A-Za-z]+) .*/\2/' | head -1 | grep .; then
    :
  else
    echo broken
  fi
}

# variant NAME CONSTANT KIND PROPERTY: detach.cfg with CONSTANT set to FALSE
# (NONE for none), checking only PROPERTY (KIND is INVARIANTS or PROPERTIES).
variant() {
  local name=$1 flip=$2 kind=$3 prop=$4 file=${out}/$1.cfg
  # flip is one constant, a comma list of constants, or NONE.
  cp "$cfg" "$file"
  sed -i '/^INVARIANTS/,$d' "$file"
  local f
  for f in ${flip//,/ }; do
    [[ $f == NONE ]] && continue
    sed -i "s/^\( *${f} = \)TRUE$/\1FALSE/" "$file"
    grep -q "^ *${f} = FALSE$" "$file" || die "${name}: ${f} is not a TRUE constant in ${cfg}"
  done
  printf '%s\n    %s\n' "$kind" "$prop" >>"$file"
  echo "$file"
}

fail=0
got=$(tlc model "$cfg")
echo "model (real design): ${got}; $(grep -E '^[0-9]+ states generated' "${out}/model.log" || true)"
[[ $got == pass ]] || { fail=1; sed -n '/^Error:/,$p' "${out}/model.log" | head -80; }

if [[ ${1:-all} == all ]]; then
  # Each fix switched off must break the property it guards.
  while read -r name flip kind prop; do
    got=$(tlc "$name" "$(variant "$name" "$flip" "$kind" "$prop")")
    echo "seeded ${name} (${flip}=FALSE): ${got}, want ${prop}"
    [[ $got == "$prop" ]] || fail=1
  done <<'SEEDS'
seed-327-reserve FixPendingReserve INVARIANTS LabelBudget
seed-hold FixHold INVARIANTS HoldBlocksPrune
seed-etag-cas FixEtagCAS INVARIANTS NoLostUpdate
seed-op-binding FixOpBinding,FixArchive INVARIANTS ReplayReturnsFirst
seed-prune FixPruneExpiredOnly INVARIANTS PruneKeepsLive
seed-window WithinWindow INVARIANTS DetachOnce
seed-hold-expires FixPendingExpires PROPERTIES HoldEnds
seed-etag-reread FixEtagReread PROPERTIES CallsFinish
seed-archive FixArchive INVARIANTS ReplaySurvivesLaterDetach
seed-resend FixResendRecover INVARIANTS ResendMatchesOriginal
seed-persist-slot FixPersistOwnSlot INVARIANTS RetryKeepsItsParams
seed-hold-gives-way FixHoldGivesWay INVARIANTS HoldNeverRefuses
SEEDS
  # Known findings in the current code (docs/formal/README.md): none. A property
  # that fails on the real design is listed here until its fix lands.
fi

echo "logs: ${out}"
exit "$fail"
