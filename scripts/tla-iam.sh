#!/usr/bin/env bash
# Model-checks docs/formal/iamauth.tla, IAM authorize then read or write of a
# named entity (#373).
#
#   tla-iam.sh           the real design passes, every seeded bug fails its
#                        property, and each known finding still fails
#   tla-iam.sh model     only the real design (docs/formal/iamauth.cfg)
#
# Needs java (11 or later) and curl. The tla2tools.jar pin is the one in
# scripts/tla-detach.sh, read from there so the two never drift. The jar is
# TLA_TOOLS_JAR, or is downloaded once to TLA_CACHE (default ~/.cache/vws)
# and checked by sha256. Logs go to TLA_OUT (default a new temporary
# directory).
set -euo pipefail

die() { echo "tla-iam: $*" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
pin() { sed -n "s/^$1=//p" "${root}/scripts/tla-detach.sh"; }
TLA_VERSION=$(pin TLA_VERSION)
TLA_URL=$(pin TLA_URL)
TLA_SHA256=$(pin TLA_SHA256)
[[ $TLA_SHA256 =~ ^[0-9a-f]{64}$ && -n $TLA_URL ]] || die "no tla2tools pin in scripts/tla-detach.sh"

spec_dir=${root}/docs/formal
cfg=${spec_dir}/iamauth.cfg
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
    -metadir "${out}/${name}.states" -config "$config" iamauth.tla) >"$log" 2>&1 || true
  rm -rf "${out}/${name}.states"
  if grep -q '^Model checking completed. No error has been found.' "$log"; then
    echo pass
  elif grep -Eo '^Error: Invariant [A-Za-z]+ is violated' "$log" |
    sed -E 's/^Error: Invariant ([A-Za-z]+) .*/\1/' | head -1 | grep .; then
    :
  else
    echo broken
  fi
}

# variant NAME CONSTANT PROPERTY: iamauth.cfg with CONSTANT set to FALSE
# (NONE for none), checking only PROPERTY.
variant() {
  local name=$1 flip=$2 prop=$3 file=${out}/$1.cfg
  cp "$cfg" "$file"
  sed -i '/^INVARIANTS/,$d' "$file"
  if [[ $flip != NONE ]]; then
    sed -i "s/^\( *${flip} = \)TRUE$/\1FALSE/" "$file"
    grep -q "^ *${flip} = FALSE$" "$file" || die "${name}: ${flip} is not a TRUE constant in ${cfg}"
  fi
  printf 'INVARIANTS\n    %s\n' "$prop" >>"$file"
  echo "$file"
}

fail=0
got=$(tlc model "$cfg")
echo "model (real design): ${got}; $(grep -E '^[0-9]+ states generated' "${out}/model.log" || true)"
[[ $got == pass ]] || { fail=1; sed -n '/^Error:/,$p' "${out}/model.log" | head -80; }

if [[ ${1:-all} == all ]]; then
  # Each guard switched off must break the property it guards. A known
  # finding (docs/formal/iamauth.md) fails on the real design (NONE) until
  # its fix lands (#624, #625, #626); then its line fails here, and the property moves into
  # iamauth.cfg.
  while read -r name flip prop; do
    got=$(tlc "$name" "$(variant "$name" "$flip" "$prop")")
    what="${flip}=FALSE"
    [[ $flip == NONE ]] && what="real design"
    echo "${name} (${what}): ${got}, want ${prop}"
    [[ $got == "$prop" ]] || fail=1
  done <<'CHECKS'
seed-fail-open FixFailClosed DenyIsNeverSkipped
seed-bind FixBind ReadsBound
seed-page-etag FixPageEtag PagesBound
seed-write-etag FixWriteEtag WritesBound
seed-expect-arn FixExpectARN WritesBound
seed-undo-etag FixUndoEtag UndoCatchesMoves
finding-create-access-key NONE CreateAccessKeyBound
finding-update-role NONE UpdateRoleBound
finding-enable-restart NONE EnableNeverStaysUnverified
CHECKS
fi

echo "logs: ${out}"
exit "$fail"
