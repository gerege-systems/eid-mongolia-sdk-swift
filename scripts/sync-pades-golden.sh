#!/usr/bin/env bash
# sync-pades-golden.sh — Go reference-ийн (gerege-systems/eid-mongolia-sdk-go) PAdES golden vector-уудыг
# Tests/GeregeEIDPadesTests/golden руу vendor хийнэ (native SDK бүр ижил fixture-ийг байт-ижил давтана).
#
#   scripts/sync-pades-golden.sh <ref>       # Go репогийн tag/commit-оос татаж бичнэ (жишээ: pades-golden-v2)
#   scripts/sync-pades-golden.sh --check     # vendored хуулбар golden/SOURCE-ийн ref-тэй таарч буйг шалгана (CI)
#
# Тестийн PKI-ийн хувийн түлхүүрийг (PRIVATE KEY блок, *.key*) ХАСНА — тест иргэний гарын үсгийг
# manifest-ийн `signature`-аас авна.
set -euo pipefail

GO_REPO=gerege-systems/eid-mongolia-sdk-go
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/Tests/GeregeEIDPadesTests/golden

fetch() { # $1 = ref → $2 = dir (golden copy, keys stripped)
  local ref=$1 out=$2 tmp
  tmp=$(mktemp -d)
  curl -fsSL "https://codeload.github.com/$GO_REPO/tar.gz/$ref" | tar -xz -C "$tmp" --strip-components=1
  cp -R "$tmp/pades/testdata/golden" "$out"
  # golden v4 (Go validate/): DSS-ийн цуцлалтын нотолгооны тохирол/шинэлэг байдал ба гүн давхарлалтын оролт —
  # native тест complete-ийн OCSP/CRL дүрэм ба PRECHECKS #2a-г эдгээрээр шалгана.
  if [ -d "$tmp/pades/testdata/validate/input" ]; then
    mkdir -p "$out/validate"
    cp "$tmp"/pades/testdata/validate/input/dss-*.pdf "$tmp"/pades/testdata/validate/input/deep-nesting*.pdf "$out/validate/"
  fi
  rm -rf "$tmp"
  # Гаралтын PDF (output/) ба desktop/ нь sha256-аар тулгагдана — репод хуулахгүй.
  rm -rf "$out/output" "$out/desktop"
  find "$out" -name '*.key*' -delete
  for f in "$out"/pki/*.pem; do
    [ -f "$f" ] || continue
    awk '/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/{skip=1} !skip{print} /-----END [A-Z0-9 ]*PRIVATE KEY-----/{skip=0}' "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
  done
}

if [ "${1:-}" = --check ]; then
  [ -f "$dest/SOURCE" ] || { echo "golden/SOURCE алга" >&2; exit 1; }
  ref=$(head -n1 "$dest/SOURCE")
  tmp=$(mktemp -d)
  fetch "$ref" "$tmp/golden"
  cp "$dest/SOURCE" "$tmp/golden/SOURCE"
  if diff -r "$tmp/golden" "$dest" >/dev/null; then echo "golden = $GO_REPO@$ref ✓"; rm -rf "$tmp"; exit 0; fi
  diff -rq "$tmp/golden" "$dest" || true
  rm -rf "$tmp"
  echo "vendored golden нь $ref-ээс зөрж байна — scripts/sync-pades-golden.sh $ref" >&2
  exit 1
fi

ref=${1:?ref (Go репогийн tag/commit)}
rm -rf "$dest"
mkdir -p "$(dirname "$dest")"
fetch "$ref" "$dest"
echo "$ref" > "$dest/SOURCE"
echo "✓ $dest ← $ref"
