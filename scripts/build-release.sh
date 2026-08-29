#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
OUTDIR="${OUTDIR:-dist}"

TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

LDFLAGS="-s -w -buildid= -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT}"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

for target in "${TARGETS[@]}"; do
  os="${target%%/*}"
  arch="${target##*/}"
  name="export-tool-${VERSION}-${os}-${arch}"
  [ "$os" = "windows" ] && name="${name}.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$OUTDIR/$name" .
  echo "built $name"
done

cd "$OUTDIR"
find . -type f -name 'export-tool-*' -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS
sed -i.bak 's|\./||' SHA256SUMS && rm -f SHA256SUMS.bak
cat SHA256SUMS
