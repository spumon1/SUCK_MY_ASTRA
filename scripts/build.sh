#!/usr/bin/env bash
# Builds the plugin as a linux c-shared library inside a throwaway Go
# container, so the deploy host only needs Docker.
#
# Usage: scripts/build.sh [output-dir]
#        GOARCH=arm64 scripts/build.sh   # cross-compile for arm64
#
# The .so must match the CPA binary's architecture exactly -- an arm64 CPA
# cannot load an amd64 .so and vice versa. Default is the host's own arch;
# GOARCH=amd64|arm64 cross-compiles via the matching Debian cross gcc inside
# the container (no qemu needed: the container always runs the host arch's
# image, only the toolchain targets the other arch).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_IMAGE="${GO_IMAGE:-golang:1.26}"
CACHE_DIR="$REPO_DIR/.gocache"

case "$(uname -m)" in
	x86_64)        host_arch=amd64 ;;
	aarch64|arm64) host_arch=arm64 ;;
	*) echo "unsupported host arch: $(uname -m)" >&2; exit 2 ;;
esac

GOARCH="${GOARCH:-$host_arch}"
GOOS="${GOOS:-linux}"
if [ "$GOOS" != "linux" ]; then
	echo "only linux is supported (the c-shared plugin ABI is built for linux)" >&2
	exit 2
fi
case "$GOARCH" in
	amd64|arm64) ;;
	*) echo "unsupported GOARCH: $GOARCH (want amd64 or arm64)" >&2; exit 2 ;;
esac

OUT_DIR="${1:-$REPO_DIR/build/$GOOS/$GOARCH}"
mkdir -p "$OUT_DIR" "$CACHE_DIR/build" "$CACHE_DIR/mod"

# --user keeps go.sum and the built .so owned by the invoking user rather than
# root, which matters because the same tree is committed and deployed.
DOCKER_USER=(--user "$(id -u):$(id -g)")
INNER='go mod tidy && go build -buildmode=c-shared -o /out/codex-turn-state-cloud-mint.so .'

if [ "$GOARCH" != "$host_arch" ]; then
	# A different GOARCH is a real cross-compile: CGO's c-shared link needs the
	# target's C toolchain, installed into the throwaway container from Debian's
	# gcc-*-linux-gnu packages. apt needs root, so --user is dropped and the
	# output/cache trees are handed back to the invoking user afterwards.
	case "$GOARCH" in
		amd64) CROSS_PKG="gcc-x86-64-linux-gnu";  CROSS_CC="x86_64-linux-gnu-gcc" ;;
		arm64) CROSS_PKG="gcc-aarch64-linux-gnu"; CROSS_CC="aarch64-linux-gnu-gcc" ;;
	esac
	INNER="apt-get update -qq && apt-get install -y -qq $CROSS_PKG >/dev/null && export CC=$CROSS_CC && go mod tidy && go build -buildmode=c-shared -o /out/codex-turn-state-cloud-mint.so ."
	DOCKER_USER=()
fi

docker run --rm \
	"${DOCKER_USER[@]}" \
	-v "$REPO_DIR/go":/src \
	-v "$OUT_DIR":/out \
	-v "$CACHE_DIR":/gocache \
	-w /src \
	-e CGO_ENABLED=1 \
	-e GOOS="$GOOS" \
	-e GOARCH="$GOARCH" \
	-e GOCACHE=/gocache/build \
	-e GOMODCACHE=/gocache/mod \
	-e GOFLAGS=-buildvcs=false \
	"$GO_IMAGE" \
	sh -c "$INNER"

if [ ${#DOCKER_USER[@]} -eq 0 ]; then
	# Cross builds ran as root for apt; return ownership of everything the build
	# touched to the invoking user so the tree stays committable.
	docker run --rm \
		-v "$REPO_DIR/go":/src \
		-v "$OUT_DIR":/out \
		-v "$CACHE_DIR":/gocache \
		"$GO_IMAGE" \
		sh -c "chown -R $(id -u):$(id -g) /out /gocache /src"
fi

echo
echo "built: $OUT_DIR/codex-turn-state-cloud-mint.so  ($GOOS/$GOARCH)"
ls -la "$OUT_DIR"
