#!/usr/bin/env bash
# 插件在一次性 Go 容器里炼成 Linux c-shared 库；
# 部署主机只管备好 Docker，不必把整间炼丹房搬回家。
#
# Usage: scripts/build.sh [output-dir]
#        GOARCH=arm64 scripts/build.sh   # cross-compile for arm64
#
# .so 与 CPA 的架构必须对号入座，arm64 与 amd64 不可互借椅子。
# 默认跟宿主架构走；GOARCH=amd64|arm64 可借容器里的 Debian 交叉 gcc
# 编出另一种架构。不用请 qemu 来当翻译：容器镜像始终跟宿主同架构，
# 只有工具链替目标架构干活。
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

# --user 让 go.sum 和产出的 .so 认调用者为主人，不跟 root 改姓；
# 同一棵源码树还要提交、部署，产权别在厨房里弄丢。
DOCKER_USER=(--user "$(id -u):$(id -g)")
INNER='go mod tidy && go build -buildmode=c-shared -o /out/codex-turn-state-cloud-mint.so .'

if [ "$GOARCH" != "$host_arch" ]; then
	# GOARCH 换架构不是换帽子：CGO 的 c-shared 链接真要目标 C 工具链。
	# 一次性容器从 Debian 的 gcc-*-linux-gnu 包请来这位师傅；
	# apt 需要 root，就暂撤 --user，完工后把产物与缓存的产权还给调用者。
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
	# 交叉构建为 apt 借过 root 的印章；现在把构建碰过的文件还给调用者，
	# 别让提交源码变成向管理员讨房契。
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
