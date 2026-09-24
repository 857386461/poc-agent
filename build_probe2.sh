#!/bin/bash
#
# AgentProbe（能力探针 v2）编译打包脚本
# 运行环境：macOS + Xcode Command Line Tools（GitHub Actions）
# 产物：build/AgentProbe-D.ipa
# 权限：ent_d.plist = ent_c 全量 + no-sandbox/platform-application 的配套项
#       + HID 事件投递/监听 + IOKit user-client 例外 + 启动 App 权限
#
set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"
echo "==> 工作目录: $(pwd)"

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
CC="$(xcrun --sdk iphoneos --find clang)"
MIN_OS="15.0"

echo "==> SDK: ${SDK_PATH}"
echo "==> CC : ${CC}"

if [ -z "${SDK_PATH}" ] || [ ! -d "${SDK_PATH}" ]; then
    echo "!! iphoneos SDK 路径无效" >&2
    exit 1
fi

rm -rf build
mkdir -p build

APP_DIR="build/Payload/AgentProbe.app"
mkdir -p "${APP_DIR}"

echo "==> 编译 AgentProbe"
"${CC}" \
    -arch arm64 \
    -isysroot "${SDK_PATH}" \
    -miphoneos-version-min="${MIN_OS}" \
    -fobjc-arc \
    -O0 \
    -framework UIKit \
    -framework Foundation \
    -framework CoreGraphics \
    -framework CoreFoundation \
    -framework ReplayKit \
    -framework CoreImage \
    -framework CoreMedia \
    -framework CoreVideo \
    -o "${APP_DIR}/AgentProbe" \
    AgentProbe.m

echo "==> 拷贝 Info.plist"
cp Info_probe2.plist "${APP_DIR}/Info.plist"

echo "==> 签名（entitlements: ent_d.plist）"
codesign -f -s - --entitlements ent_d.plist "${APP_DIR}"

echo "==> 打包 AgentProbe-D.ipa（保留 Payload/ 前缀）"
( cd build && zip -qry "AgentProbe-D.ipa" Payload )

echo "==> 校验产物"
unzip -l build/AgentProbe-D.ipa
codesign -d --entitlements :- "${APP_DIR}" 2>/dev/null || codesign -d --entitlements - "${APP_DIR}"

ls -l build/*.ipa
echo "==> 完成: build/AgentProbe-D.ipa"
