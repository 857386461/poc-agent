#!/bin/bash
#
# PoCAgent 编译打包脚本（A/B 双变体）
# 运行环境：macOS + Xcode Command Line Tools
# 产物：
#   build/PoCAgent.ipa    —— ent.plist   （含 no-sandbox，需 Install as System App）
#   build/PoCAgent-B.ipa  —— ent_b.plist （无 no-sandbox，普通安装可启动）
#
set -euo pipefail
set -x

cd "$(dirname "$0")"

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

build_variant() {
    local ENT="$1"
    local SUFFIX="$2"
    local APP_DIR="build/Payload${SUFFIX}/PoCAgent.app"

    mkdir -p "${APP_DIR}"

    echo "==> 编译 PoCAgent${SUFFIX}"
    "${CC}" \
        -arch arm64 \
        -isysroot "${SDK_PATH}" \
        -miphoneos-version-min="${MIN_OS}" \
        -fobjc-arc \
        -O0 \
        -framework UIKit \
        -framework Foundation \
        -framework CoreGraphics \
        -o "${APP_DIR}/PoCAgent" \
        PoCAgent.m

    echo "==> 拷贝 Info.plist"
    cp Info.plist "${APP_DIR}/Info.plist"

    echo "==> 签名（entitlements: ${ENT}）"
    codesign -f -s - --entitlements "${ENT}" "${APP_DIR}"

    echo "==> 打包 PoCAgent${SUFFIX}.ipa"
    ( cd "build/Payload${SUFFIX}" && zip -qry "../PoCAgent${SUFFIX}.ipa" PoCAgent.app )
}

build_variant ent.plist ""
build_variant ent_b.plist "-B"

ls -l build/*.ipa
echo ""
echo "==> 完成:"
echo "    build/PoCAgent.ipa   (含 no-sandbox，TrollStore 勾 Install as System App)"
echo "    build/PoCAgent-B.ipa (无 no-sandbox，普通安装即可启动)"
echo "==> 装好打开 App 点『开始验证』，或用快捷指令打开 pocagent://run"
