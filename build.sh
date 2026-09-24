#!/bin/bash
#
# PoCAgent 编译打包脚本
# 运行环境：macOS + Xcode Command Line Tools
# 产物：build/PoCAgent.ipa  —— 用 TrollStore 安装
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
APP_DIR="build/Payload/PoCAgent.app"
mkdir -p "${APP_DIR}"

echo "==> 编译 PoCAgent"
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

echo "==> 签名（ad-hoc + entitlements；TrollStore 安装时会重新签名但保留 entitlements）"
codesign -f -s - --entitlements ent.plist "${APP_DIR}"

echo "==> 校验 entitlements 是否写入"
codesign -d --entitlements - "${APP_DIR}" || true

echo "==> 打包 IPA"
cd build
zip -qry PoCAgent.ipa Payload
cd ..

echo ""
echo "==> 完成: $(pwd)/build/PoCAgent.ipa"
echo "==> 用 TrollStore 安装，建议开启 'Install as System App'"
echo "==> 装好后打开 App 点『开始验证』，或用快捷指令打开 pocagent://run"
