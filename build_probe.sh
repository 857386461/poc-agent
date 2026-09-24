#!/bin/bash
#
# TouchProbe 编译打包脚本
# 运行环境：macOS + Xcode Command Line Tools（GitHub Actions）
# 产物：build/TouchProbe-C.ipa —— 复用 PoCAgent 已验证的 ent_c.plist 权限组合
#
set -euo pipefail
set -x

# 切换到脚本所在目录（workflow 可能从仓库根目录调用）
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

APP_DIR="build/Payload/TouchProbe.app"
mkdir -p "${APP_DIR}"

echo "==> 编译 TouchProbe"
"${CC}" \
    -arch arm64 \
    -isysroot "${SDK_PATH}" \
    -miphoneos-version-min="${MIN_OS}" \
    -fobjc-arc \
    -O0 \
    -framework UIKit \
    -framework Foundation \
    -framework CoreGraphics \
    -o "${APP_DIR}/TouchProbe" \
    TouchProbe.m

echo "==> 拷贝 Info.plist"
cp Info_probe.plist "${APP_DIR}/Info.plist"

echo "==> 签名（entitlements: ent_c.plist，与 PoCAgent C 版一致）"
codesign -f -s - --entitlements ent_c.plist "${APP_DIR}"

echo "==> 打包 TouchProbe-C.ipa（保留 Payload/ 前缀）"
( cd build && zip -qry "TouchProbe-C.ipa" Payload )

echo "==> 校验产物"
unzip -l build/TouchProbe-C.ipa
codesign -d --entitlements :- "${APP_DIR}" 2>/dev/null || codesign -d --entitlements - "${APP_DIR}"

ls -l build/*.ipa
echo "==> 完成: build/TouchProbe-C.ipa"
echo "    安装：TrollStore → 勾选 Install as System App"
