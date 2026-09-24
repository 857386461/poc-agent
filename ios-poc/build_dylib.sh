#!/bin/bash
# 编译 AgentInject.dylib（供 TrollFools 注入目标 App）
# 在 GitHub Actions macOS runner 上执行。脚本内部 cd 自身目录，
# 因为 workflow 是在仓库根执行的（老坑 #5）。
set -e
cd "$(dirname "$0")"

SRC=AgentInject.m
OUT=build/AgentInject.dylib

echo "=== [1/4] 源码行数 ==="
wc -l "$SRC"

rm -rf build && mkdir -p build

echo "=== [2/4] 编译 arm64 dynamiclib ==="
xcrun -sdk iphoneos clang \
  -arch arm64 \
  -dynamiclib \
  -miphoneos-version-min=15.0 \
  -fobjc-arc \
  -O0 \
  -framework UIKit \
  -framework Foundation \
  -framework CoreGraphics \
  -framework QuartzCore \
  -install_name @executable_path/AgentInject.dylib \
  -o "$OUT" \
  "$SRC"

echo "=== [3/4] ad-hoc 签名（TrollFools 后会重签，这里只是让结构合法） ==="
codesign -f -s - "$OUT" 2>&1 || echo "（签名失败可忽略，TrollFools 会重签）"

echo "=== [4/4] 产物 ==="
ls -la "$OUT"
file "$OUT"
echo "--- 依赖 ---"
otool -L "$OUT"

# 打成 zip，方便 Safari 下载后解压出 .dylib 再交给 TrollFools
( cd build && zip -qry AgentInject.zip AgentInject.dylib )
ls -la build/AgentInject.zip
echo "BUILD_OK"
