#!/bin/bash
# Linux 上交叉编译 AgentInject2.dylib（iOS arm64）——绕开 macOS runner 配额。
# 思路：LLVM clang 直接支持 -target arm64-apple-ios；链接用 lld 的 Mach-O 后端；
#       SDK 用开源的 iPhoneOS SDK 打包版；符号全部 dynamic_lookup，运行时由 iOS dyld 解析。
set -e
cd "$(dirname "$0")"

SRC=AgentInject2.m
OUT=build/AgentInject2.dylib
SDKURL="${SDKURL:-https://github.com/xybp888/iOS-SDKs/releases/download/iOS17.0-SDKs/iPhoneOS17.0.sdk.zip}"

echo "=== [1/5] 工具链 ==="
clang --version | head -2
ls -la /usr/bin/ld.lld* /usr/lib/llvm-*/bin/ld.lld 2>/dev/null | head
rm -rf build && mkdir -p build

echo "=== [2/5] 拉 iPhoneOS SDK ==="
curl -sL -o /tmp/iphoneos.zip "$SDKURL"
ls -la /tmp/iphoneos.zip
unzip -q /tmp/iphoneos.zip -d /tmp/sdks
SDK=$(find /tmp/sdks -maxdepth 3 -type d -name "iPhoneOS*.sdk" | head -1)
echo "SDK=$SDK"
ls "$SDK" | head
echo "--- UIKit framework ---"
ls "$SDK/System/Library/Frameworks/UIKit.framework" | head
echo "--- 找 UIUtilities ---"
find "$SDK" -maxdepth 4 -name "UIUtilities.framework" -o -maxdepth 4 -name "UIDefines.h" | head -5
echo "--- usr/lib tbd 样例 ---"
ls "$SDK/usr/lib" | head -5

echo "=== [3/5] 编译 arm64 dynamiclib ==="
CLANG=${CLANG:-clang}
LDLLD=$(ls /usr/lib/llvm-*/bin/ld.lld /usr/bin/ld.lld 2>/dev/null | head -1)
echo "lld=$LDLLD"
$CLANG -target arm64-apple-ios15.0 -miphoneos-version-min=15.0 \
  -isysroot "$SDK" \
  -arch arm64 \
  -dynamiclib \
  -fobjc-arc \
  -O0 \
  -fuse-ld="$LDLLD" \
  -Wl,-undefined,dynamic_lookup \
  -Wl,-platform_version,ios,15.0,15.0 \
  -lobjc -lSystem \
  -framework UIKit \
  -framework Foundation \
  -framework CoreGraphics \
  -framework QuartzCore \
  -framework Vision \
  -framework CoreImage \
  -framework ImageIO \
  -install_name @executable_path/AgentInject2.dylib \
  -o "$OUT" \
  "$SRC" 2>&1 | tee /tmp/build.txt | grep -E "error|fatal" | head -40 || true
test -f "$OUT" || { echo "COMPILE_FAILED"; tail -40 /tmp/build.txt; exit 1; }

echo "=== [4/5] 产物检查 ==="
ls -la "$OUT"
file "$OUT" || true

echo "=== [5/5] 打包 ==="
( cd build && zip -qry AgentInject2.zip AgentInject2.dylib )
ls -la build/AgentInject2.zip
echo "BUILD_OK"
