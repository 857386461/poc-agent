#!/bin/bash
# 编译 HLProbe.dylib（老贝贝底座运行时探针，供 TrollFools 注入任意 App）
#
# 除了出产物，本脚本还顺带回答规格书 §2.2 悬着的问题：
#   iOS SDK 里到底有没有 IOKit 头 / 能不能 -framework IOKit / 手写 extern 能否通过。
# 这三条结论会打进构建日志，用来更新规格书。
set -e
cd "$(dirname "$0")"

echo "=== [0/5] iOS SDK 诊断（规格书 §2.2） ==="
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
echo "SDK: $SDK"
echo "--- Frameworks 里的 IOKit ---"
ls "$SDK/System/Library/Frameworks" 2>/dev/null | grep -i iokit || echo "  [结论] SDK 里没有 IOKit.framework"
echo "--- usr/include/IOKit ---"
ls "$SDK/usr/include/IOKit" 2>/dev/null | head -5 || echo "  [结论] 没有 usr/include/IOKit"
echo "--- 全 SDK 搜 IOHIDEvent 头文件 ---"
find "$SDK" -name "IOHIDEvent*.h" 2>/dev/null | head -5 || true
echo "（以上为空 = 头文件确实不全，只能 extern 或 dlsym）"

echo "=== [1/5] §2.2 手法验证：手写 extern 声明，不依赖任何 IOKit 头 ==="
cat > /tmp/hl_extern.m <<'EOF'
#import <Foundation/Foundation.h>
typedef void *IOHIDEventRef;
typedef void *IOHIDEventSystemClientRef;
extern IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(void *a);
extern IOHIDEventRef IOHIDEventCreateDigitizerEvent(void *a, uint64_t t, uint32_t b,
    uint32_t c, uint32_t d, uint32_t e, uint32_t f, double x, double y, double z,
    double w, double v, Boolean m, Boolean n, uint32_t o);
extern void IOHIDEventSystemClientDispatchEvent(IOHIDEventSystemClientRef c, IOHIDEventRef e);
int hl_use(void){
    IOHIDEventSystemClientRef c = IOHIDEventSystemClientCreate(NULL);
    IOHIDEventSystemClientDispatchEvent(c, NULL);
    return c != NULL;
}
EOF
if xcrun -sdk iphoneos clang -arch arm64 -c -fobjc-arc -miphoneos-version-min=15.0 \
     -o /tmp/hl_extern.o /tmp/hl_extern.m 2>/tmp/hl_c.log; then
  echo "  [结论] extern 声明「编译」通过（不依赖头文件，§2.2 手法编译期可行）"
else
  echo "  [结论] extern 声明编译失败："; tail -5 /tmp/hl_c.log
fi

echo "=== [2/5] §2.2 手法验证：链接期要不要 -framework IOKit ==="
if xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -miphoneos-version-min=15.0 \
     -framework IOKit -o /tmp/hl_extern.dylib /tmp/hl_extern.m 2>/tmp/hl_l.log; then
  echo "  [结论] -framework IOKit 链接通过（SDK 里有 IOKit，可直接 extern + 链接）"
else
  echo "  [结论] -framework IOKit 链接失败："; tail -8 /tmp/hl_l.log
  echo "  → 说明 iOS 上这些符号只能 dlsym 运行时取，不能链接期依赖"
fi

echo "=== [3/5] 编译 HLProbe.dylib（dlsym 路线，不链 IOKit） ==="
rm -rf build_hl && mkdir -p build_hl
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
  -install_name @executable_path/HLProbe.dylib \
  -o build_hl/HLProbe.dylib \
  HLProbe.m

echo "=== [4/5] ad-hoc 签名 ==="
codesign -f -s - build_hl/HLProbe.dylib 2>&1 || echo "（忽略，TrollFools 会重签）"

echo "=== [5/5] 产物 ==="
ls -la build_hl/HLProbe.dylib
file build_hl/HLProbe.dylib
echo "--- 依赖 ---"
otool -L build_hl/HLProbe.dylib
( cd build_hl && zip -qry HLProbe.zip HLProbe.dylib )
ls -la build_hl/HLProbe.zip
echo "BUILD_OK"
