//
//  AgentProbe.m  ——  「能不能用代码模拟人手点屏幕」能力探针 v2
//
//  为什么要重写一版：
//    v1(TouchProbe) 结论是「权限没生效」，但事后证明那是**误判**：
//      (a) CS_PLATFORM_BINARY 缺失 → 被误读成 platform-application 失效。
//          实际：TrollStore 官方文档明说「拿到真正的 platformization 是不可能的」，
//          即该 flag 本来就不会有。PoCAgent C 版同样没有它，task_for_pid 照样成功。
//      (b) 「/ 不可写」→ 被误读成「有沙箱」。
//          实际：iOS 15+ 是 Signed System Volume，/ 对所有人（含 root）只读，与沙箱无关。
//      (c) CS_REQUIRE_LV 为真 → 被误读成 skip-library-validation 未生效。
//          实际：该 entitlement 在 iOS 15+/A12+ 属「禁用项」，TrollStore 装的时候会剥掉，
//          剥掉才是正常的（而且它跟模拟点击无关）。
//      (d) 最要命的一条：v1 在真正投递之前就 return 了。
//          它写死「只走 IOHIDEventCreateDigitizerFingerEvent 这条路」，
//          一旦 dlsym 首选命中的是 IOHIDEventCreateDigitizerEvent，就直接判 PARTIAL 返回，
//          **事件根本没投出去过**。
//      (e) 参数个数错了。IOHIDEventCreateDigitizerFingerEventWithQuality 实际是 18 个参数，
//          v1 只传了 7 个 —— 后面 x/y/z 全是寄存器垃圾值，坐标等于随机数。
//
//  本版做四件事：
//    A. 自证权限：用 SecTaskCopyValueForEntitlement 把自己**实际拿到手**的
//       entitlements 打出来（TrollStore 会剥掉禁用项，打印即见真章）。
//    B. 自证越权：task_for_pid 扫全机进程，看还能不能拿到别人的 task port。
//    C. 自证模拟点击：用**正确签名**构造 hand+finger 事件，走 4 条投递通路，
//       并用一个「全屏触摸计数器」做闭环 —— 打中了计数器就 +1。
//       其中 _enqueueHIDEvent: 是「自己点自己」的对照组（必中），
//       它要是也不中，说明事件构造本身错了；它中而其它不中，说明缺的是全局投递权限。
//    D. 系统手势自证：合成一次「从底部上滑回主屏」，若 App 真的退到后台，
//       就证明合成事件被 SpringBoard 采信了（这是最硬的一条证据）。
//    E. 顺带测截图：UIGetScreenImage / _UICreateScreenUIImage，成功就把图显示出来。
//

#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <unistd.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <objc/runtime.h>

// ---------------------------------------------------------------------------
// csops（私有，需显式声明；符号在 libsystem_kernel.dylib）
// ---------------------------------------------------------------------------
#define CS_OPS_STATUS 0
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// SecTask 系列虽然由 Security.framework 导出，但 iOS SDK 不提供头文件、
// 也不在公开 .tbd 里，直接链接有失败风险 —— 改为运行时 dlopen + dlsym。
typedef struct __SecTask *SecTaskRef;
typedef SecTaskRef (*FnSecTaskCreateFromSelf)(CFAllocatorRef);
typedef CFTypeRef  (*FnSecTaskCopyValueForEntitlement)(SecTaskRef, CFStringRef, CFErrorRef *);

// ---------------------------------------------------------------------------
// 日志（惰性初始化！v1 的日志黑洞就是栽在这：向 nil 发消息是静默 no-op）
// ---------------------------------------------------------------------------
static UITextView      *gLogView = nil;
static NSMutableString *gLog     = nil;

static void TPLog(NSString *line) {
    NSLog(@"[AGENTPROBE] %@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLog) gLog = [NSMutableString string];
        @synchronized (gLog) {
            [gLog appendString:line];
            [gLog appendString:@"\n"];
        }
        if (gLogView) {
            gLogView.text = gLog;
            [gLogView scrollRangeToVisible:NSMakeRange(gLogView.text.length, 0)];
        }
    });
}

static void TPHeader(NSString *t) {
    TPLog(@"");
    TPLog([NSString stringWithFormat:@"========== %@ ==========", t]);
}

// ===========================================================================
// 一、权限自证
// ===========================================================================

static void TP_DumpOwnEntitlements(void) {
    TPHeader(@"A. 我实际拿到的 entitlements（TrollStore 会剥掉禁用项）");

    void *hSec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!hSec) { TPLog(@"  Security.framework 打不开"); return; }
    FnSecTaskCreateFromSelf createFromSelf =
        (FnSecTaskCreateFromSelf)dlsym(hSec, "SecTaskCreateFromSelf");
    FnSecTaskCopyValueForEntitlement copyValue =
        (FnSecTaskCopyValueForEntitlement)dlsym(hSec, "SecTaskCopyValueForEntitlement");
    if (!createFromSelf || !copyValue) {
        TPLog([NSString stringWithFormat:@"  SecTask 符号缺失 create=%p copy=%p",
               createFromSelf, copyValue]);
        return;
    }

    SecTaskRef task = createFromSelf(kCFAllocatorDefault);
    if (!task) { TPLog(@"  SecTaskCreateFromSelf 返回空"); return; }

    const char *keys[] = {
        "platform-application",
        "com.apple.private.security.no-sandbox",
        "com.apple.private.security.storage.AppDataContainers",
        "com.apple.system-task-ports",
        "com.apple.system-task-ports.read",
        "get-task-allow",
        "com.apple.private.hid.client.event-dispatch",
        "com.apple.private.hid.client.event-monitor",
        "com.apple.private.skip-library-validation",
        "com.apple.springboard.launchapplications",
        "com.apple.security.exception.iokit-user-client-class",
    };
    for (int i = 0; i < (int)(sizeof(keys)/sizeof(keys[0])); i++) {
        CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, keys[i], kCFStringEncodingUTF8);
        CFTypeRef v = copyValue(task, k, NULL);
        NSString *shown = @"（无 / 已被剥离）";
        if (v) {
            if (CFGetTypeID(v) == CFBooleanGetTypeID()) {
                shown = CFBooleanGetValue((CFBooleanRef)v) ? @"✅ true" : @"❌ false";
            } else {
                CFStringRef d = CFCopyDescription(v);
                shown = [(__bridge NSString *)d copy];
                CFRelease(d);
            }
            CFRelease(v);
        }
        TPLog([NSString stringWithFormat:@"  %-52s : %@", keys[i], shown]);
        CFRelease(k);
    }
    CFRelease(task);

    // csops 原始值（只作记录，不再用它下任何结论）
    uint32_t flags = 0;
    int r = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    TPLog([NSString stringWithFormat:@"  [参考] csops r=%d flags=0x%08X（CS_PLATFORM_BINARY 缺失属正常，见文件头说明）", r, flags]);
}

// 沙箱判据：沙箱内 HOME 指向容器路径；无沙箱时是 /var/mobile
static void TP_SandboxCheck(void) {
    const char *home = getenv("HOME");
    TPLog([NSString stringWithFormat:@"  HOME = %s", home ? home : "(null)"]);
    BOOL sandboxed = (home && strstr(home, "/Containers/") != NULL);
    TPLog([NSString stringWithFormat:@"  沙箱判定（按 HOME）: %@", sandboxed ? @"仍有沙箱" : @"无沙箱 ✅"]);

    // 真实可写性：写一个只有无沙箱才够得着的路径
    NSString *probe = @"/var/mobile/Library/Preferences/.agentprobe_probe";
    NSError *e = nil;
    BOOL ok = [@"probe" writeToFile:probe atomically:YES encoding:NSUTF8StringEncoding error:&e];
    TPLog([NSString stringWithFormat:@"  写 /var/mobile/Library/Preferences/ : %@%@",
           ok ? @"✅ 成功" : @"❌ 失败",
           ok ? @"" : [NSString stringWithFormat:@" (%@)", e.localizedDescription ?: @"?"]]);
    if (ok) [[NSFileManager defaultManager] removeItemAtPath:probe error:nil];
}

// ===========================================================================
// 二、越权自证：task_for_pid 扫全机
// ===========================================================================

extern kern_return_t task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);

static void TP_TaskPortSweep(void) {
    TPHeader(@"B. 越权自证：task_for_pid 扫描全机进程");

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t sz = 0;
    if (sysctl(mib, 4, NULL, &sz, NULL, 0) != 0 || sz == 0) {
        TPLog(@"  sysctl 取进程列表失败"); return;
    }
    struct kinfo_proc *procs = malloc(sz);
    if (sysctl(mib, 4, procs, &sz, NULL, 0) != 0) { free(procs); TPLog(@"  sysctl 第二次失败"); return; }

    int n = (int)(sz / sizeof(struct kinfo_proc));
    int ok = 0, tried = 0;
    NSMutableString *samples = [NSMutableString string];
    for (int i = 0; i < n; i++) {
        pid_t p = procs[i].kp_proc.p_pid;
        if (p <= 0 || p == getpid()) continue;
        tried++;
        mach_port_t tp = MACH_PORT_NULL;
        if (task_for_pid(mach_task_self(), p, &tp) == KERN_SUCCESS && tp != MACH_PORT_NULL) {
            ok++;
            if (samples.length < 120)
                [samples appendFormat:@"pid=%d(%s) ", p, procs[i].kp_proc.p_comm];
            mach_port_deallocate(mach_task_self(), tp);
        }
    }
    free(procs);
    TPLog([NSString stringWithFormat:@"  尝试 %d 个进程，成功拿到 task port 的: %d 个", tried, ok]);
    TPLog([NSString stringWithFormat:@"  样本: %@", samples.length ? samples : @"（无）"]);
    TPLog(ok > 0 ? @"  判定：越权能力仍在 ✅（与 PoCAgent C 版结论一致）"
                 : @"  判定：越权能力已失效 ❌");
}

// ===========================================================================
// 三、模拟点击：正确的私有 API 姿势
// ===========================================================================
//
//  签名严格照抄 PTFakeTouch(IOHIDEvent+KIF.m) —— 这是被大量项目验证过的原始定义：
//    IOHIDEventCreateDigitizerEvent(allocator, timeStamp, type, index, identity,
//        eventMask, buttonMask, x, y, z, tipPressure, barrelPressure,
//        range, touch, options)                                    ← 15 个参数
//    IOHIDEventCreateDigitizerFingerEventWithQuality(allocator, timeStamp, index,
//        identity, eventMask, x, y, z, tipPressure, twist,
//        minorRadius, majorRadius, quality, density, irregularity,
//        range, touch, options)                                    ← 18 个参数

typedef void  *IOHIDEventRef;
typedef void  *IOHIDEventSystemClientRef;
typedef uint64_t IOHIDTime;

typedef IOHIDEventRef (*FnCreateDigitizer)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t,
                                           uint32_t, uint32_t, uint32_t,
                                           double, double, double, double, double,
                                           Boolean, Boolean, uint32_t);
typedef IOHIDEventRef (*FnCreateFingerQ)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t, uint32_t,
                                         double, double, double, double, double,
                                         double, double, double, double, double,
                                         Boolean, Boolean, uint32_t);
typedef void (*FnAppend)(IOHIDEventRef parent, IOHIDEventRef child);
typedef void (*FnSetInt)(IOHIDEventRef ev, uint32_t field, int value);
typedef IOHIDEventSystemClientRef (*FnClientSimple)(CFAllocatorRef, uint32_t);
typedef IOHIDEventSystemClientRef (*FnClientCreate)(CFAllocatorRef);
typedef void (*FnDispatch)(IOHIDEventSystemClientRef, IOHIDEventRef);

static FnCreateDigitizer   gCreateDigitizer   = NULL;
static FnCreateFingerQ     gCreateFingerQ     = NULL;
static FnAppend            gAppend            = NULL;
static FnSetInt            gSetInt            = NULL;
static FnClientSimple      gClientSimple      = NULL;
static FnClientCreate      gClientCreate      = NULL;
static FnDispatch          gDispatch          = NULL;

// 字段编号：IOHIDEventFieldBase(type) = type << 16；kIOHIDEventTypeDigitizer = 11
#define kIOHIDEventTypeDigitizer 11
#define IOHIDField(n) ((uint32_t)(((uint32_t)kIOHIDEventTypeDigitizer << 16) + (n)))
#define kFieldDigitizerX                  IOHIDField(0)
#define kFieldDigitizerY                  IOHIDField(1)
#define kFieldDigitizerEventMask          IOHIDField(7)
#define kFieldDigitizerIsDisplayIntegrated IOHIDField(25)

#define kTransducerHand   3
#define kTransducerFinger 2

#define kMaskRange    0x00000001
#define kMaskTouch    0x00000002
#define kMaskPosition 0x00000004
#define kMaskStop     0x00000008
#define kMaskStart    0x00000100

static void TP_LoadHIDSymbols(void) {
    TPHeader(@"C1. 私有符号解析");

    const char *fws[] = {
        "/System/Library/PrivateFrameworks/IOHID.framework/IOHID",
        "/System/Library/Frameworks/IOKit.framework/IOKit",
    };
    for (int i = 0; i < 2; i++) {
        void *h = dlopen(fws[i], RTLD_LAZY | RTLD_GLOBAL);
        TPLog([NSString stringWithFormat:@"  dlopen %-40s → %@", fws[i],
               h ? @"OK" : [NSString stringWithFormat:@"%s", dlerror()]]);
    }

    struct { const char *name; void **slot; } tab[] = {
        {"IOHIDEventCreateDigitizerEvent",                    (void **)&gCreateDigitizer},
        {"IOHIDEventCreateDigitizerFingerEventWithQuality",   (void **)&gCreateFingerQ},
        {"IOHIDEventAppendEvent",                             (void **)&gAppend},
        {"IOHIDEventSetIntegerValue",                         (void **)&gSetInt},
        {"IOHIDEventSystemClientCreateSimpleClient",          (void **)&gClientSimple},
        {"IOHIDEventSystemClientCreate",                      (void **)&gClientCreate},
        {"IOHIDEventSystemClientDispatchEvent",               (void **)&gDispatch},
    };
    for (int i = 0; i < (int)(sizeof(tab)/sizeof(tab[0])); i++) {
        void *p = dlsym(RTLD_DEFAULT, tab[i].name);
        if (!p) p = dlsym(RTLD_DEFAULT, tab[i].name);
        *(tab[i].slot) = p;
        TPLog([NSString stringWithFormat:@"  %-46s → %p %@", tab[i].name, p, p ? @"" : @"❌缺失"]);
    }
}

// 构造一个「手 + 手指」复合事件（PTFakeTouch 同款结构）
typedef NS_ENUM(int, TPPhase) { TPPhaseBegin, TPPhaseMove, TPPhaseEnd };

static IOHIDEventRef TP_MakeTouchEvent(double x, double y, TPPhase phase) {
    if (!gCreateDigitizer || !gCreateFingerQ || !gAppend || !gSetInt) return NULL;

    IOHIDTime ts = mach_absolute_time();

    // 手掌事件（容器）
    IOHIDEventRef hand = gCreateDigitizer(kCFAllocatorDefault, ts, kTransducerHand,
                                          0, 0, kMaskTouch, 0,
                                          0, 0, 0, 0, 0,
                                          0, true, 0);
    if (!hand) return NULL;
    gSetInt(hand, kFieldDigitizerIsDisplayIntegrated, 1);

    uint32_t mask;
    int touching;
    switch (phase) {
        case TPPhaseBegin: mask = kMaskRange | kMaskTouch | kMaskPosition | kMaskStart; touching = 1; break;
        case TPPhaseMove:  mask = kMaskPosition;                                        touching = 1; break;
        default:           mask = kMaskStop;                                            touching = 0; break;
    }

    IOHIDEventRef finger = gCreateFingerQ(kCFAllocatorDefault, ts,
                                          1,      // index
                                          2,      // identity（固定 2）
                                          mask,
                                          x, y, 0,
                                          0,      // tipPressure
                                          0,      // twist
                                          5.0, 5.0, 1.0, 1.0, 1.0,   // minorRadius, majorRadius, quality, density, irregularity
                                          touching, touching,        // range, touch
                                          0);
    if (!finger) { CFRelease(hand); return NULL; }
    gSetInt(finger, kFieldDigitizerIsDisplayIntegrated, 1);
    gAppend(hand, finger);
    CFRelease(finger);
    return hand;
}

// ---------------------------------------------------------------------------
// 触摸计数器（闭环验证用）
// ---------------------------------------------------------------------------
static UILabel         *gCatcherLabel = nil;
static NSInteger        gCatcherHits  = 0;
// 注意：CGPointZero 不是编译期常量，不能用作 static 的初始化器（会报
// "initializer element is not a compile-time constant"）—— 用聚合初始化写死。
static CGPoint          gCatcherLast  = {0.0, 0.0};
static CGPoint          gCatcherViewCenter = {0.0, 0.0};
static UIView          *gCatcher = nil;

@interface TPCatcherView : UIView
@end

@implementation TPCatcherView
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    gCatcherLast = [t locationInView:self];
    gCatcherHits++;
    dispatch_async(dispatch_get_main_queue(), ^{
        gCatcherLabel.text = [NSString stringWithFormat:@"触摸命中次数: %ld\n最后一次: (%.0f, %.0f)",
                              (long)gCatcherHits, gCatcherLast.x, gCatcherLast.y];
    });
    TPLog([NSString stringWithFormat:@"  ★ 计数器 +1 → %ld  坐标(%.0f, %.0f)",
           (long)gCatcherHits, gCatcherLast.x, gCatcherLast.y]);
}
@end

// ---------------------------------------------------------------------------
// 四条投递通路
// ---------------------------------------------------------------------------

static IOHIDEventSystemClientRef gSimpleClient = NULL;
static IOHIDEventSystemClientRef gFullClient   = NULL;

// 通路 1：SimpleClient + DispatchEvent（SimulateTouch 全局注入走的就是这条）
static BOOL TP_Dispatch_SimpleClient(IOHIDEventRef ev) {
    if (!gClientSimple || !gDispatch) return NO;
    if (!gSimpleClient) gSimpleClient = gClientSimple(kCFAllocatorDefault, 0);
    if (!gSimpleClient) { TPLog(@"    SimpleClient 创建返回空"); return NO; }
    gDispatch(gSimpleClient, ev);
    return YES;
}

// 通路 2：完整 Client + DispatchEvent
static BOOL TP_Dispatch_FullClient(IOHIDEventRef ev) {
    if (!gClientCreate || !gDispatch) return NO;
    if (!gFullClient) gFullClient = gClientCreate(kCFAllocatorDefault);
    if (!gFullClient) { TPLog(@"    完整 Client 创建返回空"); return NO; }
    gDispatch(gFullClient, ev);
    return YES;
}

// 通路 3：UIApplication 私有 _enqueueHIDEvent:（自己点自己，对照组）
static BOOL TP_Dispatch_Enqueue(IOHIDEventRef ev) {
    UIApplication *app = [UIApplication sharedApplication];
    SEL sel = NSSelectorFromString(@"_enqueueHIDEvent:");
    if (![app respondsToSelector:sel]) { TPLog(@"    _enqueueHIDEvent: 不存在"); return NO; }
    typedef void (*Fn)(id, SEL, IOHIDEventRef);
    Fn f = (Fn)[app methodForSelector:sel];
    if (!f) return NO;
    f(app, sel, ev);
    return YES;
}

// 通路 4 原计划用 BKSHIDEventSetDigitizerInfo 指定窗口 contextID，
// 但该私有函数的参数个数无法在运行时确认，传错有崩溃风险，且它只能点「自己」的窗口、
// 对「点目标 App」没有帮助 —— 因此移除，只保留全局两条 + 对照一条。

// ---------------------------------------------------------------------------
// 点一下，然后看计数器是否 +1
// ---------------------------------------------------------------------------
static BOOL TP_TapAndVerify(CGPoint pt, NSString *pathName, int which) {
    NSInteger before = gCatcherHits;

    IOHIDEventRef down = TP_MakeTouchEvent(pt.x, pt.y, TPPhaseBegin);
    if (!down) { TPLog([NSString stringWithFormat:@"  [%@] 事件构造失败（down=NULL）", pathName]); return NO; }
    usleep(40000);
    IOHIDEventRef up = TP_MakeTouchEvent(pt.x, pt.y, TPPhaseEnd);

    BOOL sent = NO;
    switch (which) {
        case 1: sent = TP_Dispatch_SimpleClient(down); break;
        case 2: sent = TP_Dispatch_FullClient(down);   break;
        case 3: sent = TP_Dispatch_Enqueue(down);      break;
    }
    usleep(60000);
    if (up) {
        switch (which) {
            case 1: TP_Dispatch_SimpleClient(up); break;
            case 2: TP_Dispatch_FullClient(up);   break;
            case 3: TP_Dispatch_Enqueue(up);      break;
        }
        CFRelease(up);
    }
    CFRelease(down);

    // 等事件跑完一圈
    for (int i = 0; i < 12 && gCatcherHits == before; i++) usleep(50000);

    BOOL hit = (gCatcherHits > before);
    TPLog([NSString stringWithFormat:@"  [%@] 投递%@ → 计数器 %ld → %ld  %@",
           pathName, sent ? @"成功" : @"失败",
           (long)before, (long)gCatcherHits,
           hit ? @"✅ 命中（事件真的进了系统）" : @"❌ 未命中"]);
    return hit;
}

static void TP_TapMatrix(void) {
    TPHeader(@"C2. 模拟点击闭环（4 条通路，逐条验证）");

    if (!gCreateDigitizer || !gCreateFingerQ) {
        TPLog(@"  事件构造器缺失，无法继续");
        return;
    }

    CGPoint pt = CGPointMake(gCatcherViewCenter.x, gCatcherViewCenter.y);
    TPLog([NSString stringWithFormat:@"  目标坐标 = 计数器中心 (%.0f, %.0f)", pt.x, pt.y]);

    gCatcherHits = 0;

    BOOL h1 = TP_TapAndVerify(pt, @"通路1 SimpleClient全局投递", 1);
    usleep(200000);
    BOOL h2 = TP_TapAndVerify(pt, @"通路2 完整Client全局投递", 2);
    usleep(200000);
    BOOL h3 = TP_TapAndVerify(pt, @"通路3 _enqueueHIDEvent(对照组/自己点自己)", 3);

    TPHeader(@"C3. 点击结论");
    if (h3 && !h1 && !h2) {
        TPLog(@"  ⚠️ 只有对照组命中：事件构造是对的，但**全局投递被拦**。");
        TPLog(@"     → 需要真正的全局投递权限（本版 ent_d.plist 已加 HID dispatch），");
        TPLog(@"       若仍被拦，则说明必须改走「把代码注入目标 App」的路线。");
    } else if (h1 || h2) {
        TPLog(@"  ✅ 全局投递可用！合成点击能进入系统输入流。");
        TPLog(@"     → 目标 App 在前台时，这一下点到的就是目标 App。");
    } else if (!h3) {
        TPLog(@"  ❓ 连对照组都没命中：事件构造参数可能仍不对（坐标/掩码/identity）。");
    }
    TPLog([NSString stringWithFormat:@"  明细: 通路1=%@ 通路2=%@ 通路3=%@",
           h1?@"命中":@"未中", h2?@"命中":@"未中", h3?@"命中":@"未中"]);
}

// ---------------------------------------------------------------------------
// C4：系统手势自证 —— 从底部上滑，若 App 退回后台 = SpringBoard 采信了合成事件
// ---------------------------------------------------------------------------
static BOOL gDidBackgroundAfterGesture = NO;

static void TP_HomeGestureTest(void) {
    TPHeader(@"C4. 系统手势自证（底部上滑 → 若真的回到主屏，说明 SpringBoard 采信了）");

    if (!gCreateDigitizer || !gCreateFingerQ) { TPLog(@"  事件构造器缺失"); return; }

    CGSize sc = [UIScreen mainScreen].bounds.size;
    double x  = sc.width / 2.0;
    double y0 = sc.height - 4.0;
    double y1 = sc.height * 0.35;

    gDidBackgroundAfterGesture = NO;
    TPLog([NSString stringWithFormat:@"  投递手势 (%.0f, %.0f) → (%.0f, %.0f)", x, y0, x, y1]);

    IOHIDEventRef d = TP_MakeTouchEvent(x, y0, TPPhaseBegin);
    if (d) { TP_Dispatch_SimpleClient(d); TP_Dispatch_FullClient(d); CFRelease(d); }
    usleep(30000);

    const int steps = 8;
    for (int i = 1; i <= steps; i++) {
        double y = y0 + (y1 - y0) * ((double)i / steps);
        IOHIDEventRef m = TP_MakeTouchEvent(x, y, TPPhaseMove);
        if (m) { TP_Dispatch_SimpleClient(m); TP_Dispatch_FullClient(m); CFRelease(m); }
        usleep(12000);
    }
    IOHIDEventRef u = TP_MakeTouchEvent(x, y1, TPPhaseEnd);
    if (u) { TP_Dispatch_SimpleClient(u); TP_Dispatch_FullClient(u); CFRelease(u); }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gDidBackgroundAfterGesture)
            TPLog(@"  ✅ 手势生效：App 已退回后台 → 合成事件被系统采信（最硬证据）");
        else
            TPLog(@"  ❌ 手势未生效：仍在前台 → 合成事件没被系统采信");
    });
}

// ===========================================================================
// 四、截图能力
// ===========================================================================

static CGFloat TP_MeanLuminance(UIImage *img) {
    if (!img) return -1;
    CGImageRef cg = img.CGImage;
    if (!cg) return -1;
    size_t w = 32, h = 32;
    unsigned char buf[32*32*4];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(buf, w, h, 8, w*4, cs,
                                             kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    if (!ctx) return -1;
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
    CGContextRelease(ctx);
    double sum = 0;
    for (int i = 0; i < (int)(w*h); i++) sum += (buf[i*4] + buf[i*4+1] + buf[i*4+2]) / 3.0;
    return (CGFloat)(sum / (double)(w*h));
}

typedef CGImageRef (*FnUIGetScreenImage)(void);
typedef UIImage *(*FnUICreateScreenUIImage)(void);

static UIImage *gShot = nil;

static UIImage *TP_TryScreenshot(void) {
    TPHeader(@"D. 截图能力");

    // 方式 1：UIGetScreenImage()
    FnUIGetScreenImage f1 = (FnUIGetScreenImage)dlsym(RTLD_DEFAULT, "UIGetScreenImage");
    TPLog([NSString stringWithFormat:@"  UIGetScreenImage → %p", f1]);
    if (f1) {
        CGImageRef cg = f1();
        TPLog([NSString stringWithFormat:@"    调用返回 %p, 尺寸 %zux%zu", cg,
               cg ? CGImageGetWidth(cg) : 0, cg ? CGImageGetHeight(cg) : 0]);
        if (cg) {
            UIImage *img = [UIImage imageWithCGImage:cg];
            CFRelease(cg);
            if (img) return img;
        }
    }

    // 方式 2：_UICreateScreenUIImage()
    FnUICreateScreenUIImage f2 = (FnUICreateScreenUIImage)dlsym(RTLD_DEFAULT, "_UICreateScreenUIImage");
    TPLog([NSString stringWithFormat:@"  _UICreateScreenUIImage → %p", f2]);
    if (f2) {
        UIImage *img = f2();
        TPLog([NSString stringWithFormat:@"    调用返回 %@, 尺寸 %.0fx%.0f",
               img ? @"非空" : @"空", img ? img.size.width : 0, img ? img.size.height : 0]);
        if (img) return img;
    }

    TPLog(@"  ❌ 两种截图方式都没拿到图（可能是 framebuffer 权限，需要额外 entitlement）");
    return nil;
}

// 把截图弹出来给用户看一眼（最直观的证明）
@interface TPShotViewController : UIViewController
@property (nonatomic, strong) UIImage *img;
@end

@implementation TPShotViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    CGFloat W = self.view.bounds.size.width, H = self.view.bounds.size.height;
    UIImageView *iv = [[UIImageView alloc] initWithFrame:CGRectMake(8, 60, W - 16, H - 160)];
    iv.contentMode = UIViewContentModeScaleAspectFit;
    iv.backgroundColor = [UIColor darkGrayColor];
    iv.image = self.img;
    [self.view addSubview:iv];

    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(8, 24, W - 16, 30)];
    lb.textColor = [UIColor whiteColor];
    lb.font = [UIFont boldSystemFontOfSize:15];
    lb.text = [NSString stringWithFormat:@"截图成功  %.0f x %.0f  亮度 %.0f",
               self.img.size.width, self.img.size.height, TP_MeanLuminance(self.img)];
    [self.view addSubview:lb];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(8, H - 70, W - 16, 50);
    close.backgroundColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    [close setTitle:@"关闭" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [close addTarget:self action:@selector(dismissSelf) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:close];
}
- (void)dismissSelf { [self dismissViewControllerAnimated:YES completion:nil]; }
@end

// ===========================================================================
// 五、UI
// ===========================================================================

@interface TPRootViewController : UIViewController
@end

@implementation TPRootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"自动操作探针";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // 全部 frame 布局，避开 Auto Layout（v1 的按钮失效就栽在约束上）
    CGSize screen = [UIScreen mainScreen].bounds.size;
    CGFloat W = screen.width, H = screen.height;
    CGFloat pad = 10.0;
    BOOL isPad = ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad);
    if (isPad) { W = MIN(screen.width, 560.0); pad = (screen.width - W) / 2.0; }

    CGFloat y = 44.0 + 16.0;
    CGFloat btnH = 46.0;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(pad, y, (W - pad*3)/2.0, btnH);
    [btn setTitle:@"▶ 跑全部探针" forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    btn.backgroundColor = [UIColor colorWithRed:0.0 green:0.478 blue:1.0 alpha:1.0];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.layer.cornerRadius = 9;
    [btn addTarget:self action:@selector(runAll) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];

    UIButton *shotBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    shotBtn.frame = CGRectMake(CGRectGetMaxX(btn.frame) + pad, y, (W - pad*3)/2.0, btnH);
    [shotBtn setTitle:@"📷 截图测试" forState:UIControlStateNormal];
    shotBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    shotBtn.backgroundColor = [UIColor colorWithRed:0.13 green:0.55 blue:0.24 alpha:1.0];
    [shotBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    shotBtn.layer.cornerRadius = 9;
    [shotBtn addTarget:self action:@selector(doShot) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:shotBtn];

    y = CGRectGetMaxY(btn.frame) + 8.0;

    CGFloat logH = (H - y - pad - 24.0) * 0.52;
    gLogView = [[UITextView alloc] initWithFrame:CGRectMake(pad, y, W - pad*2, logH)];
    gLogView.font = [UIFont monospacedSystemFontOfSize:9.5 weight:UIFontWeightRegular];
    gLogView.editable = NO;
    gLogView.backgroundColor = [UIColor colorWithRed:0.96 green:0.96 blue:0.97 alpha:1.0];
    gLogView.layer.cornerRadius = 8;
    gLogView.textContainerInset = UIEdgeInsetsMake(6, 6, 6, 6);
    [self.view addSubview:gLogView];

    y = CGRectGetMaxY(gLogView.frame) + 8.0;

    TPCatcherView *catcher = [[TPCatcherView alloc] initWithFrame:
                              CGRectMake(pad, y, W - pad*2, H - y - pad - 20.0)];
    catcher.backgroundColor = [UIColor colorWithRed:0.12 green:0.30 blue:0.55 alpha:1.0];
    catcher.layer.cornerRadius = 8;
    [self.view addSubview:catcher];
    gCatcher = catcher;
    // 注意：HID 数字转换器用的是**屏幕绝对坐标**（points），
    // 不是视图局部坐标 —— 这里换算到窗口坐标系，否则打点位置会整体偏移。
    gCatcherViewCenter = [catcher convertPoint:CGPointMake(catcher.bounds.size.width / 2.0,
                                                          catcher.bounds.size.height / 2.0)
                                        toView:nil];

    gCatcherLabel = [[UILabel alloc] initWithFrame:catcher.bounds];
    gCatcherLabel.textAlignment = NSTextAlignmentCenter;
    gCatcherLabel.numberOfLines = 3;
    gCatcherLabel.textColor = [UIColor whiteColor];
    gCatcherLabel.font = [UIFont boldSystemFontOfSize:15];
    gCatcherLabel.text = @"触摸计数器: 0\n（探针会往这里打合成点击）";
    [catcher addSubview:gCatcherLabel];

    [self.view bringSubviewToFront:btn];
    [self.view bringSubviewToFront:shotBtn];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onBackground)
                                                 name:UIApplicationDidEnterBackgroundNotification
                                               object:nil];

    TPLog(@"就绪。1.2 秒后自动开跑（也可以点按钮 / 长按屏幕）。");
    TPLog([NSString stringWithFormat:@"屏幕 %.0f x %.0f", screen.width, screen.height]);

    UILongPressGestureRecognizer *lp =
        [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(onLongPress:)];
    lp.minimumPressDuration = 0.5;
    lp.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:lp];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        TPLog(@"〔自动执行〕");
        [self runAll];
    });
}

// 布局稳定后再算一次，确保拿到的是窗口/屏幕绝对坐标
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    if (gCatcher) {
        gCatcherViewCenter = [gCatcher convertPoint:CGPointMake(gCatcher.bounds.size.width / 2.0,
                                                               gCatcher.bounds.size.height / 2.0)
                                             toView:nil];
    }
}

- (void)onBackground {
    gDidBackgroundAfterGesture = YES;
    NSLog(@"[AGENTPROBE] applicationDidEnterBackground");
}

- (void)onLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state == UIGestureRecognizerStateBegan) [self runAll];
}

- (void)runAll {
    TPLog(@"");
    TPLog(@"##################################################");
    TPLog(@"   自动操作能力探针 v2   AgentProbe");
    TPLog(@"##################################################");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        TPLog([NSString stringWithFormat:@"  系统版本: %@   机型: %@   pid: %d",
               [[UIDevice currentDevice] systemVersion],
               [[UIDevice currentDevice] model], getpid()]);

        TP_DumpOwnEntitlements();
        TP_SandboxCheck();
        TP_TaskPortSweep();
        TP_LoadHIDSymbols();
        TP_TapMatrix();
        TP_HomeGestureTest();

        TPLog(@"");
        TPLog(@"探针跑完。下一步：点「📷 截图测试」。");
        TPLog(@"##################################################");
    });
}

- (void)doShot {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        UIImage *img = TP_TryScreenshot();
        if (!img) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            TPShotViewController *vc = [[TPShotViewController alloc] init];
            vc.img = img;
            [self presentViewController:vc animated:YES completion:nil];
        });
    });
}

@end

@interface TPAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation TPAppDelegate
- (BOOL)application:(UIApplication *)application
didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController =
        [[UINavigationController alloc] initWithRootViewController:[[TPRootViewController alloc] init]];
    [self.window makeKeyAndVisible];
    return YES;
}
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    TPLog([NSString stringWithFormat:@"被 URL 唤起: %@", url.absoluteString]);
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([TPAppDelegate class]));
    }
}
