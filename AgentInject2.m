// ===========================================================================
//  AgentInject2.m —— TrollFools 注入用 dylib（arm64 / iOS 15+）
//
//  目标：一次装机回答所有问题，并且「通的那条路」直接变成可用的控制通道。
//
//  相比 v1（闪退版）的修法：
//    1. constructor 里【不碰任何 UIKit】。只注册通知 + 起后台线程。
//       所有 UI 操作推迟到 UIApplicationDidFinishLaunching 之后 6 秒。
//    2. 每个自检步骤独立 @try/@catch，一步炸不影响其他步。
//    3. 不再用「dispatch 返回值 == 成功」这种自欺判据（v2/v3 探针就是栽在这）。
//       改用【客观判据】：
//         · 建一个 HID monitor client（type=2）挂 runloop，统计收到的事件数
//           → 计数涨了 = 事件真的进了系统队列（backboardd 收了）
//         · hook -[UIApplication sendEvent:] 计数
//           → 计数涨了 = 事件真的回到了本进程 UIKit（对注入目标 App 来说这就够了）
//
//  从「老贝贝连点器 v5.0.2」逆向里抄来的唯一有价值的东西：
//    · 它用的是老签名 IOHIDEventSystemClientCreate(kCFAllocatorDefault)（单参数），
//      而不是 CreateWithType / CreateSimpleClient。
//    · 它用 IOHIDEventAppendEvent 把「手指事件」挂进「手掌(hand)事件」容器。
//    · 它有 IOHIDEventSetSenderID 调用，且带 0x4001 常量。
//    → 这三点我们做成矩阵枚举，逐条实测，不再猜。
//
//  其余（OpenCV 找图 / Vision 识字 / 动作列表 UI / 那 6 个 UI 挂点）全部废弃不用。
// ===========================================================================

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <unistd.h>
#import <sys/sysctl.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

// ---------------------------------------------------------------------------
// 0. 日志：同时进内存缓冲 / NSLog / 文件
// ---------------------------------------------------------------------------
static NSMutableString *gLog = nil;
static NSLock          *gLogLock = nil;

static void AILogv(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) { NSLog(@"[AI2] %@", s); return; }
    [gLogLock lock];
    [gLog appendString:s]; [gLog appendString:@"\n"];
    [gLogLock unlock];
    NSLog(@"[AI2] %@", s);
}
#define AILog(...) AILogv(__VA_ARGS__)

static void AIWriteReport(void) {
    if (!gLog) return;
    [gLogLock lock];
    NSString *snap = [gLog copy];
    [gLogLock unlock];
    NSData *d = [snap dataUsingEncoding:NSUTF8StringEncoding];
    NSString *paths[] = {
        @"/var/mobile/agent_inject2_report.txt",
        @"/var/mobile/Documents/agent_inject2_report.txt",
        [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
         stringByAppendingPathComponent:@"agent_inject2_report.txt"],
    };
    for (int i = 0; i < 3; i++) {
        @try { [d writeToFile:paths[i] atomically:YES]; AILog(@"报告已写: %@", paths[i]); } @catch (id e) {}
    }
}

// ---------------------------------------------------------------------------
// 1. 全局状态
// ---------------------------------------------------------------------------
static volatile int32_t gMonHits      = 0;   // HID monitor client 收到的事件数
static volatile int32_t gSendEventHits = 0;  // -[UIApplication sendEvent:] 命中数
static volatile int32_t gControlHits   = 0;  // UIControl 触发数
static volatile int32_t gActionHits    = 0;  // -[UIApplication sendAction:...] 命中数（按钮真被按的铁证）
static NSString *gLastAction  = nil;   // 最后一次命中的 action 描述

static int  gBestTap   = 0;   // 0=无 1=HID 2=进程内UIKit 3=UIControl
static int  gBestTapForm = 0; // HID 事件形态：0=复合 1=裸18参 2=裸老10参
static int  gBestShot  = 0;   // 0=无 1..N 对应截图方法
static void *gBestClient = NULL;  // 能用的 HID client
static BOOL gIsSpringBoard = NO;
static NSString *gProcName = @"?";
static NSString *gBundleId = @"?";
static NSString *gDevId    = @"?";
static NSString *gBase     = nil;   // 控制服务器地址（可运行时覆盖）
static BOOL gBooted = NO;
static NSString *gBootSrc  = @"?";  // 记录自检是被哪条路径触发的（排障用）

// ---- v10 网络可观测性 ----
// 之前所有版本都只能靠用户「复制日志再粘贴回来」才能知道网络到底怎么了，
// 而用户明确说过「我传话传不清楚」。所以 v10 把这些数字直接画在手机屏幕顶端：
// 一眼就能看到是没网(-1009)、DNS 挂了(-1003)、超时(-1001) 还是 TLS(-1200)。
static NSString * const kAIVer = @"v23";
static volatile int32_t gPollOK = 0, gPollErr = 0;
static volatile int32_t gRepOK  = 0, gRepErr  = 0;
static volatile int32_t gCmdGot = 0;
static long             gLastErrCode = 0;
static NSString        *gLastErrText = nil;
static NSString        *gToastText   = nil;   // 我从中继下发的一句话
static NSString        *gDiagText    = nil;   // 网络自检结果
static UIWindow        *gHudWindow   = nil;   // 顶端常驻状态条（独立于盖屏，收起盖屏也还在）
static UILabel         *gHudLabel    = nil;
static BOOL             gHudWanted   = YES;
static NSString        *gActiveBase  = nil;   // 当前实际在用的中继地址（可能是 IP 兜底）
// 注意：不能用 UIBackgroundTaskInvalid 初始化 —— 它不是编译期常量，
// static 变量拿它当 initializer 会直接报 "initializer element is not a compile-time constant"。
static UIBackgroundTaskIdentifier gBgTask = 0;
static BOOL gBgActive = NO;

// 盖屏窗口。必须是 static 强引用，否则 ARC 会在函数返回时把它释放掉，
// 表现就是"注入成功但屏幕上什么都没有"（v2 踩过的坑）。
// 同时它必须在文件靠前的位置声明 —— v3 的伪造 Touch 分发代码（约 530 行）
// 会用到它，声明放在 13 节会导致 "use of undeclared identifier"。
static UIWindow *gOverlayWindow = nil;
static UIWindow *gFloatWindow   = nil;   // v20 悬浮球（替代碍事的全屏盖屏，默认只留这个）
static BOOL      gFloatExpanded = NO;    // 悬浮球是否展开了面板
static BOOL      gFloatForce    = NO;    // 交互操作要立刻重绘，跳过节流
static CFTimeInterval gFloatLast = 0;

// v20 开关项：状态存 NSUserDefaults，杀 App 重开也记得住。
// 放在文件靠前的位置 —— AIExecCmd（~2200 行）在它定义之前就要用。
#define AIK(k) [@"ai2_" stringByAppendingString:(k)]
static BOOL AIFlag(NSString *k, BOOL def) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:AIK(k)];
    return v ? [v boolValue] : def;
}
static void AISetFlag(NSString *k, BOOL b) {
    [[NSUserDefaults standardUserDefaults] setBool:b forKey:AIK(k)];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

// 前向声明：sendEvent hook 里要在定义之前调用 AIBoot
static void AIBoot(void);
// AITapInProcess（约 430 行）在 AIHostWindow 定义（约 580 行）之前就要用它
static UIWindow *AIHostWindow(void);
static void AISetOverlayVisible(BOOL vis);   // 盖屏按钮在它的定义之前就要用
static void AIShowOverlay(void);            // 盖屏按钮回调里要刷新报告
static void AITestTapAt(CGPoint pt, NSString *desc);
static void AITestTapButton(void);
static NSString *AINetDiag(void);           // AIExecCmd（~1500 行）在它的定义之前就要用
static void AIToast(NSString *txt);
static void AISetHudVisible(BOOL vis);
static void AIHudApply(void);
static NSString *AITcpTest(const char *host, int port, double tmoSec);  // AINetLoop(~1656) 在定义(~1938)之前就要用
// 这个坑已经栽了 4 次（v3/v5/v13x2）：C99 不允许隐式声明，
// 在本文件里任何「定义在后面的 static 函数」被提前调用，都得在这里补一行声明。
static void AISleep(double sec);                        // 7c 段在它定义之前调用
static BOOL AIDispatchFakeViaSendEvent(CGPoint pt, int steps, double dt);
// v16：macro（~1000 行）要在下面这几个函数的定义之前调用它们
static BOOL AIFakeSwipe(CGPoint a, CGPoint b, int steps, double dur);
static void AIMainSync(void (^b)(void));
static NSString *AITreeOf(UIView *v, int depth, int maxDepth);
static NSString *AITextList(UIView *v, int depth, int maxDepth);  // v19：读界面文本（陌生 App 导航刚需）
static BOOL AIBudgetTake(void);                      // v23：额度控制，定义在 ~2340 行
static NSArray *AIHostWindows(void);                 // v23：候选窗口列表（AIHitAtPoint 提前用）
static UIView *AIHitAtPoint(CGPoint pt);             // v23：跨窗口命中测试
static void AIBudgetReset(int n);                    // v23：额度重置，定义在 ~2410 行
static NSDictionary *AIPickTextViaGesture(NSString *kw);  // v23：按文字触发手势，定义在 ~1339 行
static NSDictionary *AIScrollAt(CGPoint pt, double dy, double dx, BOOL anim);  // v17
static NSString *AIBack(void);                  // v18：AIRunMacro(~1057) 在它定义之前要调用
static NSString *AINavInfo(void);               // v18
// v20 自更新：AIInstall（~3060 行）在它们的定义之前要调用
static NSString *AICoreDir(void);
static BOOL  AIHandoffToNewer(void);
static NSString *AIUpdateFrom(NSString *url, NSString *ver);
static void  AIFloatApply(void);
static NSString *AINewerCorePath(void);      // core 命令 + 悬浮球面板要用
static void  AICheckUpdateAsync(void);       // AIBoot 里要用
static void  AIInstall(void);                // AgentCoreStart（非 static）要调用它

// ---------------------------------------------------------------------------
// 2. HID 私有符号（全部 dlsym，不做链接期依赖）
// ---------------------------------------------------------------------------
typedef void     *IOHIDEventRef;
typedef void     *IOHIDEventSystemClientRef;
typedef uint64_t  IOHIDTime;

typedef IOHIDEventRef (*F_CreateDigitizer)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t,
                                           uint32_t, uint32_t, uint32_t,
                                           double, double, double, double, double,
                                           Boolean, Boolean, uint32_t);
typedef IOHIDEventRef (*F_CreateFingerQ)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t, uint32_t,
                                         double, double, double, double, double,
                                         double, double, double, double, double,
                                         Boolean, Boolean, uint32_t);
typedef IOHIDEventRef (*F_CreateFingerOld)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t, uint32_t,
                                           double, double, double, double, double, uint32_t);
typedef void (*F_Append)(IOHIDEventRef, IOHIDEventRef);
typedef void (*F_SetInt)(IOHIDEventRef, uint32_t, int);
typedef void (*F_SetFloat)(IOHIDEventRef, uint32_t, double);
typedef void (*F_SetSender)(IOHIDEventRef, uint64_t);
typedef IOHIDEventSystemClientRef (*F_ClientCreate)(CFAllocatorRef);
typedef IOHIDEventSystemClientRef (*F_ClientSimple)(CFAllocatorRef, uint32_t);
typedef IOHIDEventSystemClientRef (*F_ClientType)(CFAllocatorRef, int32_t, CFDictionaryRef);
typedef void (*F_Dispatch)(IOHIDEventSystemClientRef, IOHIDEventRef);
typedef void (*F_Schedule)(IOHIDEventSystemClientRef, CFRunLoopRef, CFStringRef);
typedef void (*F_SetCb)(IOHIDEventSystemClientRef, void *, void *, void *);

static F_CreateDigitizer gCreateDigitizer = NULL;
static F_CreateFingerQ   gCreateFingerQ   = NULL;
static F_CreateFingerOld gCreateFingerOld = NULL;
static F_Append          gAppend          = NULL;
static F_SetInt          gSetInt          = NULL;
static F_SetFloat        gSetFloat        = NULL;
static F_SetSender       gSetSender       = NULL;
static F_ClientCreate    gClientCreate    = NULL;
static F_ClientSimple    gClientSimple    = NULL;
static F_ClientType      gClientType      = NULL;
static F_Dispatch        gDispatch        = NULL;
static F_Schedule        gSchedule        = NULL;
static F_SetCb           gSetCb           = NULL;

#define kIOHIDEventTypeDigitizer 11
#define IOHIDField(n) ((uint32_t)(((uint32_t)kIOHIDEventTypeDigitizer << 16) + (n)))
#define kFieldDigitizerX                   IOHIDField(0)
#define kFieldDigitizerY                   IOHIDField(1)
#define kFieldDigitizerEventMask           IOHIDField(7)
#define kFieldDigitizerIsDisplayIntegrated IOHIDField(25)

#define kTransducerHand   3
#define kTransducerFinger 2
#define kMaskRange    0x00000001
#define kMaskTouch    0x00000002
#define kMaskPosition 0x00000004

typedef enum { TPBegin = 0, TPMove = 1, TPEnd = 2 } TPPhase;

static void AILoadHID(void) {
    AILog(@"==== [1] HID 符号解析 ====");
    const char *fws[] = {
        "/System/Library/PrivateFrameworks/IOHID.framework/IOHID",
        "/System/Library/Frameworks/IOKit.framework/IOKit",
    };
    for (int i = 0; i < 2; i++) {
        void *h = dlopen(fws[i], RTLD_LAZY | RTLD_GLOBAL);
        AILog(@"  dlopen %s -> %@", fws[i], h ? @"OK" : @"FAIL");
    }
    struct { const char *n; void **s; } tab[] = {
        {"IOHIDEventCreateDigitizerEvent",                  (void **)&gCreateDigitizer},
        {"IOHIDEventCreateDigitizerFingerEventWithQuality", (void **)&gCreateFingerQ},
        {"IOHIDEventCreateDigitizerFingerEvent",            (void **)&gCreateFingerOld},
        {"IOHIDEventAppendEvent",                           (void **)&gAppend},
        {"IOHIDEventSetIntegerValue",                       (void **)&gSetInt},
        {"IOHIDEventSetFloatValue",                         (void **)&gSetFloat},
        {"IOHIDEventSetSenderID",                           (void **)&gSetSender},
        {"IOHIDEventSystemClientCreate",                    (void **)&gClientCreate},
        {"IOHIDEventSystemClientCreateSimpleClient",        (void **)&gClientSimple},
        {"IOHIDEventSystemClientCreateWithType",            (void **)&gClientType},
        {"IOHIDEventSystemClientDispatchEvent",             (void **)&gDispatch},
        {"IOHIDEventSystemClientScheduleWithRunLoop",       (void **)&gSchedule},
        {"IOHIDEventSystemClientSetEventCallback",          (void **)&gSetCb},
    };
    int miss = 0;
    for (int i = 0; i < (int)(sizeof(tab)/sizeof(tab[0])); i++) {
        void *p = dlsym(RTLD_DEFAULT, tab[i].n);
        *(tab[i].s) = p;
        if (!p) miss++;
        AILog(@"  %-46s %@", tab[i].n, p ? @"OK" : @"❌缺失");
    }
    AILog(@"  缺失 %d 个", miss);
}

// ---------------------------------------------------------------------------
// 3. 事件构造：三种形态
// ---------------------------------------------------------------------------
static IOHIDEventRef AIMakeHand(IOHIDTime ts) {
    if (!gCreateDigitizer) return NULL;
    return gCreateDigitizer(kCFAllocatorDefault, ts, kTransducerHand, 0, 0,
                            kMaskTouch, 0, 0, 0, 0, 0, 0, 0, true, 0);
}

// 形态 A：复合 —— hand 容器 + 手指（18 参新签名），照 KIF/PTFakeTouch
static IOHIDEventRef AIMakeComposite(double x, double y, TPPhase ph) {
    if (!gCreateDigitizer || !gCreateFingerQ || !gAppend) return NULL;
    IOHIDTime ts = mach_absolute_time();
    uint32_t mask = (ph == TPMove) ? kMaskPosition : (kMaskRange | kMaskTouch);
    uint32_t touching = (ph == TPEnd) ? 0 : 1;
    IOHIDEventRef hand = AIMakeHand(ts);
    if (!hand) return NULL;
    if (gSetInt) gSetInt(hand, kFieldDigitizerIsDisplayIntegrated, 1);
    IOHIDEventRef f = gCreateFingerQ(kCFAllocatorDefault, ts, 1, 2, mask,
                                     x, y, 0,
                                     0,     // tipPressure
                                     0,     // twist
                                     5.0, 5.0, 1.0, 1.0, 1.0,
                                     touching, touching, 0);
    if (!f) { CFRelease(hand); return NULL; }
    if (gSetInt) gSetInt(f, kFieldDigitizerIsDisplayIntegrated, 1);
    gAppend(hand, f);
    CFRelease(f);
    return hand;
}

// 形态 B：裸手指（不包 hand），18 参
static IOHIDEventRef AIMakeBareFinger(double x, double y, TPPhase ph) {
    if (!gCreateFingerQ) return NULL;
    IOHIDTime ts = mach_absolute_time();
    uint32_t mask = (ph == TPMove) ? kMaskPosition : (kMaskRange | kMaskTouch);
    uint32_t touching = (ph == TPEnd) ? 0 : 1;
    return gCreateFingerQ(kCFAllocatorDefault, ts, 2, 2, mask, x, y, 0,
                          0, 0, 5.0, 5.0, 1.0, 1.0, 1.0, touching, touching, 0);
}

// 形态 C：裸手指，老式 10 参签名（连点器 v5.0.2 疑似用的就是这类）
static IOHIDEventRef AIMakeOldFinger(double x, double y, TPPhase ph) {
    if (!gCreateFingerOld) return NULL;
    IOHIDTime ts = mach_absolute_time();
    uint32_t mask = (ph == TPMove) ? kMaskPosition : (kMaskRange | kMaskTouch);
    return gCreateFingerOld(kCFAllocatorDefault, ts, 2, 2, mask, x, y, 0, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// 4. monitor 回环（客观判据 1）
// ---------------------------------------------------------------------------
static void AIMonCb(void *target, void *refcon, IOHIDEventSystemClientRef sender, IOHIDEventRef event) {
    (void)target; (void)refcon; (void)sender; (void)event;
    __sync_fetch_and_add(&gMonHits, 1);
}

static void *gMonClient = NULL;

static void AISetupMonitor(CFRunLoopRef rl) {
    AILog(@"==== [2] HID monitor 回环 ====");

    // iOS 16.1.2 实测：IOHIDEventSystemClientSetEventCallback 不导出。
    // 这里扫描一批候选名，找出本系统真正可用的回调注册 API —— 这本身就是要的答案之一。
    const char *cands[] = {
        "IOHIDEventSystemClientSetEventCallback",
        "IOHIDEventSystemClientSetEventCallbackWithType",
        "IOHIDEventSystemClientRegisterEventCallback",
        "_IOHIDEventSystemClientSetEventCallback",
        "IOHIDEventSystemClientSetEventCallbackAndDispatchQueue",
        "IOHIDEventSystemClientSetDispatchQueue",   // 2 参，不能当回调 setter 用，只探测
    };
    const char *used = NULL;
    for (int i = 0; i < 6; i++) {
        void *q = dlsym(RTLD_DEFAULT, cands[i]);
        AILog(@"  候选 %-52s -> %@", cands[i], q ? @"命中" : @"—");
        if (q && !used && i != 5) { gSetCb = (F_SetCb)q; used = cands[i]; }
    }
    if (!used) {
        AILog(@"  无可用回调注册 API → monitor 判据不可用，只剩 sendEvent hook 判据");
        return;
    }
    AILog(@"  采用回调 API: %s", used);

    if (!gClientType || !gSchedule) { AILog(@"  client/schedule 符号不全，跳过 monitor"); return; }
    @try {
        gMonClient = gClientType(kCFAllocatorDefault, 2 /*Monitor*/, NULL);
        AILog(@"  CreateWithType(Monitor) -> %@", gMonClient ? @"OK" : @"NULL");
        if (gMonClient) {
            gSetCb(gMonClient, (void *)AIMonCb, NULL, NULL);
            gSchedule(gMonClient, rl, kCFRunLoopDefaultMode);
            AILog(@"  回调已挂到 runloop");
        }
    } @catch (NSException *e) { AILog(@"  monitor 异常: %@", e); }
    if (!gMonClient && gClientSimple) {
        @try {
            gMonClient = gClientSimple(kCFAllocatorDefault, 2);
            AILog(@"  回退 CreateSimpleClient(2) -> %@", gMonClient ? @"OK" : @"NULL");
            if (gMonClient) { gSetCb(gMonClient, (void *)AIMonCb, NULL, NULL); gSchedule(gMonClient, rl, kCFRunLoopDefaultMode); }
        } @catch (NSException *e) { AILog(@"  回退异常: %@", e); }
    }
}

// ---------------------------------------------------------------------------
// 5. hook -[UIApplication sendEvent:]（客观判据 2）
// ---------------------------------------------------------------------------
static IMP gOrigSendEvent = NULL;

static BOOL gHooked = NO;

// 【铁证判据】touchesBegan 被调用 ≠ 按钮真的被按了。
// UIControl 的事件最终都走 -[UIApplication sendAction:to:from:forEvent:]，
// 这个被调用了，才说明按钮的 target-action 真的执行了。
static BOOL (*gOrigSendAction)(id, SEL, SEL, id, id, UIEvent *) = NULL;

static BOOL AIHookedSendAction(id self, SEL _cmd, SEL action, id target, id sender, UIEvent *ev) {
    if (action && target) {
        __sync_fetch_and_add(&gActionHits, 1);
        gLastAction = [NSString stringWithFormat:@"%@ %@",
                       NSStringFromClass([sender class]), NSStringFromSelector(action)];
    }
    if (gOrigSendAction) return gOrigSendAction(self, _cmd, action, target, sender, ev);
    return NO;
}

static void AIHookSendAction(void) {
    static BOOL hooked = NO;
    if (hooked) return;
    Class c = NSClassFromString(@"UIApplication");
    if (!c) return;
    SEL sel = @selector(sendAction:to:from:forEvent:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (!orig || orig == (IMP)AIHookedSendAction) return;
    class_addMethod(c, sel, orig, method_getTypeEncoding(m));
    gOrigSendAction = (BOOL (*)(id, SEL, SEL, id, id, UIEvent *))orig;
    method_setImplementation(class_getInstanceMethod(c, sel), (IMP)AIHookedSendAction);
    hooked = YES;
    AILog(@"  hook -[UIApplication sendAction:...] -> OK");
}

static void AIHookSendEvent(void) {
    // 必须去重：重复 hook 会让 gOrigSendEvent 变成我们自己的 block → 无限递归 → 崩
    if (gHooked) return;
    Class c = NSClassFromString(@"UIApplication");
    if (!c) return;
    Method m = class_getInstanceMethod(c, @selector(sendEvent:));
    if (!m) return;
    gOrigSendEvent = method_getImplementation(m);
    if (!gOrigSendEvent) return;
    SEL sel = @selector(sendEvent:);
    IMP newImp = imp_implementationWithBlock(^(id me, UIEvent *ev) {
        __sync_fetch_and_add(&gSendEventHits, 1);
        // ★ 兜底触发：只要 dylib 被加载，用户一碰屏幕就一定会启动自检。
        //   不依赖 constructor / +load / 通知 / 定时器任何一条路径。
        if (!gBooted) {
            static BOOL scheduled = NO;
            if (!scheduled) {
                scheduled = YES;
                gBootSrc = @"触摸(sendEvent hook)";
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try { AIBoot(); } @catch (NSException *e) { NSLog(@"[AI2] touch-boot ex %@", e); }
                });
            }
        }
        ((void (*)(id, SEL, id))gOrigSendEvent)(me, sel, ev);
    });
    method_setImplementation(m, newImp);
    gHooked = YES;
    AILog(@"  hook -[UIApplication sendEvent:] -> %@", gOrigSendEvent ? @"OK" : @"FAIL");
}

// UIApplication 类可能还没加载，轮询等它出现再 hook
static void AIHookWhenReady(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        static int tries = 0;
        Class c = NSClassFromString(@"UIApplication");
        if (!c || !class_getInstanceMethod(c, @selector(sendEvent:))) {
            if (tries++ < 60) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)),
                               dispatch_get_main_queue(), ^{ AIHookWhenReady(); });
            }
            return;
        }
        @try { AIHookSendEvent(); } @catch (NSException *e) {}
    });
}

// ---------------------------------------------------------------------------
// 6. 通用 NSInvocation 助手（调私有方法，类型安全）
// ---------------------------------------------------------------------------
// 依据 methodSignature 的真实参数类型装箱 —— arm64 下 int 走通用寄存器、
// double 走浮点寄存器，装箱类型搞错值就是垃圾（这是私有 API 调用最常见的坑）
static void AISetArg(NSInvocation *inv, NSMethodSignature *sig, NSUInteger idx, id a) {
    if (idx >= sig.numberOfArguments) return;
    const char *t = [sig getArgumentTypeAtIndex:idx];
    char c = t[0];
    // 跳过 const/r/n 等修饰符
    while (c == 'r' || c == 'n' || c == 'N' || c == 'o' || c == 'O' || c == 'R' || c == 'V') { t++; c = t[0]; }

    if (c == '{') {
        if (strncmp(t, @encode(CGPoint), strlen(@encode(CGPoint))) == 0) {
            CGPoint p = [a isKindOfClass:[NSValue class]] ? [(NSValue *)a CGPointValue] : CGPointZero;
            [inv setArgument:&p atIndex:idx]; return;
        }
        if (strncmp(t, @encode(CGRect), strlen(@encode(CGRect))) == 0) {
            CGRect r = [a isKindOfClass:[NSValue class]] ? [(NSValue *)a CGRectValue] : CGRectZero;
            [inv setArgument:&r atIndex:idx]; return;
        }
    }
    if (c == 'd' || c == 'f') {
        double v = [a respondsToSelector:@selector(doubleValue)] ? [a doubleValue] : 0.0;
        if (c == 'f') { float fv = (float)v; [inv setArgument:&fv atIndex:idx]; }
        else { [inv setArgument:&v atIndex:idx]; }
        return;
    }
    if (c == 'B') {
        BOOL v = [a respondsToSelector:@selector(boolValue)] ? [a boolValue] : NO;
        [inv setArgument:&v atIndex:idx]; return;
    }
    if (c == '@' || c == '#') {
        void *p = (__bridge void *)a; [inv setArgument:&p atIndex:idx]; return;
    }
    // 其余按 8 字节整数传
    long long v = [a respondsToSelector:@selector(longLongValue)] ? [a longLongValue] : 0;
    [inv setArgument:&v atIndex:idx];
}

static NSInvocation *AIMakeInvocation(id target, NSString *selName, NSArray *args) {
    if (!target) return nil;
    SEL s = NSSelectorFromString(selName);
    if (![target respondsToSelector:s]) return nil;
    NSMethodSignature *sig = [target methodSignatureForSelector:s];
    if (!sig) return nil;
    if (sig.numberOfArguments < args.count + 2) return nil;
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.selector = s; inv.target = target;
    for (NSUInteger i = 0; i < args.count; i++) AISetArg(inv, sig, i + 2, args[i]);
    return inv;
}

static BOOL AIInvoke(id target, NSString *selName, NSArray *args) {
    NSInvocation *inv = AIMakeInvocation(target, selName, args);
    if (!inv) return NO;
    @try { [inv invoke]; return YES; } @catch (NSException *e) { AILog(@"    (invoke %@ 异常 %@)", selName, e.reason); return NO; }
}

static id AIInvokeRet(id target, NSString *selName, NSArray *args) {
    NSInvocation *inv = AIMakeInvocation(target, selName, args);
    if (!inv) return nil;
    @try { [inv invoke]; } @catch (NSException *e) { return nil; }
    const char *rt = inv.methodSignature.methodReturnType;
    if (rt[0] != '@' && rt[0] != '#') return nil;
    void *ret = NULL;
    @try { [inv getReturnValue:&ret]; } @catch (NSException *e) { return nil; }
    return ret ? (__bridge id)ret : nil;
}

// ---------------------------------------------------------------------------
// 7. 进程内 UIKit 合成触摸（形态 2）
// ---------------------------------------------------------------------------
static BOOL AITapInProcess(CGPoint pt) {
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return NO;
    UIWindow *w = AIHostWindow();
    if (!w) return NO;

    UITouch *t = [UITouch alloc];
    NSArray *mkSels = @[@"initAtPoint:inWindow:", @"initWithPoint:inWindow:", @"_initWithPoint:inWindow:"];
    UITouch *touch = nil;
    for (NSString *sn in mkSels) {
        id r = AIInvokeRet(t, sn, @[[NSValue valueWithCGPoint:pt], w]);
        if (r) { touch = r; AILog(@"  触摸构造命中: %@", sn); break; }
    }
    if (!touch) { AILog(@"  ❌ UITouch 私有构造全部失败"); return NO; }

    AIInvoke(touch, @"setPhase:",      @[@(UITouchPhaseBegan)]);
    AIInvoke(touch, @"setTimestamp:",  @[@([[NSDate date] timeIntervalSince1970])]);
    AIInvoke(touch, @"setTapCount:",   @[@1]);
    AIInvoke(touch, @"setWindow:",     @[w]);
    AIInvoke(touch, @"_setLocationInWindow:resetPrevious:", @[[NSValue valueWithCGPoint:pt], @YES]);

    UIEvent *ev = nil;
    for (NSString *sn in @[@"initWithTouch:", @"_initWithTouch:"]) {
        id r = AIInvokeRet([UIEvent alloc], sn, @[touch]);
        if (r) { ev = r; AILog(@"  UIEvent 构造命中: %@", sn); break; }
    }
    if (!ev) { AILog(@"  ❌ UIEvent 私有构造失败"); return NO; }
    @try { [app sendEvent:ev]; return YES; } @catch (NSException *e) { AILog(@"  sendEvent 异常 %@", e); return NO; }
}

// ---------------------------------------------------------------------------
// 7b. 伪造 Touch/Event + 直接分发
//
//  iOS 16.1.2 实测：UITouch 的私有构造 selector（initAtPoint:inWindow: 等）
//  全部不存在 → 走「先构造真 UITouch 再 sendEvent」这条路是死路。
//  但 UITouch / UIEvent 本身是普通 ObjC 类，可以【子类化并覆盖 getter】，
//  然后直接调用目标 view 的 touchesBegan:/touchesEnded: —— 自己完成 hit-test
//  和分发，完全不依赖任何私有构造 API。
//  对 Unity / Cocos 这类游戏，它们的触摸入口就是 UnityView 的 touchesBegan，
//  所以直接调它就能把触摸喂进去。
// ---------------------------------------------------------------------------
@interface AIFakeTouch : UITouch
@property (nonatomic, assign) CGPoint       aiPoint;   // 相对于 aiView 的坐标
@property (nonatomic, weak)   UIView       *aiView;
@property (nonatomic, weak)   UIWindow     *aiWindow;
@property (nonatomic, assign) UITouchPhase  aiPhase;
@property (nonatomic, assign) NSTimeInterval aiTime;
@end

@implementation AIFakeTouch
// ★ v13：走 sendEvent 路径时 aiView 是 nil（UIKit 自己决定发给谁）。
//   此时 aiPoint 存的是【window 坐标】，用它往目标 view 换算。
- (CGPoint)locationInView:(UIView *)v {
    if (!v) return self.aiPoint;
    if (!self.aiView) {
        // aiPoint 是 window 坐标 —— 从 window 换算到 v
        UIWindow *win = self.aiWindow ?: v.window;
        if (win && v != win) return [win convertPoint:self.aiPoint toView:v];
        return self.aiPoint;
    }
    if (v == self.aiView) return self.aiPoint;
    return [self.aiView convertPoint:self.aiPoint toView:v];
}
- (CGPoint)previousLocationInView:(UIView *)v          { return [self locationInView:v]; }
// Unity / Cocos 有些版本读 preciseLocationInView，父类实现会去读未初始化的 ivar，必须挡掉
- (CGPoint)preciseLocationInView:(UIView *)v           { return [self locationInView:v]; }
- (CGPoint)precisePreviousLocationInView:(UIView *)v   { return [self locationInView:v]; }
- (UITouchPhase)phase       { return self.aiPhase; }
- (UIView *)view            { return self.aiView; }
- (UIWindow *)window        { return self.aiWindow ?: self.aiView.window; }
- (NSTimeInterval)timestamp { return self.aiTime; }
- (NSUInteger)tapCount      { return 1; }
- (UITouchType)type         { return UITouchTypeDirect; }
- (CGFloat)force                { return 1.0; }
- (CGFloat)maximumPossibleForce { return 1.0; }
- (CGFloat)majorRadius          { return 5.0; }
- (CGFloat)majorRadiusTolerance { return 0.0; }
- (CGFloat)minorRadius          { return 5.0; }
- (CGFloat)altitudeAngle        { return 1.5707963; }
- (CGFloat)azimuthAngle         { return 0.0; }
- (CGVector)azimuthUnitVectorInView:(UIView *)v { CGVector g; g.dx = 1.0; g.dy = 0.0; return g; }
- (NSArray *)gestureRecognizers  { return nil; }
- (UITouchProperties)estimatedProperties                   { return 0; }
- (UITouchProperties)estimatedPropertiesExpectingUpdates   { return 0; }
- (NSNumber *)estimationUpdateIndex                        { return nil; }
@end

@interface AIFakeEvent : UIEvent
@property (nonatomic, strong) NSSet         *aiTouches;
@property (nonatomic, assign) NSTimeInterval aiTime;
@end

@implementation AIFakeEvent
- (NSSet *)allTouches                       { return self.aiTouches; }
- (NSSet *)touchesForView:(UIView *)v       { return self.aiTouches; }
- (NSSet *)touchesForWindow:(UIWindow *)w   { return self.aiTouches; }
- (UIEventType)type                         { return UIEventTypeTouches; }
- (UIEventSubtype)subtype                   { return UIEventSubtypeNone; }
- (NSTimeInterval)timestamp                 { return self.aiTime; }
@end

// 直接把触摸喂给指定 view（绕过 UIKit 分发）
static BOOL AIDispatchFakeToView(UIView *target, CGPoint ptInTarget) {
    if (!target) return NO;
    AIFakeTouch *t = [AIFakeTouch new];
    t.aiPoint = ptInTarget;
    t.aiView  = target;
    t.aiTime  = [[NSDate date] timeIntervalSince1970];

    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one;
    ev.aiTime    = t.aiTime;

    @try {
        t.aiPhase = UITouchPhaseBegan;
        [target touchesBegan:one withEvent:ev];
        t.aiPhase = UITouchPhaseMoved;
        [target touchesMoved:one withEvent:ev];
        t.aiPhase = UITouchPhaseEnded;
        [target touchesEnded:one withEvent:ev];
        return YES;
    } @catch (NSException *ex) {
        AILog(@"  分发异常: %@", ex.reason);
        return NO;
    }
}

// ---------------------------------------------------------------------------
// 7c. v13：走 UIApplication.sendEvent: 的「正规」伪造触摸
//
//   为什么必须这么改（v12 的致命缺陷）：
//     v12 是 hitTest 找到目标 view 后【直接调它的 touchesBegan:】。
//     这跳过了 UIKit 完整的事件链路：
//         UIApplication.sendEvent: → UIWindow.sendEvent:
//           → hitTest → 【手势识别器链】 → 才轮到 view.touchesBegan:
//     后果（真机上实测到的）：
//       · 计数 se（sendEvent hook）永远是 0 —— 事件根本没经过 sendEvent
//       · 微信 TabBar 点击无效、视图树 227 行一行不变
//       · 只有那些「自己在 touchesBegan 里写逻辑」的视图（如自建的测试 view、
//         以及部分游戏引擎的 UnityView）才有反应
//
//   正确做法：把伪造的 UIEvent 交给 UIApplication.sendEvent:，
//   让 UIKit 自己去 hitTest、自己走手势识别、自己决定发给谁。
//   这样 UITabBar / UIControl / 手势 才能正常响应。
//
//   注意：AIFakeTouch / AIFakeEvent 这两个子类不用改 —— 它们的 getter 覆盖
//   本来就是完整的，UIKit 内部也是通过这些 getter 读值的。
// ---------------------------------------------------------------------------
static BOOL AISendFakeEventToApp(AIFakeTouch *t, AIFakeEvent *ev) {
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) { AILog(@"    ❌ 无 UIApplication"); return NO; }
    @try {
        // 优先走 hook 前的原始实现，避免我们自己的 hook 递归。
        // IMP 是函数指针不是对象，必须强转成正确签名再调。
        if (gOrigSendEvent) {
            ((void (*)(id, SEL, id))gOrigSendEvent)(app, @selector(sendEvent:), ev);
            __sync_fetch_and_add(&gSendEventHits, 1);   // 手工补计数：绕过了 hook 自己
            return YES;
        }
        [app sendEvent:ev];
        return YES;
    } @catch (NSException *e) {
        AILog(@"    ❌ sendEvent 异常: %@", e.reason);
        return NO;
    }
}

// dt：给 UIKit 处理每一拍的时间，单位秒（必须泵 runloop，不能用 usleep —— 
//     在后台线程 usleep 会让主线程没机会跑，事件永远不被处理）
static BOOL AIDispatchFakeViaSendEvent(CGPoint screenPt, int steps, double dt) {
    UIWindow *w = AIHostWindow();
    if (!w) { AILog(@"    ❌ 无可用 window"); return NO; }

    // 坐标一律用【window 坐标系】（sendEvent 之后 UIKit 自己按各 view 换算）
    CGPoint p0 = screenPt;
    if (w.bounds.size.height > 0 && screenPt.y <= w.bounds.size.height) p0 = screenPt;  // 已是 window 坐标

    int seBefore = gSendEventHits;
    int actBefore = gActionHits;

    AIFakeTouch *t = [AIFakeTouch new];
    t.aiWindow = w;
    t.aiView   = nil;
    t.aiTime   = [[NSDate date] timeIntervalSince1970];

    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one;
    ev.aiTime    = t.aiTime;

    // —— Began ——
    t.aiPoint = p0;
    t.aiPhase = UITouchPhaseBegan;
    if (!AISendFakeEventToApp(t, ev)) return NO;
    AISleep(dt);

    // —— Moved（中间过程；很多手势识别器要求有移动轨迹才会触发）——
    for (int i = 1; i <= steps; i++) {
        t.aiPoint = p0;                 // 点击不位移，但补 Moved 让识别器「活」起来
        t.aiPhase = UITouchPhaseMoved;
        AISendFakeEventToApp(t, ev);
        AISleep(dt);
    }

    // —— Ended ——
    t.aiPoint = p0;
    t.aiPhase = UITouchPhaseEnded;
    AISendFakeEventToApp(t, ev);
    AISleep(dt);

    int dse = gSendEventHits - seBefore;
    int dact = gActionHits - actBefore;
    AILog(@"    sendEvent 路径: 进入 sendEvent %+d 次, sendAction %+d 次", dse, dact);
    return (dse > 0);
}

// ---------------------------------------------------------------------------
// 7d. v14：probe / tapui —— 先看清「点的到底是什么」，再决定怎么触发
//
//   v13 的遗留问题：se 计数确实涨了（事件进了 sendEvent），但微信 TabBar
//   纹丝不动 —— 说明 UIKit 内部（C++ 层）没把伪造的 UIEvent 路由到 TabBar。
//   继续瞎猜没意义，先做两件事：
//     probe —— 报告某坐标【实际命中】的 view：类名、屏幕坐标、是否 UIControl、
//              沿 superview 链最近的可触发控件。把"我以为点的是谁"变成事实。
//     tapui —— 对命中控件直接 sendActionsForControlEvents:UIControlEventTouchUpInside。
//              这不是"模拟手指"，但效果等价于用户点击按钮，且 100% 可靠。
// ---------------------------------------------------------------------------
static NSDictionary *AIProbeAt(CGPoint pt) {
    __block NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"pt"] = [NSString stringWithFormat:@"(%.0f,%.0f)", pt.x, pt.y];
    UIWindow *w = AIHostWindow();
    if (!w) { d[@"err"] = @"无 window"; return d; }
    d[@"win"] = NSStringFromCGRect(w.bounds);

    id hit = nil;
    @try { hit = [w hitTest:pt withEvent:nil]; } @catch (id e) {}
    if (!hit) { d[@"err"] = @"hitTest 返回 nil"; return d; }

    UIView *v = (UIView *)hit;
    CGRect screen = [v convertRect:v.bounds toView:nil];
    d[@"hit"]      = NSStringFromClass([v class]);
    d[@"hitFrame"] = NSStringFromCGRect(screen);
    d[@"isControl"] = @([v isKindOfClass:[UIControl class]]);

    // 沿 superview 找最近的可触发控件
    UIView *p = v; int up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UIControl class]]) {
            d[@"ctrl"]      = NSStringFromClass([p class]);
            d[@"ctrlFrame"] = NSStringFromCGRect([p convertRect:p.bounds toView:nil]);
            d[@"ctrlUp"]    = @(up);
            d[@"enabled"]   = @([(UIControl *)p isEnabled]);
            d[@"ctrlCenter"] = [NSString stringWithFormat:@"(%.0f,%.0f)",
                                CGRectGetMidX([p convertRect:p.bounds toView:nil]),
                                CGRectGetMidY([p convertRect:p.bounds toView:nil])];
            break;
        }
        p = p.superview; up++;
    }
    if (!d[@"ctrl"]) d[@"ctrl"] = @"(沿父链 12 层内无 UIControl)";
    return d;
}

// 直接触发控件的 action（等价于用户点击这个按钮）
static BOOL AITapUIControlAt(CGPoint pt, NSString **outDesc) {
    UIWindow *w = AIHostWindow();
    if (!w) return NO;
    id hit = nil;
    @try { hit = [w hitTest:pt withEvent:nil]; } @catch (id e) {}
    UIView *v = (UIView *)hit;
    if (!v) return NO;

    UIControl *c = nil;
    UIView *p = v; int up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UIControl class]]) { c = (UIControl *)p; break; }
        p = p.superview; up++;
    }
    if (!c) { if (outDesc) *outDesc = @"命中链上无 UIControl"; return NO; }

    int a0 = gActionHits;
    @try {
        [c sendActionsForControlEvents:UIControlEventTouchUpInside];
    } @catch (NSException *e) {
        if (outDesc) *outDesc = [@"sendActions 异常: " stringByAppendingString:(e.reason ?: @"?")];
        return NO;
    }
    if (outDesc) {
        *outDesc = [NSString stringWithFormat:@"%@ (第%d层父) sendAction+%d",
                    NSStringFromClass([c class]), up, gActionHits - a0];
    }
    return YES;
}

// 让 runloop 转一会儿，给 UIKit 处理触摸的机会（别用 usleep 卡死主线程）
static void AISleep(double sec) {
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:sec]];
}

// 【iOS 13+ 大坑】用了 SceneDelegate 的 App，window 挂在每个 UIWindowScene 上，
// [UIApplication sharedApplication].windows 对它们是【空数组】，keyWindow 也常是 nil。
// v4 就是栽在这：拿不到 App 自己的 window，于是所有点击/截图全落在我们自己盖的屏上。
static NSArray *AIAllWindows(void) {
    NSMutableArray *out = [NSMutableArray array];
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return out;

    if ([app respondsToSelector:@selector(connectedScenes)]) {
        id scenes = [app performSelector:@selector(connectedScenes)];
        if ([scenes isKindOfClass:[NSSet class]]) {
            for (id sc in (NSSet *)scenes) {
                if (![sc respondsToSelector:@selector(windows)]) continue;
                id ws = [sc performSelector:@selector(windows)];
                if (![ws isKindOfClass:[NSArray class]]) continue;
                for (id w in (NSArray *)ws) {
                    if ([w isKindOfClass:[UIWindow class]] && ![out containsObject:w]) [out addObject:w];
                }
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in app.windows) if (![out containsObject:w]) [out addObject:w];
#pragma clang diagnostic pop
    return out;
}

// v20：数一棵视图树有多少个「可见」节点 —— 用来判断哪个窗口才是 App 真正在显示的。
//
//   ★ 踩坑（快手）：快手上有一个【全屏但内容为空】的窗口抢到了 isKeyWindow，
//     旧逻辑「见到 keyWindow 就 return」于是 tree / text 全抓到一个光秃秃的
//     UIView (0,0,390,844)，界面文字一条都读不到。微信目前侥幸没踩到，
//     但只要宿主 App 多开一个空窗口就会复现，所以这里改成按内容量选。
static int AICountNodes(UIView *v, int depth, int maxDepth, int cap) {
    if (!v || depth > maxDepth) return 0;
    if (v.hidden || v.alpha < 0.01) return 0;
    int n = 1;
    for (UIView *c in v.subviews) {
        n += AICountNodes(c, depth + 1, maxDepth, cap);
        if (n >= cap) break;                 // 够多就打住，别把主线程拖住
    }
    return n;
}

// v23：允许外部指定「用第几个窗口」（wins 列出来的序号）。
//  -1 = 自动。宿主 App 把侧边栏/弹层挂在别的窗口时，靠它切过去。
static int gWinIdx = -1;

// v23：候选窗口列表（过滤掉我们自己盖的东西），顺序稳定，wins 与 win=N 共用
static NSArray *AIHostWindows(void) {
    NSMutableArray *out = [NSMutableArray array];
    for (UIWindow *w in AIAllWindows()) {
        if (w == gOverlayWindow) continue;
        if (w == gHudWindow) continue;          // v10 顶端状态条，别让它冒充 App 窗口
        if (w == gFloatWindow) continue;        // v20 悬浮球
        NSString *cn = NSStringFromClass([w class]);
        if ([cn rangeOfString:@"TextEffects"].location != NSNotFound) continue;
        if ([cn rangeOfString:@"RemoteKeyboard"].location != NSNotFound) continue;
        [out addObject:w];
    }
    return out;
}

// v23：命中测试必须从【最上面的窗口】往下找。快手的侧边栏挂在后面加的窗口上，
// 只问 keyWindow / 内容最多的窗口，hitTest 会被底层那个全屏大窗口截胡。
static UIView *AIHitAtPoint(CGPoint pt) {
    NSArray *ws = AIHostWindows();
    for (NSInteger i = ws.count - 1; i >= 0; i--) {
        UIWindow *w = ws[i];
        if (w.hidden || w.alpha < 0.01) continue;
        @try {
            UIView *v = [w hitTest:pt withEvent:nil];
            if (v) return v;
        } @catch (id e) {}
    }
    return nil;
}

// 找「App 自己的」窗口：排除我们盖的屏、排除键盘/文本特效窗口
static UIWindow *AIHostWindow(void) {
    NSArray *ws = AIHostWindows();
    if (gWinIdx >= 0 && gWinIdx < (int)ws.count) {
        UIWindow *w = ws[gWinIdx];
        AILog(@"  [win] 指定窗口 #%d = %@", gWinIdx, NSStringFromClass([w class]));
        return w;
    }
    UIWindow *best = nil, *key = nil;
    int bestN = 0;
    for (UIWindow *w in ws) {
        if (w.hidden || w.alpha < 0.01) continue;
        int n = AICountNodes(w, 0, 14, 600);
        if (w.isKeyWindow) key = w;
        if (n > bestN) { bestN = n; best = w; }
    }
    // keyWindow 只要不是空壳（≥8 个节点）就尊重它，否则退回「内容最多」的那个
    if (key) {
        int kn = AICountNodes(key, 0, 14, 600);
        if (kn >= 8) return key;
        AILog(@"  ⚠️ keyWindow %@ 只有 %d 个节点（空壳），改用内容最多的窗口(%d)",
              NSStringFromClass([key class]), kn, bestN);
    }
    return best ?: key ?: gOverlayWindow;
}

// ---------------------------------------------------------------------------
// 7d-x. v23：gtap —— 手势直达，专治「自绘控件点不动」
//
//   ★ 踩坑（快手）：侧边栏每个格子命中 TK_VIEW_TKView，父链 12 层里
//     【既没有 UIControl，也不是 UITableViewCell / UICollectionViewCell】。
//     于是 tapui（sendActionsForControlEvents）哑火、pick（走 delegate）也哑火，
//     界面纹丝不动。这种自绘控件的点击，实际是靠挂在 view 上的
//     UITapGestureRecognizer 完成的 —— 那就直接把它的 target-action 拿出来调。
//
//   三板斧，依次降级：
//     1) runtime 读 UIGestureRecognizer 的私有 _targets，取 target/action 直接 perform
//     2) KVC 强写 state = Recognized，让 UIKit 自己发 action
//     3) 都没有就退回正规合成触摸（UIApplication sendEvent）
// ---------------------------------------------------------------------------

// 把某个 view（含父链若干层）上的手势罗列出来，诊断用
static NSString *AIChainOf(UIView *v) {
    NSMutableString *s = [NSMutableString string];
    UIView *p = v; int up = 0;
    while (p && up < 16) {
        CGRect f = [p convertRect:p.bounds toView:nil];
        NSMutableString *gs = [NSMutableString string];
        @try {
            for (UIGestureRecognizer *gr in p.gestureRecognizers) {
                [gs appendFormat:@"%@%@", gs.length ? @"," : @"",
                 NSStringFromClass([gr class])];
            }
        } @catch (id e) {}
        [s appendFormat:@"%2d %@ 框(%.0f,%.0f,%.0f,%.0f)%@\n",
         up, NSStringFromClass([p class]), f.origin.x, f.origin.y, f.size.width, f.size.height,
         gs.length ? [@" 手势:" stringByAppendingString:gs] : @""];
        p = p.superview; up++;
    }
    return s;
}

// 从手势里抠出 target/action 并触发。返回 YES 表示确实发了 action。
static BOOL AIFireGesture(UIGestureRecognizer *gr) {
    if (!gr || !gr.enabled) return NO;
    // 1) 私有 _targets：数组里每个元素是 UIGestureRecognizerTarget，含 _target / _action
    @try {
        Ivar iv = class_getInstanceVariable([gr class], "_targets");
        if (iv) {
            id arr = object_getIvar(gr, iv);
            if ([arr isKindOfClass:[NSArray class]]) {
                BOOL fired = NO;
                for (id t in (NSArray *)arr) {
                    id tgt = nil; SEL act = NULL;
                    Ivar ti = class_getInstanceVariable([t class], "_target");
                    Ivar ai = class_getInstanceVariable([t class], "_action");
                    if (ti) tgt = object_getIvar(t, ti);
                    if (ai) {
                        // SEL 不是对象，不能用 object_getIvar（ARC 下会炸），直接按偏移取
                        char *base = (char *)(__bridge void *)t;
                        act = *(SEL *)(base + ivar_getOffset(ai));
                    }
                    if (tgt && act && [tgt respondsToSelector:act]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                        [tgt performSelector:act withObject:gr];
#pragma clang diagnostic pop
                        fired = YES;
                        AILog(@"    手势 action 已触发: %@ -> %@",
                              NSStringFromClass([tgt class]), NSStringFromSelector(act));
                    }
                }
                if (fired) return YES;
            }
        }
    } @catch (id e) {}

    // 2) KVC 强写 state，让 UIKit 自己发 action
    @try {
        [gr setValue:@(UIGestureRecognizerStateRecognized) forKey:@"state"];
        AILog(@"    手势 state 已置 Recognized（KVC 兜底）");
        return YES;
    } @catch (id e) {}
    return NO;
}

// 在指定屏幕坐标上，沿父链找到第一个可点的手势并触发
static NSDictionary *AIGestureTapAt(CGPoint pt) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    UIView *hit = AIHitAtPoint(pt);
    if (!hit) { d[@"ok"] = @NO; d[@"err"] = @"该坐标没命中任何 view"; return d; }
    d[@"hit"] = NSStringFromClass([hit class]);

    // 先给一次 UIControl 的机会（最正统）
    UIControl *c = nil; UIView *p = hit; int up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UIControl class]]) { c = (UIControl *)p; break; }
        p = p.superview; up++;
    }
    if (c) {
        int a0 = gActionHits;
        @try { [c sendActionsForControlEvents:UIControlEventTouchUpInside]; } @catch (id e) {}
        d[@"how"] = @"UIControl"; d[@"ctrl"] = NSStringFromClass([c class]);
        d[@"ok"] = @(gActionHits - a0 > 0);
        return d;
    }

    // 再找手势：命中 view 自己 → 父链 16 层
    p = hit; up = 0;
    while (p && up < 16) {
        @try {
            for (UIGestureRecognizer *gr in p.gestureRecognizers) {
                if (![gr isKindOfClass:[UITapGestureRecognizer class]] &&
                    ![gr isKindOfClass:[UILongPressGestureRecognizer class]]) continue;
                if (AIFireGesture(gr)) {
                    d[@"ok"] = @YES;
                    d[@"how"] = @"gesture";
                    d[@"gr"] = NSStringFromClass([gr class]);
                    d[@"up"] = @(up);
                    d[@"on"] = NSStringFromClass([p class]);
                    return d;
                }
            }
        } @catch (id e) {}
        p = p.superview; up++;
    }

    // 都没有：退回正规合成触摸（UIKit 自己走 hitTest + 手势识别）
    BOOL via = NO;
    @try { via = AIDispatchFakeViaSendEvent(pt, 2, 0.03); } @catch (id e) {}
    d[@"ok"] = @(via); d[@"how"] = via ? @"sendEvent" : @"none";
    d[@"err"] = via ? nil : @"这条父链上既无 UIControl 也无手势，合成触摸也没确认";
    return d;
}

// ---------------------------------------------------------------------------
// 7e. v15：rows / pick / picktxt —— 专治「表格行点不动」
//
//   v14 的 tapui 只对 UIControl 有效。但微信「发现」页每一行是 UITableViewCell，
//   点击靠的是 UITableViewDelegate 的 tableView:didSelectRowAtIndexPath:，
//   父链上一个 UIControl 都没有 —— tapui 直接哑火，界面纹丝不动（实测确认）。
//   三条新指令把"看行"和"点行"补齐：
//     rows    —— 列出屏幕上所有表格的可见行：行号、文本、【屏幕中心点】
//                （有了它就不用再逐个 probe 猜坐标了）
//     pick    —— 给屏幕坐标，找到那一行，直接调 delegate 的 didSelectRowAtIndexPath:
//     picktxt —— 给文本，找到含该文本的行并选中（最省事，一步到位）
// ---------------------------------------------------------------------------

// 递归收集 view 里的可见文本（标签/输入框），用来判断这一行是不是我要找的
static void AICollectTexts(UIView *v, NSMutableArray *a, int depth, int maxDepth) {
    if (!v || depth > maxDepth || !v.window) return;
    if (!AIBudgetTake()) return;            // v23：同上
    @try {
        NSString *t = nil;
        if ([v isKindOfClass:[UILabel class]])          t = ((UILabel *)v).text;
        else if ([v isKindOfClass:[UITextView class]])  t = ((UITextView *)v).text;
        else if ([v isKindOfClass:[UITextField class]]) t = ((UITextField *)v).text;
        if (t.length) [a addObject:t];
        for (UIView *s in v.subviews) AICollectTexts(s, a, depth + 1, maxDepth);
    } @catch (id e) {}
}

static NSString *AITextsOf(UIView *v) {
    NSMutableArray *a = [NSMutableArray array];
    AICollectTexts(v, a, 0, 6);
    return [a componentsJoinedByString:@" | "];
}

// v22：快手侧边栏/首页大量用 UICollectionView（TKListView 底层就是它），
//      cell 里既没有 UIControl 也不是 UITableViewCell —— 旧 pick 统统点不动。
static void AIFindCVRec(UIView *v, NSMutableArray *out, int depth) {
    if (!v || depth > 12) return;
    @try {
        if ([v isKindOfClass:[UICollectionView class]] && ![out containsObject:v]) [out addObject:v];
        for (UIView *s in v.subviews) AIFindCVRec(s, out, depth + 1);
    } @catch (id e) {}
}
static NSArray *AIVisibleCollectionViews(void) {
    NSMutableArray *out = [NSMutableArray array];
    for (UIWindow *w in AIAllWindows()) {
        if (w == gOverlayWindow || w == gHudWindow) continue;
        AIFindCVRec(w, out, 0);
    }
    return out;
}
static UICollectionView *AICollectionViewOfCell(UICollectionViewCell *cell) {
    UIView *p = cell.superview; int up = 0;
    while (p && up < 15) {
        if ([p isKindOfClass:[UICollectionView class]]) return (UICollectionView *)p;
        p = p.superview; up++;
    }
    for (UICollectionView *cv in AIVisibleCollectionViews())
        if ([[cv visibleCells] containsObject:cell]) return cv;
    return nil;
}
static NSDictionary *AIPickCellInCollection(UICollectionViewCell *cell, NSMutableDictionary *d) {
    d[@"cell"]      = NSStringFromClass([cell class]);
    d[@"cellFrame"] = NSStringFromCGRect([cell convertRect:cell.bounds toView:nil]);
    d[@"cellText"]  = AITextsOf(cell);

    UICollectionView *cv = AICollectionViewOfCell(cell);
    if (!cv) { d[@"ok"] = @NO; d[@"err"] = @"找不到 cell 所属的 UICollectionView"; return d; }
    d[@"cv"] = NSStringFromClass([cv class]);

    NSIndexPath *ip = nil;
    @try { ip = [cv indexPathForCell:cell]; } @catch (id e) {}
    if (!ip) {
        @try {
            CGPoint c = cell.center;
            CGPoint inCv = [cv convertPoint:c fromView:cell.superview];
            ip = [cv indexPathForItemAtPoint:inCv];
        } @catch (id e) {}
    }
    if (!ip) { d[@"ok"] = @NO; d[@"err"] = @"indexPathForCell 返回 nil"; return d; }
    d[@"section"] = @(ip.section); d[@"item"] = @(ip.item);

    id dlg = nil;
    @try { dlg = cv.delegate; } @catch (id e) {}
    d[@"delegate"] = dlg ? NSStringFromClass([dlg class]) : @"(nil)";

    SEL sel = @selector(collectionView:didSelectItemAtIndexPath:);
    BOOL called = NO;
    if (dlg && [dlg respondsToSelector:sel]) {
        @try {
            NSMethodSignature *sig = [dlg methodSignatureForSelector:sel];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.selector = sel;
            __unsafe_unretained UICollectionView *cvArg = cv;
            __unsafe_unretained NSIndexPath *ipArg = ip;
            [inv setArgument:&cvArg atIndex:2];
            [inv setArgument:&ipArg atIndex:3];
            [inv invokeWithTarget:dlg];
            called = YES;
            d[@"how"] = @"delegate collectionView:didSelectItemAtIndexPath:";
        } @catch (NSException *e) { d[@"invokeErr"] = e.reason ?: @"?"; }
    }
    if (!called) {
        @try {
            [cv selectItemAtIndexPath:ip animated:NO scrollPosition:UICollectionViewScrollPositionNone];
            called = YES;
            d[@"how"] = @"selectItemAtIndexPath 兜底（无 delegate）";
        } @catch (id e) {}
    }
    if (!d[@"how"]) d[@"how"] = @"两种都没调到";
    d[@"ok"] = @(called);
    return d;
}

static void AIFindTVRec(UIView *v, NSMutableArray *out, int depth) {
    if (!v || depth > 12) return;
    @try {
        if ([v isKindOfClass:[UITableView class]] && ![out containsObject:v]) [out addObject:v];
        for (UIView *s in v.subviews) AIFindTVRec(s, out, depth + 1);
    } @catch (id e) {}
}

static NSArray *AIVisibleTableViews(void) {
    NSMutableArray *out = [NSMutableArray array];
    for (UIWindow *w in AIAllWindows()) {
        if (w == gOverlayWindow || w == gHudWindow) continue;
        AIFindTVRec(w, out, 0);
    }
    return out;
}

// 【选中某一行】—— 表格行不是 UIControl，只能走 delegate
static NSDictionary *AIPickCellIn(UITableViewCell *cell, NSMutableDictionary *d) {
    d[@"cell"]      = NSStringFromClass([cell class]);
    d[@"cellFrame"] = NSStringFromCGRect([cell convertRect:cell.bounds toView:nil]);
    d[@"cellText"]  = AITextsOf(cell);

    // 1) 找这块 cell 属于哪个 tableView
    UITableView *tv = nil;
    UIView *p = cell.superview; int up = 0;
    while (p && up < 15) {
        if ([p isKindOfClass:[UITableView class]]) { tv = (UITableView *)p; break; }
        p = p.superview; up++;
    }
    if (!tv) {   // 兜底：微信有些容器把 cell 挂在别的层级下，全局扫一遍
        for (UITableView *t in AIVisibleTableViews()) {
            if ([[t visibleCells] containsObject:cell]) { tv = t; break; }
        }
    }
    if (!tv) { d[@"ok"] = @NO; d[@"err"] = @"找不到 cell 所属的 TableView"; return d; }
    d[@"tv"] = NSStringFromClass([tv class]);

    // 2) 拿 indexPath
    NSIndexPath *ip = nil;
    @try { ip = [tv indexPathForCell:cell]; } @catch (id e) {}
    if (!ip) { d[@"ok"] = @NO; d[@"err"] = @"indexPathForCell 返回 nil"; return d; }
    d[@"row"] = @(ip.row); d[@"section"] = @(ip.section);

    // 3) 调 delegate 的 didSelectRowAtIndexPath:（这才是"点中这一行"的真正入口）
    id dlg = nil;
    @try { dlg = tv.delegate; } @catch (id e) {}
    d[@"delegate"] = dlg ? NSStringFromClass([dlg class]) : @"(nil)";

    SEL sel = @selector(tableView:didSelectRowAtIndexPath:);
    BOOL called = NO;
    if (dlg && [dlg respondsToSelector:sel]) {
        @try {
            NSMethodSignature *sig = [dlg methodSignatureForSelector:sel];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.selector = sel;
            __unsafe_unretained UITableView *tvArg = tv;
            __unsafe_unretained NSIndexPath *ipArg = ip;
            [inv setArgument:&tvArg atIndex:2];
            [inv setArgument:&ipArg atIndex:3];
            [inv invokeWithTarget:dlg];
            called = YES;
        } @catch (NSException *e) { d[@"invokeErr"] = e.reason ?: @"?"; }
    }
    if (!called) {   // 兜底：少数页面靠 selectRow 自己转发
        @try {
            [tv selectRowAtIndexPath:ip animated:NO scrollPosition:UITableViewScrollPositionNone];
            called = YES;
            d[@"how"] = @"selectRowAtIndexPath 兜底";
        } @catch (id e) {}
    }
    if (!d[@"how"]) d[@"how"] = called ? @"delegate didSelectRowAtIndexPath" : @"两种都没调到";
    d[@"ok"] = @(called);
    return d;
}

// 按屏幕坐标选中一行（父链上有 UIControl 就沿用 v14 的 sendActions）
static NSDictionary *AIPickAt(CGPoint pt) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"pt"] = [NSString stringWithFormat:@"(%.0f,%.0f)", pt.x, pt.y];
    UIWindow *w = AIHostWindow();
    if (!w) { d[@"ok"] = @NO; d[@"err"] = @"无 window"; return d; }
    id hit = nil;
    @try { hit = [w hitTest:pt withEvent:nil]; } @catch (id e) {}
    UIView *v = (UIView *)hit;
    if (!v) { d[@"ok"] = @NO; d[@"err"] = @"hitTest nil"; return d; }
    d[@"hit"] = NSStringFromClass([v class]);

    UIControl *c = nil; UIView *p = v; int up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UIControl class]]) { c = (UIControl *)p; break; }
        p = p.superview; up++;
    }
    if (c) {   // 按钮场景：沿用 v14 已验证可靠的路子
        int a0 = gActionHits;
        @try { [c sendActionsForControlEvents:UIControlEventTouchUpInside]; } @catch (id e) {}
        d[@"how"] = @"UIControl sendActions";
        d[@"ctrl"] = NSStringFromClass([c class]);
        d[@"dact"] = @(gActionHits - a0);
        d[@"ok"]   = @(gActionHits - a0 > 0);
        return d;
    }

    UITableViewCell *cell = nil; p = v; up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UITableViewCell class]]) { cell = (UITableViewCell *)p; break; }
        p = p.superview; up++;
    }
    // v22：UICollectionViewCell（快手侧边栏/网格页全靠这条）
    UICollectionViewCell *ccell = nil; p = v; up = 0;
    while (p && up < 12) {
        if ([p isKindOfClass:[UICollectionViewCell class]]) { ccell = (UICollectionViewCell *)p; break; }
        p = p.superview; up++;
    }
    if (ccell) return AIPickCellInCollection(ccell, d);

    // v23：快手侧边栏这类自绘 UI，父链上既没 UIControl 也不是任何标准 Cell，
    //      但点击一定绑在 tap 手势上 —— 走手势触发，别再干瞪眼。
    if (!cell) {
        NSDictionary *g = AIGestureTapAt(pt);
        if ([g[@"ok"] boolValue]) {
            [d addEntriesFromDictionary:g];
            d[@"how"] = [@"gesture:" stringByAppendingString:(g[@"how"] ?: @"")];
            return d;
        }
        d[@"ok"] = @NO;
        d[@"err"] = @"这条父链上既无 UIControl 也无 Cell，手势也没打成";
        return d;
    }
    return AIPickCellIn(cell, d);
}

static NSString *AITextOfView(UIView *v);   // v23：本文件后面定义，这里先用

// v23：界面上「文字在哪」的递归查找。快手把文字画在 _TKLabel 里，
//      标准 tree/rows 都看不到，只能靠 AITextOfView 一个个问出来。
static void AIFindTextRec(UIView *v, NSString *kw, NSMutableArray *out) {
    if (!v || out.count > 200 || !AIBudgetTake()) return;
    @try {
        NSString *t = AITextOfView(v);
        if (t.length && [t rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound) {
            CGRect ab = [v convertRect:v.bounds toView:nil];
            if (ab.size.width > 4 && ab.size.height > 4 &&
                ab.origin.x < 420 && ab.origin.x + ab.size.width > -20 &&
                ab.origin.y < 900 && ab.origin.y + ab.size.height > 0)
                [out addObject:v];
        }
        for (UIView *c in v.subviews) AIFindTextRec(c, kw, out);
    } @catch (id e) {}
}

// v23：按文字定位控件并触发它的 tap 手势 —— 自绘 UI 的通用点击解法。
//      不依赖它是 UIControl / UITableViewCell / UICollectionViewCell。
static NSDictionary *AIPickTextViaGesture(NSString *kw) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    AIBudgetReset(4000);
    NSMutableArray *out = [NSMutableArray array];
    for (UIWindow *w in AIAllWindows()) {
        if (w == gOverlayWindow || w == gHudWindow) continue;
        AIFindTextRec(w, kw, out);
    }
    if (!out.count) {
        d[@"ok"] = @NO;
        d[@"err"] = [@"界面上找不到含该文字的控件: " stringByAppendingString:kw];
        d[@"cands"] = @0;
        return d;
    }
    UIView *best = nil; CGFloat by = 1e9;
    for (UIView *v in out) {
        CGRect ab = [v convertRect:v.bounds toView:nil];
        CGFloat y = CGRectGetMinY(ab);
        if (y < by) { by = y; best = v; }
    }
    CGRect ab = [best convertRect:best.bounds toView:nil];
    CGPoint c = CGPointMake(CGRectGetMidX(ab), CGRectGetMidY(ab));
    d[@"cands"] = @(out.count);
    d[@"found"] = NSStringFromClass([best class]);
    d[@"foundFrame"] = NSStringFromCGRect(ab);
    d[@"point"] = NSStringFromCGPoint(c);
    NSDictionary *g = AIGestureTapAt(c);
    [d addEntriesFromDictionary:g];
    d[@"how"] = [@"gesture:" stringByAppendingString:(g[@"how"] ?: @"none")];
    return d;
}

// 列出屏幕上所有可见表格行（含文本和屏幕中心点）——省掉逐个 probe 的往返
static NSString *AIRowsInfo(void) {
    NSMutableArray *lines = [NSMutableArray array];
    for (UITableView *tv in AIVisibleTableViews()) {
        NSArray *cells = nil;
        @try { cells = [tv visibleCells]; } @catch (id e) {}
        if (!cells.count) continue;
        cells = [cells sortedArrayUsingComparator:^NSComparisonResult(UIView *a, UIView *b) {
            CGFloat ya = CGRectGetMinY([a convertRect:a.bounds toView:nil]);
            CGFloat yb = CGRectGetMinY([b convertRect:b.bounds toView:nil]);
            if (ya < yb) return NSOrderedAscending;
            if (ya > yb) return NSOrderedDescending;
            return NSOrderedSame;
        }];
        [lines addObject:[NSString stringWithFormat:@"=== %@ (%lu 行可见) ===",
                          NSStringFromClass([tv class]), (unsigned long)cells.count]];
        for (UITableViewCell *c in cells) {
            CGRect f = [c convertRect:c.bounds toView:nil];
            NSIndexPath *ip = nil;
            @try { ip = [tv indexPathForCell:c]; } @catch (id e) {}
            [lines addObject:[NSString stringWithFormat:@"r%ld 中心(%.0f,%.0f) 框%@ 文本:%@",
                              (long)(ip ? ip.row : -1),
                              CGRectGetMidX(f), CGRectGetMidY(f),
                              NSStringFromCGRect(f), AITextsOf(c)]];
        }
    }
    // v22：UICollectionView 的可见 cell 也列出来（快手侧边栏 TKListView 靠这个读到文字）
    for (UICollectionView *cv in AIVisibleCollectionViews()) {
        NSArray *cells = nil;
        @try { cells = [cv visibleCells]; } @catch (id e) {}
        if (!cells.count) continue;
        cells = [cells sortedArrayUsingComparator:^NSComparisonResult(UIView *a, UIView *b) {
            CGFloat ya = CGRectGetMinY([a convertRect:a.bounds toView:nil]);
            CGFloat yb = CGRectGetMinY([b convertRect:b.bounds toView:nil]);
            if (ya < yb) return NSOrderedAscending;
            if (ya > yb) return NSOrderedDescending;
            return NSOrderedSame;
        }];
        [lines addObject:[NSString stringWithFormat:@"=== %@ [collection] (%lu 项可见) ===",
                          NSStringFromClass([cv class]), (unsigned long)cells.count]];
        for (UICollectionViewCell *c in cells) {
            CGRect f = [c convertRect:c.bounds toView:nil];
            NSIndexPath *ip = nil;
            @try { ip = [cv indexPathForCell:c]; } @catch (id e) {}
            [lines addObject:[NSString stringWithFormat:@"s%ld-i%ld 中心(%.0f,%.0f) 框%@ 文本:%@",
                              (long)(ip ? ip.section : -1), (long)(ip ? ip.item : -1),
                              CGRectGetMidX(f), CGRectGetMidY(f),
                              NSStringFromCGRect(f), AITextsOf(c)]];
        }
    }
    return lines.count ? [lines componentsJoinedByString:@"\n"] : @"(屏幕上没有可见表格行)";
}

// 按文本选中一行：找到含该文本的最靠上的行
static NSDictionary *AIPickByText(NSString *kw) {
    NSMutableArray *cands = [NSMutableArray array];
    for (UITableView *tv in AIVisibleTableViews()) {
        for (UITableViewCell *c in [tv visibleCells]) {
            NSString *t = AITextsOf(c);
            if (t && [t rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound) {
                if (![cands containsObject:c]) [cands addObject:c];
            }
        }
    }
    // v22：collection view 的 item 也参与文本匹配（快手侧边栏）
    for (UICollectionView *cv in AIVisibleCollectionViews()) {
        for (UICollectionViewCell *c in [cv visibleCells]) {
            NSString *t = AITextsOf(c);
            if (t && [t rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound)
                [cands addObject:c];
        }
    }
    // v23：一个标准 Cell 都没找到 —— 快手侧边栏这种自绘 UI 走这条路。
    //      直接按文字在界面上定位控件，再沿父链触发 tap 手势。
    if (!cands.count) return AIPickTextViaGesture(kw);
    UIView *best = nil; CGFloat by = 1e9;
    for (UIView *c in cands) {
        CGFloat y = CGRectGetMinY([c convertRect:c.bounds toView:nil]);
        if (y < by) { by = y; best = c; }
    }
    NSMutableDictionary *d;
    if ([best isKindOfClass:[UICollectionViewCell class]])
        d = [AIPickCellInCollection((UICollectionViewCell *)best, [NSMutableDictionary dictionary]) mutableCopy];
    else
        d = [AIPickCellIn((UITableViewCell *)best, [NSMutableDictionary dictionary]) mutableCopy];
    d[@"cands"] = @(cands.count);
    return d;
}

// ---------------------------------------------------------------------------
// 7f. v16：macro —— 一串动作一次下发，手机本地连跑，最后一次上报
//
//   慢的根因：手机每 2 秒才来 poll 一次，每个动作都要等一趟往返。
//   实测 6 个动作 = 21 秒，其中绝大部分是"等手机来取"的空转。
//   macro 把整串动作塞进一条指令：手机本地按 gap 依次执行，往返只有一次。
//   （同时轮询改成自适应：刚执行过指令就快轮询，空闲时退回慢轮询省电。）
// ---------------------------------------------------------------------------
static NSArray *AIRunMacro(NSArray *steps, double gapMs) {
    NSMutableArray *out = [NSMutableArray array];
    int idx = 0;
    for (NSDictionary *s in steps) {
        if (![s isKindOfClass:[NSDictionary class]]) continue;
        idx++;
        NSString *op = s[@"op"] ?: @"";
        NSMutableDictionary *r = [NSMutableDictionary dictionary];
        r[@"i"] = @(idx); r[@"op"] = op;

        AIMainSync(^{
            @try {
                if ([op isEqualToString:@"wait"]) {
                    double ms = [s[@"ms"] doubleValue]; if (ms <= 0) ms = gapMs;
                    AISleep(ms / 1000.0);
                    r[@"ok"] = @YES;
                } else if ([op isEqualToString:@"pick"]) {
                    NSDictionary *d = AIPickAt(CGPointMake([s[@"x"] floatValue], [s[@"y"] floatValue]));
                    r[@"ok"]  = d[@"ok"] ?: @NO;
                    r[@"how"] = d[@"how"] ?: @"";
                    r[@"txt"] = d[@"cellText"] ?: d[@"ctrl"] ?: @"";
                    if (d[@"err"]) r[@"err"] = d[@"err"];
                } else if ([op isEqualToString:@"picktxt"]) {
                    NSDictionary *d = AIPickByText(s[@"text"] ?: @"");
                    r[@"ok"]  = d[@"ok"] ?: @NO;
                    r[@"how"] = d[@"how"] ?: @"";
                    r[@"txt"] = d[@"cellText"] ?: @"";
                    r[@"cands"] = d[@"cands"] ?: @0;
                    if (d[@"err"]) r[@"err"] = d[@"err"];
                } else if ([op isEqualToString:@"tapui"]) {
                    NSString *desc = nil;
                    BOOL ok = AITapUIControlAt(CGPointMake([s[@"x"] floatValue], [s[@"y"] floatValue]), &desc);
                    r[@"ok"] = @(ok); r[@"txt"] = desc ?: @"";
                } else if ([op isEqualToString:@"tap"]) {
                    BOOL viaSend = NO;
                    @try { viaSend = AIDispatchFakeViaSendEvent(CGPointMake([s[@"x"] floatValue], [s[@"y"] floatValue]), 2, 0.03); } @catch (id e) {}
                    r[@"ok"] = @(viaSend); r[@"how"] = viaSend ? @"sendEvent" : @"(未确认)";
                } else if ([op isEqualToString:@"scroll"]) {
                    NSDictionary *d = AIScrollAt(CGPointMake([s[@"x"] floatValue], [s[@"y"] floatValue]),
                                                 [s[@"dy"] doubleValue], [s[@"dx"] doubleValue], YES);
                    r[@"ok"] = d[@"ok"] ?: @NO;
                    r[@"txt"] = [NSString stringWithFormat:@"%@ %@ -> %@ (移动 %.0f)",
                                 d[@"sv"] ?: @"?", d[@"before"] ?: @"?",
                                 d[@"after"] ?: @"?", [d[@"moved"] doubleValue]];
                    if (d[@"err"]) r[@"err"] = d[@"err"];
                } else if ([op isEqualToString:@"swipe"]) {
                    int steps = [s[@"steps"] intValue];  if (steps < 1) steps = 12;
                    double dur = [s[@"dur"] doubleValue]; if (dur <= 0) dur = 0.35;
                    BOOL ok = AIFakeSwipe(CGPointMake([s[@"x1"] floatValue], [s[@"y1"] floatValue]),
                                          CGPointMake([s[@"x2"] floatValue], [s[@"y2"] floatValue]), steps, dur);
                    r[@"ok"] = @(ok);
                } else if ([op isEqualToString:@"rows"]) {
                    NSString *t = AIRowsInfo();
                    NSString *head = t.length > 300 ? [t substringToIndex:300] : t;
                    r[@"ok"] = @YES; r[@"txt"] = head;
                    r[@"n"]  = @([t componentsSeparatedByString:@"\n"].count);
                } else if ([op isEqualToString:@"tree"]) {
                    UIWindow *w = AIHostWindow();
                    UIView *root = w ? (w.rootViewController.view ?: w) : nil;
                    NSString *t = root ? AITreeOf(root, 0, 12) : @"";
                    r[@"ok"] = @YES; r[@"n"] = @([t componentsSeparatedByString:@"\n"].count);
                    NSString *b64 = [[t dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
                    r[@"b64"] = b64 ?: @"";      // 完整树塞回来，省一趟往返
                } else if ([op isEqualToString:@"toast"]) {
                    AIToast(s[@"text"] ?: @"(空)");
                    r[@"ok"] = @YES;
                } else if ([op isEqualToString:@"probe"]) {
                    NSDictionary *d = AIProbeAt(CGPointMake([s[@"x"] floatValue], [s[@"y"] floatValue]));
                    r[@"ok"] = @YES; r[@"txt"] = [NSString stringWithFormat:@"%@ / %@",
                                                  d[@"hit"] ?: @"?", d[@"ctrl"] ?: @"?"];
                } else if ([op isEqualToString:@"back"]) {
                    NSString *t = AIBack();
                    r[@"ok"] = @(![t hasPrefix:@"act=none"]);
                    r[@"txt"] = t;
                } else if ([op isEqualToString:@"nav"]) {
                    r[@"ok"] = @YES; r[@"txt"] = AINavInfo();
                } else {
                    r[@"ok"] = @NO; r[@"err"] = [@"macro 不支持的 op: " stringByAppendingString:op];
                }
            } @catch (NSException *e) {
                r[@"ok"] = @NO; r[@"err"] = e.reason ?: @"异常";
            }
            // 每步之间留出动画时间（wait 步自己已经睡过了）
            if (![op isEqualToString:@"wait"]) AISleep(gapMs / 1000.0);
        });
        [out addObject:r];
        AILog(@"  [macro %d/%lu] %@ -> ok=%@ %@",
              idx, (unsigned long)steps.count, op, r[@"ok"], r[@"txt"] ?: r[@"err"] ?: @"");
    }
    return out;
}

// ---------------------------------------------------------------------------
// 7i. v18：back / nav —— 治「看得见却点不着」的返回键
//
//   现象：微信「作品」页（FlutterView）左上角明明有返回箭头，probe 扫过去却
//         整屏零 UIControl。原因：那个箭头是 Flutter 用 Skia 自己画到画布上的，
//         UIKit 视图树里根本没有对应的 UIButton —— 靠 UIControl 的 pick/tapui
//         必然找不到；伪造触摸 Flutter 引擎也不认（跟 tap/swipe 一个病）。
//   但视图树里有 UINavigationTransitionView ⇒ 这一页是 push 进原生导航栈的。
//   所以解法不是"点箭头"，而是"绕开 UI，直接命令导航栈 pop"。
// ---------------------------------------------------------------------------

// 递归收集所有 view 的 nextResponder（是 UIViewController 的）——
// 比从 rootViewController 一层层下钻可靠：微信的容器 VC 不一定走标准
// nav/tab/presented 关系，但每个 VC 的 view 一定在响应链上。
static void AICollectVCs(UIView *v, NSMutableArray *out, int depth, int maxDepth) {
    if (!v || depth > maxDepth) return;
    id nr = v.nextResponder;
    if ([nr isKindOfClass:[UIViewController class]] && ![out containsObject:nr]) [out addObject:nr];
    for (UIView *s in v.subviews) AICollectVCs(s, out, depth + 1, maxDepth);
}

// 当前屏幕上能摸到的所有 VC（含窗口根 VC）
static NSArray *AIVCsOnScreen(void) {
    NSMutableArray *vcs = [NSMutableArray array];
    UIWindow *w = AIHostWindow();
    if (w == gOverlayWindow || w == gHudWindow) return vcs;   // 别把自己盖的屏当宿主
    if (w.rootViewController) [vcs addObject:w.rootViewController];
    AICollectVCs(w, vcs, 0, 40);
    return vcs;
}

static NSString *AINavInfo(void) {
    __block NSMutableString *s = [NSMutableString string];
    AIMainSync(^{
        UIWindow *w = AIHostWindow();
        [s appendFormat:@"hostWin=%@ root=%@\n", NSStringFromClass([w class]),
            w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"(nil)"];
        int i = 0;
        for (UIViewController *vc in AIVCsOnScreen()) {
            BOOL vis = (vc.isViewLoaded && vc.view.window != nil);
            UINavigationController *n = [vc isKindOfClass:[UINavigationController class]]
                ? (UINavigationController *)vc : vc.navigationController;
            NSMutableString *ex = [NSMutableString string];
            if (n) [ex appendFormat:@" NAV(栈深%d)", (int)n.viewControllers.count];
            if (vc.presentedViewController)
                [ex appendFormat:@" present=%@", NSStringFromClass([vc.presentedViewController class])];
            [s appendFormat:@"  [%d] %@ 可见=%@%@\n", i++, NSStringFromClass([vc class]),
                vis ? @"Y" : @"n", ex];
        }
    });
    return [s copy];
}

static NSString *AIBack(void) {
    __block NSMutableString *s = [NSMutableString string];
    AIMainSync(^{
        NSArray *vcs = AIVCsOnScreen();

        // 1) 最内层「被 present 且可见」的 VC → dismiss（弹出的东西优先关掉）
        UIViewController *presTarget = nil;
        for (UIViewController *vc in vcs) {
            UIViewController *p = vc.presentedViewController;
            if (p && !p.isBeingDismissed && p.isViewLoaded && p.view.window) presTarget = p;
        }

        // 2) 可见的、栈深 >1 的 UINavigationController → pop（push 进来的页面）
        UINavigationController *navToPop = nil;
        for (UIViewController *vc in vcs) {
            UINavigationController *n = [vc isKindOfClass:[UINavigationController class]]
                ? (UINavigationController *)vc : vc.navigationController;
            if (n && n.viewControllers.count > 1 && n.isViewLoaded && n.view.window) {
                if (!navToPop || n.viewControllers.count >= navToPop.viewControllers.count) navToPop = n;
            }
        }

        if (presTarget) {
            [s appendFormat:@"act=dismiss 目标=%@ ", NSStringFromClass([presTarget class])];
            [presTarget.presentingViewController dismissViewControllerAnimated:YES completion:nil];
        } else if (navToPop) {
            [s appendFormat:@"act=pop nav=%@ 栈深=%d 退掉=%@ ",
                NSStringFromClass([navToPop class]), (int)navToPop.viewControllers.count,
                NSStringFromClass([navToPop.topViewController class])];
            [navToPop popViewControllerAnimated:YES];
        } else {
            [s appendString:@"act=none(没找到可见的导航栈，先跑 nav 看结构)"];
        }
    });
    return [s copy];
}

// 诊断：把所有 window / scene 打出来，一眼看出到底有没有 App 自己的窗口
static void AIDumpWindows(void) {
    AILog(@"==== [0b] Window / Scene 枚举（诊断） ====");
    UIApplication *app = [UIApplication sharedApplication];
    NSArray *all = AIAllWindows();
    AILog(@"  共找到 %lu 个 window", (unsigned long)all.count);
    for (UIWindow *w in all) {
        AILog(@"    - %@ hidden=%d key=%d alpha=%.2f %@ rootVC=%@%@",
              NSStringFromClass([w class]), w.hidden, (int)w.isKeyWindow, w.alpha,
              NSStringFromCGRect(w.frame),
              w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"(nil)",
              (w == gOverlayWindow ? @"   ← 我们的盖屏" : @""));
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    AILog(@"  [UIApplication windows] 数量 = %lu", (unsigned long)app.windows.count);
#pragma clang diagnostic pop
    if ([app respondsToSelector:@selector(connectedScenes)]) {
        id scenes = [app performSelector:@selector(connectedScenes)];
        NSSet *ss = [scenes isKindOfClass:[NSSet class]] ? (NSSet *)scenes : nil;
        AILog(@"  connectedScenes 数量 = %lu", (unsigned long)ss.count);
        for (id sc in ss) {
            int act = -1;
            @try { act = (int)[[sc valueForKey:@"activationState"] integerValue]; } @catch (id e) {}
            AILog(@"    * %@ activationState=%d", NSStringFromClass([sc class]), act);
        }
    }
}

// 屏幕坐标 -> 某个 view 内部的伪造触摸序列（Began / N×Moved / Ended）
static BOOL AIDispatchFakeSeq(UIView *target, CGPoint from, CGPoint to, int steps, double dur) {
    if (!target) return NO;
    if (steps < 1) steps = 1;
    if (dur <= 0) dur = 0.06;

    AIFakeTouch *t = [AIFakeTouch new];
    t.aiView  = target;
    t.aiTime  = [[NSDate date] timeIntervalSince1970];

    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one;
    ev.aiTime    = t.aiTime;

    @try {
        t.aiPhase = UITouchPhaseBegan;
        t.aiPoint = from;
        [target touchesBegan:one withEvent:ev];
        AISleep(dur / (double)steps);
        for (int i = 1; i <= steps; i++) {
            t.aiPhase = UITouchPhaseMoved;
            t.aiPoint = CGPointMake(from.x + (to.x - from.x) * (CGFloat)i / (CGFloat)steps,
                                    from.y + (to.y - from.y) * (CGFloat)i / (CGFloat)steps);
            t.aiTime  = [[NSDate date] timeIntervalSince1970];
            ev.aiTime = t.aiTime;
            [target touchesMoved:one withEvent:ev];
            AISleep(dur / (double)steps);
        }
        t.aiPhase = UITouchPhaseEnded;
        t.aiPoint = to;
        t.aiTime  = [[NSDate date] timeIntervalSince1970];
        ev.aiTime = t.aiTime;
        [target touchesEnded:one withEvent:ev];
        return YES;
    } @catch (NSException *ex) {
        AILog(@"  序列分发异常: %@", ex.reason);
        return NO;
    }
}

// 【统一入口】屏幕坐标点击：自己 hit-test 到最深的 view，再分发伪造触摸。
// v3 的 bug：回退到盖屏 window 后命中了自己的 UITextView，坐标还超出屏幕 ——
// 这里改成始终以「App 自己的窗口」为基准，命中不到就退到根 view（游戏一般整屏一个 view）。
static BOOL AIFakeTapAtWindowPoint(CGPoint pt) {
    UIWindow *w = AIHostWindow();
    if (!w) { AILog(@"  无可用 window"); return NO; }
    AILog(@"  宿主 window: %@ %@", NSStringFromClass([w class]), NSStringFromCGRect(w.bounds));

    UIView *target = nil;
    @try { target = [w hitTest:pt withEvent:nil]; } @catch (NSException *e) {}
    if (!target) target = w.rootViewController.view;
    if (!target) {
        for (UIView *v in w.subviews) { target = v; break; }
    }
    if (!target) target = w;
    AILog(@"  hitTest 命中: %@", NSStringFromClass([target class]));

    CGPoint local = [w convertPoint:pt toView:target];
    return AIDispatchFakeSeq(target, local, local, 1, 0.06);
}

// 屏幕坐标滑动
static BOOL AIFakeSwipe(CGPoint a, CGPoint b, int steps, double dur) {
    UIWindow *w = AIHostWindow();
    if (!w) return NO;
    UIView *target = nil;
    @try { target = [w hitTest:a withEvent:nil]; } @catch (NSException *e) {}
    if (!target) target = w.rootViewController.view ?: w;
    CGPoint la = [w convertPoint:a toView:target];
    CGPoint lb = [w convertPoint:b toView:target];
    AILog(@"  swipe 目标: %@ (%.0f,%.0f)->(%.0f,%.0f) steps=%d",
          NSStringFromClass([target class]), la.x, la.y, lb.x, lb.y, steps);
    return AIDispatchFakeSeq(target, la, lb, steps, dur);
}

// ---------------------------------------------------------------------------
//   v17：伪触摸滑动已证实无效（回执 ok 但视图树零差异 —— UIKit 不路由伪造事件）。
//   改走结果侧：直接改 UIScrollView.contentOffset，绕开整条触摸链。
//   dy > 0 = 内容向上走（看到后面的内容），dy < 0 = 往回看。
// ---------------------------------------------------------------------------
static NSDictionary *AIScrollAt(CGPoint pt, double dy, double dx, BOOL anim) {
    UIWindow *w = AIHostWindow();
    if (!w) return @{@"ok": @NO, @"err": @"无 window"};
    UIView *hit = nil;
    @try { hit = [w hitTest:pt withEvent:nil]; } @catch (NSException *e) {}
    UIView *v = hit;  UIScrollView *sv = nil;  int up = 0;
    while (v && up < 25) {
        if ([v isKindOfClass:[UIScrollView class]]) { sv = (UIScrollView *)v; break; }
        v = v.superview; up++;
    }
    if (!sv) return @{@"ok": @NO, @"err": @"父链 25 层内无 UIScrollView",
                      @"hit": hit ? NSStringFromClass(hit.class) : @"nil"};
    CGPoint before = sv.contentOffset;
    CGFloat maxY = MAX(0, sv.contentSize.height - sv.bounds.size.height);
    CGFloat maxX = MAX(0, sv.contentSize.width  - sv.bounds.size.width);
    CGPoint after = CGPointMake(MIN(maxX, MAX(0, before.x + dx)),
                                MIN(maxY, MAX(0, before.y + dy)));
    [sv setContentOffset:after animated:anim];
    return @{@"ok": @YES, @"sv": NSStringFromClass(sv.class), @"up": @(up),
             @"hit": hit ? NSStringFromClass(hit.class) : @"nil",
             @"before": NSStringFromCGPoint(before),
             @"after":  NSStringFromCGPoint(after),
             @"moved":  @(after.y - before.y),
             @"contentSize": NSStringFromCGSize(sv.contentSize),
             @"frame":  NSStringFromCGRect(sv.bounds)};
}

// 主线程同步执行（HTTP 服务在后台线程，触摸/截图必须回主线程）
static void AIMainSync(void (^b)(void)) {
    if ([NSThread isMainThread]) b();
    else dispatch_sync(dispatch_get_main_queue(), b);
}

// 前向声明：AIDispatchFakeViaSendEvent 定义在 7c（~600 行），
// 而 AIMainSyncBool 用在 AIExecCmd（~1600 行）—— 顺序没问题，
// 但 AIMainSync 定义在 7b（~620 行）之后，这里补声明以防顺序调整。
static BOOL AIMainSyncBool(BOOL (^b)(void));

// 同上，但要拿回一个 BOOL 返回值（dispatch_sync 的 block 不能直接 return）
static BOOL AIMainSyncBool(BOOL (^b)(void)) {
    __block BOOL r = NO;
    void (^w)(void) = ^{ r = b(); };
    if ([NSThread isMainThread]) w();
    else dispatch_sync(dispatch_get_main_queue(), w);
    return r;
}

// --- 闭环自证用的测试视图 ---
static int gFakeHits = 0;
@interface AITestView : UIView
@end
@implementation AITestView
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    gFakeHits++;
    AILog(@"  ★★ AITestView 收到 touchesBegan（第 %d 次）", gFakeHits);
}
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    AILog(@"  ★★ AITestView 收到 touchesEnded");
}
@end

static void AIFakeTapTest(void) {
    AILog(@"==== [3c] 伪造 Touch/Event 直接分发（闭环自证） ====");
    UIView *host = gOverlayWindow ? gOverlayWindow.rootViewController.view : nil;
    if (!host) { AILog(@"  没有宿主 view"); return; }

    AITestView *tv = [[AITestView alloc] initWithFrame:CGRectMake(20, 200, 140, 90)];
    tv.backgroundColor = [UIColor blueColor];
    tv.userInteractionEnabled = YES;
    [host addSubview:tv];
    [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];

    // 步骤 1：直接喂给测试 view，验证伪造对象本身可用
    int h0 = gFakeHits;
    BOOL ok1 = AIDispatchFakeToView(tv, CGPointMake(70, 45));
    AILog(@"  [1] 直接分发到 AITestView -> %@  计数器+%d", ok1 ? @"已投递" : @"失败", gFakeHits - h0);

    // 步骤 2：走 hit-test 自动定位（目标是【App 自己的】view，不是我们的盖屏）
    // 计数器不涨是【正常的】—— 因为事件被送去了 App 的 view，不是 AITestView。
    // 真正的判据在 [3d]。
    CGSize scr = [UIScreen mainScreen].bounds.size;
    BOOL ok2 = AIFakeTapAtWindowPoint(CGPointMake(scr.width * 0.5, scr.height * 0.5));
    AILog(@"  [2] 屏幕中心 (%.0f,%.0f) 自动定位分发 -> %@", scr.width * 0.5, scr.height * 0.5,
          ok2 ? @"已投递" : @"失败");

    if (gFakeHits > 0 && gBestTap == 0) {
        gBestTap = 4;   // 4 = 伪造对象直接分发
        AILog(@"  ↑ 选定为点击通道：伪造 Touch/Event 直接分发");
    }
    [tv removeFromSuperview];
}

// ---------------------------------------------------------------------------
// 7c. 【决定性判据】目标 App 自己的 view 到底收没收到我们的伪造触摸？
//
//  只说"已投递"不算数（AIDispatchFakeSeq 返回 YES 只能证明没抛异常）。
//  这里给目标 view 的类装一个 touchesBegan: 计数器，用 swizzle 实现：
//    · class_addMethod 先把父类实现复制进本类 → 替换只影响本类，不污染 UIResponder
//    · 只统计 event 是 AIFakeEvent（我们自己造的）的调用 → 不会误计真实触摸
// ---------------------------------------------------------------------------
static volatile int32_t gTargetHits = 0;
static NSString *gTargetHitClass = nil;
static IMP       gOrigTouchesBegan = NULL;

static void AIHookedTouchesBegan(id self, SEL _cmd, NSSet *touches, UIEvent *ev) {
    if ([ev isKindOfClass:[AIFakeEvent class]]) {
        gTargetHits++;
        gTargetHitClass = NSStringFromClass([self class]);
    }
    if (gOrigTouchesBegan) ((void (*)(id, SEL, NSSet *, UIEvent *))gOrigTouchesBegan)(self, _cmd, touches, ev);
}

static void AIHookTouchesOn(Class c) {
    if (!c) return;
    SEL sel = @selector(touchesBegan:withEvent:);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (orig == (IMP)AIHookedTouchesBegan) return;   // 已经装过
    class_addMethod(c, sel, orig, method_getTypeEncoding(m));
    gOrigTouchesBegan = orig;
    method_setImplementation(class_getInstanceMethod(c, sel), (IMP)AIHookedTouchesBegan);
    AILog(@"  已给 %@ 的 touchesBegan: 装计数器", NSStringFromClass(c));
}

static void AITargetViewTest(void) {
    AILog(@"==== [3d] 目标 App 自己的 view 实测（决定性判据） ====");
    UIWindow *w = AIHostWindow();
    if (!w) { AILog(@"  无宿主 window"); return; }
    CGSize s = [UIScreen mainScreen].bounds.size;
    CGPoint pt = CGPointMake(s.width * 0.5, s.height * 0.5);

    UIView *target = nil;
    @try { target = [w hitTest:pt withEvent:nil]; } @catch (id e) {}
    if (!target) target = w.rootViewController.view;
    if (!target) target = w;

    NSString *cn = NSStringFromClass([target class]);
    AILog(@"  目标 view: %@  屏幕 %.0fx%.0f 点(%.0f,%.0f)", cn, s.width, s.height, pt.x, pt.y);
    if (target.window == gOverlayWindow || [cn hasPrefix:@"AI"]) {
        AILog(@"  ⚠️ 命中的是我们自己的盖屏 —— 没找到 App 自己的窗口");
    } else {
        AILog(@"  ✓ 命中的是 App 自己的 view（window=%@）", NSStringFromClass([target.window class]));
    }

    @try { AIHookTouchesOn([target class]); } @catch (id e) { AILog(@"  hook 失败"); }
    int h0 = gTargetHits;
    CGPoint local = [w convertPoint:pt toView:target];
    BOOL ok = AIDispatchFakeSeq(target, local, local, 1, 0.06);
    AILog(@"  分发 -> %@   ★目标 view 实际收到伪造触摸 +%d (%@)",
          ok ? @"已投递" : @"失败", gTargetHits - h0, gTargetHitClass ?: @"-");
    if (gTargetHits > h0 && gBestTap == 0) {
        gBestTap = 4;
        AILog(@"  ↑ 选定为点击通道：伪造 Touch/Event 直接分发（已证实目标 view 收到）");
    }
}

// --- dump UITouch / UIEvent 的真实方法名：找出本系统真正的构造入口 ---
static void AIDumpTouchAPI(void) {
    AILog(@"==== [3a] UITouch / UIEvent 方法名 dump ====");
    struct { Class c; const char *n; } tgt[] = {
        { [UITouch class], "UITouch" },
        { [UIEvent class],  "UIEvent" },
    };
    for (int k = 0; k < 2; k++) {
        unsigned int n = 0;
        Method *ms = class_copyMethodList(tgt[k].c, &n);
        AILog(@"  %s 共 %u 个实例方法，含关键词的:", tgt[k].n, n);
        int shown = 0;
        for (unsigned int i = 0; i < n && shown < 40; i++) {
            SEL sel = method_getName(ms[i]);
            const char *nm = sel_getName(sel);
            unsigned na = method_getNumberOfArguments(ms[i]);
            BOOL interesting = (strstr(nm, "init") || strstr(nm, "Point") || strstr(nm, "point")
                                || strstr(nm, "Window") || strstr(nm, "window")
                                || strstr(nm, "location") || strstr(nm, "Location")
                                || strstr(nm, "Touch") || strstr(nm, "touch")
                                || strstr(nm, "Event") || strstr(nm, "event"));
            if (interesting) {
                AILog(@"    -[%s %s]  (%u 参数)", tgt[k].n, nm, na);
                shown++;
            }
        }
        free(ms);
    }
}

// ---------------------------------------------------------------------------
// 8. HID 自检矩阵
// ---------------------------------------------------------------------------
static void AIPump(CFRunLoopRef rl, double sec) {
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, sec, false);
}

typedef struct { const char *name; void *client; } ClientEnt;

static void AIHidMatrix(CFRunLoopRef rl) {
    AILog(@"==== [3] HID 点击矩阵（判据: monitor 回环 + sendEvent hook） ====");
    if (!gDispatch) { AILog(@"  dispatch 符号缺失，跳过"); return; }

    ClientEnt cl[8]; int nc = 0;
    @try { void *c = gClientCreate ? gClientCreate(kCFAllocatorDefault) : NULL;
           if (c) cl[nc++] = (ClientEnt){"Create(老签名·连点器同款)", c}; } @catch (id e) {}
    if (gClientSimple) {
        uint32_t types[] = {0, 1, 3, 4};
        const char *tn[] = {"SimpleClient(0)", "SimpleClient(1)", "SimpleClient(3)", "SimpleClient(4)"};
        for (int i = 0; i < 4; i++) {
            @try { void *c = gClientSimple(kCFAllocatorDefault, types[i]);
                   if (c) cl[nc++] = (ClientEnt){tn[i], c}; } @catch (id e) {}
        }
    }
    @try { void *c = gClientType ? gClientType(kCFAllocatorDefault, 0, NULL) : NULL;
           if (c) cl[nc++] = (ClientEnt){"WithType(0)", c}; } @catch (id e) {}
    AILog(@"  可用 client: %d 个", nc);

    CGSize scr = [UIScreen mainScreen].bounds.size;
    CGFloat sx = scr.width * 0.5, sy = scr.height * 0.5;
    CGFloat scale = [UIScreen mainScreen].scale;

    for (int ci = 0; ci < nc; ci++) {
        for (int form = 0; form < 3; form++) {
            const char *fn[] = {"复合hand+finger(18参)", "裸finger(18参)", "裸finger(老10参)"};
            int m0 = gMonHits, s0 = gSendEventHits;
            BOOL built = NO;
            @try {
                for (int ph = 0; ph < 3; ph++) {
                    IOHIDEventRef ev = NULL;
                    if (form == 0)      ev = AIMakeComposite(sx, sy, (TPPhase)ph);
                    else if (form == 1) ev = AIMakeBareFinger(sx, sy, (TPPhase)ph);
                    else                ev = AIMakeOldFinger(sx, sy, (TPPhase)ph);
                    if (!ev) continue;
                    built = YES;
                    if (gSetSender) @try { gSetSender(ev, 0x4001ULL); } @catch (id e) {}
                    gDispatch(cl[ci].client, ev);
                    CFRelease(ev);
                    AIPump(rl, 0.25);
                }
            } @catch (NSException *e) { AILog(@"  [%s/%s] 异常 %@", cl[ci].name, fn[form], e); }
            int dm = gMonHits - m0, ds = gSendEventHits - s0;
            BOOL ok = (dm > 0 || ds > 0);
            AILog(@"  %@ client=%-28s form=%-22s monitor+%d sendEvent+%d",
                  ok ? @"✅" : (built ? @"❌" : @"  "), cl[ci].name, fn[form], dm, ds);
            if (ok && !gBestClient) { gBestClient = cl[ci].client; gBestTap = 1;
                AILog(@"     ↑ 选定为 HID 通道 (form=%d)", form);
                gBestTapForm = form;
            }
        }
    }
    // 统一复查：所有组合发完之后再等 1.5s，防止「事件延迟到达」被判成失败
    int sAll = gSendEventHits, mAll = gMonHits;
    AIPump(rl, 1.5);
    AILog(@"  【统一复查】全部发完后再等 1.5s: sendEvent %d→%d (+%d), monitor %d→%d (+%d)",
          sAll, gSendEventHits, gSendEventHits - sAll, mAll, gMonHits, gMonHits - mAll);
    if (gSendEventHits - sAll > 0 && !gBestClient) {
        gBestClient = cl[0].client; gBestTap = 1;
        AILog(@"     ↑ 复查阶段才收到，说明事件有延迟：HID 通道实际可用");
    }
    AILog(@"  屏幕 %.0fx%.0f scale=%.1f 测试点(%.0f,%.0f)", scr.width, scr.height, scale, sx, sy);
}

// ---------------------------------------------------------------------------
// 9. 截图矩阵
// ---------------------------------------------------------------------------
static UIImage *AIShot_Private1(void) {  // UIGetScreenImage
    CGImageRef (*f)(void) = (CGImageRef (*)(void))dlsym(RTLD_DEFAULT, "UIGetScreenImage");
    if (!f) return nil;
    @try { CGImageRef cg = f(); if (!cg) return nil;
        UIImage *im = [UIImage imageWithCGImage:cg]; return im; } @catch (id e) { return nil; }
}
static UIImage *AIShot_Private2(void) {  // _UICreateScreenUIImage
    UIImage *(*f)(void) = (UIImage *(*)(void))dlsym(RTLD_DEFAULT, "_UICreateScreenUIImage");
    if (!f) return nil;
    @try { return f(); } @catch (id e) { return nil; }
}
static UIImage *AIShot_Hierarchy(void) {
    UIApplication *app = [UIApplication sharedApplication];
    UIWindow *w = AIHostWindow();
    if (!w) return nil;
    if (w == gOverlayWindow) AILog(@"    ⚠️ 拿到的还是我们的盖屏，截图内容可能不对");
    CGSize s = w.bounds.size;
    if (s.width < 1 || s.height < 1) return nil;
    @try {
        UIGraphicsBeginImageContextWithOptions(s, NO, 0);
        BOOL ok = [w drawViewHierarchyInRect:CGRectMake(0, 0, s.width, s.height) afterScreenUpdates:NO];
        UIImage *im = ok ? UIGraphicsGetImageFromCurrentImageContext() : nil;
        UIGraphicsEndImageContext();
        return im;
    } @catch (id e) { UIGraphicsEndImageContext(); return nil; }
}
static UIImage *AIShot_Layer(void) {
    UIApplication *app = [UIApplication sharedApplication];
    UIWindow *w = AIHostWindow();
    if (!w) return nil;
    if (w == gOverlayWindow) AILog(@"    ⚠️ 拿到的还是我们的盖屏，截图内容可能不对");
    CGSize s = w.bounds.size;
    if (s.width < 1 || s.height < 1) return nil;
    @try {
        UIGraphicsBeginImageContextWithOptions(s, NO, 0);
        [w.layer renderInContext:UIGraphicsGetCurrentContext()];
        UIImage *im = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        return im;
    } @catch (id e) { UIGraphicsEndImageContext(); return nil; }
}

// 注意：ARC 下【不能】把 Objective-C 对象放进 struct / 结构体数组
// （"ARC forbids Objective-C objects in struct"）—— 所以用平行数组，不用结构体内嵌 NSString*
static const int      kShotIdx[] = {1, 2, 3, 4};
static const char    *kShotName[] = {"UIGetScreenImage", "_UICreateScreenUIImage",
                                     "drawViewHierarchyInRect", "layer renderInContext"};

static void AIShotMatrix(void) {
    AILog(@"==== [4] 截图矩阵 ====");
    UIImage *(*fns[])(void) = {AIShot_Private1, AIShot_Private2, AIShot_Hierarchy, AIShot_Layer};
    for (int i = 0; i < 4; i++) {
        UIImage *im = nil;
        @try { im = fns[i](); } @catch (NSException *e) { AILog(@"  [%s] 异常 %@", kShotName[i], e.reason); }
        CGSize sz = im ? im.size : CGSizeZero;
        NSData *png = (im && sz.width > 1) ? UIImagePNGRepresentation(im) : nil;
        AILog(@"  [%d] %-26s -> %@ %.0fx%.0f %luB", kShotIdx[i], kShotName[i],
              im ? @"有图" : @"空", sz.width, sz.height, (unsigned long)(png ? png.length : 0));
        if (im && sz.width > 1 && !gBestShot) { gBestShot = kShotIdx[i]; AILog(@"     ↑ 选定为截图通道"); }
    }
}

// 按编号取截图策略（供 /shot 指令复用）
static UIImage *AIShotByBest(void) {
    switch (gBestShot) {
        case 1: return AIShot_Private1();
        case 2: return AIShot_Private2();
        case 3: return AIShot_Hierarchy();
        case 4: return AIShot_Layer();
        default: return nil;
    }
}

// ---------------------------------------------------------------------------
// 10. UIControl 路线（对 UI 自动化有用，对游戏无用）
// ---------------------------------------------------------------------------
static void AIWalkControls(UIView *root, NSMutableArray *out, int depth) {
    if (!root || depth > 12) return;
    for (UIView *v in root.subviews) {
        if ([v isKindOfClass:[UIControl class]]) [out addObject:v];
        AIWalkControls(v, out, depth + 1);
    }
}

static void AIControlProbe(void) {
    AILog(@"==== [5] UIControl / 视图树 ====");
    UIApplication *app = [UIApplication sharedApplication];
    UIWindow *w = AIHostWindow();
    if (!w) { AILog(@"  无 window"); return; }
    AILog(@"  宿主 window: %@ rootVC=%@", NSStringFromClass([w class]),
          w.rootViewController ? NSStringFromClass([w.rootViewController class]) : @"(nil)");
    NSMutableArray *ctls = [NSMutableArray array];
    @try { AIWalkControls(w, ctls, 0); } @catch (id e) {}
    AILog(@"  UIControl 数量: %lu", (unsigned long)ctls.count);
    int shown = 0;
    for (UIControl *c in ctls) {
        if (shown++ >= 8) break;
        CGRect r = c.frame;
        AILog(@"    %@ frame=(%.0f,%.0f,%.0f,%.0f) hidden=%d",
              NSStringFromClass([c class]), r.origin.x, r.origin.y, r.size.width, r.size.height, c.hidden);
    }
    if (ctls.count && gBestTap == 0) {
        @try {
            UIControl *c = ctls.firstObject;
            int s0 = gControlHits;
            [c sendActionsForControlEvents:UIControlEventTouchUpInside];
            AILog(@"  直接触发首个 UIControl -> hits+%d", gControlHits - s0);
            gBestTap = 3;
        } @catch (NSException *e) { AILog(@"  UIControl 触发异常 %@", e); }
    }
}

// ---------------------------------------------------------------------------
// 11. 环境
// ---------------------------------------------------------------------------
static void AIEnv(void) {
    AILog(@"==== [0] 环境 ====");
    gProcName = [[NSProcessInfo processInfo] processName] ?: @"?";
    gBundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"?";
    gIsSpringBoard = [gBundleId isEqualToString:@"com.apple.springboard"];
    gDevId = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    AILog(@"  进程=%@ bundle=%@ pid=%d SpringBoard=%d", gProcName, gBundleId, getpid(), gIsSpringBoard);
    AILog(@"  iOS=%@ 设备=%@", [UIDevice currentDevice].systemVersion, [UIDevice currentDevice].model);

    // entitlement 抽查
    NSString *probe = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    (void)probe;
    const char *ents[] = {
        "com.apple.private.hid.client.event-dispatch",
        "com.apple.private.hid.client.event-monitor",
        "get-task-allow", "platform-application",
        "com.apple.private.security.no-sandbox",
        "com.apple.private.skip-library-validation",
    };
    // 用 SecTask 读自身 entitlement
    void *hSec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (hSec) {
        void *(*SecTaskCreateFromSelf)(CFAllocatorRef) =
            (void *(*)(CFAllocatorRef))dlsym(hSec, "SecTaskCreateFromSelf");
        CFTypeRef (*SecTaskCopyValueForEntitlement)(void *, CFStringRef, CFErrorRef *) =
            (CFTypeRef (*)(void *, CFStringRef, CFErrorRef *))dlsym(hSec, "SecTaskCopyValueForEntitlement");
        if (SecTaskCreateFromSelf && SecTaskCopyValueForEntitlement) {
            void *task = SecTaskCreateFromSelf(kCFAllocatorDefault);
            if (task) {
                for (int i = 0; i < (int)(sizeof(ents)/sizeof(ents[0])); i++) {
                    CFStringRef k = CFStringCreateWithCString(NULL, ents[i], kCFStringEncodingUTF8);
                    CFTypeRef v = SecTaskCopyValueForEntitlement(task, k, NULL);
                    // 注意：存在但值为 false 时 v 也非 NULL，必须判布尔值而不是判非空
                    NSString *sv;
                    if (!v) sv = @"NO(无)";
                    else if (CFGetTypeID(v) == CFBooleanGetTypeID()) sv = CFBooleanGetValue((CFBooleanRef)v) ? @"YES" : @"NO(显式false)";
                    else sv = @"YES(非布尔值)";
                    AILog(@"  ent %-46s = %@", ents[i], sv);
                    if (v) CFRelease(v);
                    CFRelease(k);
                }
                CFRelease(task);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 12. 网络：反向轮询控制服务器
// ---------------------------------------------------------------------------
static NSData *AIHttp(NSString *urlStr, NSData *body, NSTimeInterval tmo) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) return nil;
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u
                                                     cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                 timeoutInterval:tmo];
    if (body) { rq.HTTPMethod = @"POST"; rq.HTTPBody = body;
                [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"]; }
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSession *s = [NSURLSession sharedSession];
    NSURLSessionDataTask *t = [s dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        out = d; dispatch_semaphore_signal(sem);
    }];
    [t resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((tmo + 2.0) * NSEC_PER_SEC)));
    return out;
}

// 带 NSError 的版本：网络失败时必须能看到具体原因（DNS / TLS / 超时 / ATS），
// 否则只能看到"设备没上线"，根本没法排查。
static NSData *AIHttpErr(NSString *urlStr, NSData *body, NSTimeInterval tmo, NSError **errOut) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) { if (errOut) *errOut = [NSError errorWithDomain:@"AI" code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"URL 非法"}]; return nil; }
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u
                                                     cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                 timeoutInterval:tmo];
    if (body) { rq.HTTPMethod = @"POST"; rq.HTTPBody = body;
                [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"]; }
    __block NSData *out = nil;
    __block NSError *err = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSession *s = [NSURLSession sharedSession];
    NSURLSessionDataTask *t = [s dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        out = d; err = e; dispatch_semaphore_signal(sem);
    }];
    [t resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((tmo + 2.0) * NSEC_PER_SEC)));
    if (errOut) *errOut = err;
    return out;
}

// 信任任意证书的 session delegate —— 只给「IP 直连兜底」用。
// 直连 49.233.x.x 时证书 CN 是 *.workbuddy.host，跟 IP 对不上，系统必然拒绝握手；
// 我们自己接管校验才发得出去。主链路始终是带校验的域名 HTTPS，不受影响。
@interface AITrustDelegate : NSObject <NSURLSessionDelegate>
@end
@implementation AITrustDelegate
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]
        && challenge.protectionSpace.serverTrust) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}
@end
static AITrustDelegate *gTrustDel = nil;

// trustAny=YES 时跳过证书校验；host 不为空时覆盖 Host 头（IP 直连时给负载均衡用）。
// 返回 YES 表示拿到了响应体；响应体本身通过 *out 返回。
static BOOL AIHttpEx(NSString *urlStr, NSData *body, NSTimeInterval tmo,
                     BOOL trustAny, NSString *host, NSData **out, NSError **errOut,
                     NSInteger *httpCode, NSTimeInterval *ms) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) { if (errOut) *errOut = [NSError errorWithDomain:@"AI" code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"URL 非法"}]; return NO; }
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u
                                                     cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                 timeoutInterval:tmo];
    if (body) { rq.HTTPMethod = @"POST"; rq.HTTPBody = body;
                [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"]; }
    if (host.length) [rq setValue:host forHTTPHeaderField:@"Host"];

    __block NSData *got = nil;
    __block NSError *err = nil;
    __block NSInteger code = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSession *s;
    if (trustAny) {
        if (!gTrustDel) gTrustDel = [AITrustDelegate new];
        s = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                          delegate:gTrustDel delegateQueue:nil];
    } else {
        s = [NSURLSession sharedSession];
    }
    NSDate *t0 = [NSDate date];
    NSURLSessionDataTask *t = [s dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        got = d; err = e;
        if ([r isKindOfClass:[NSHTTPURLResponse class]]) code = [(NSHTTPURLResponse *)r statusCode];
        dispatch_semaphore_signal(sem);
    }];
    [t resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((tmo + 2.0) * NSEC_PER_SEC)));
    if (ms)   *ms   = [[NSDate date] timeIntervalSinceDate:t0];
    if (out)  *out  = got;
    if (httpCode) *httpCode = code;
    if (errOut) *errOut = err;
    if (trustAny) { @try { [s invalidateAndCancel]; } @catch (id e) {} }
    return got != nil && err == nil;
}

static NSString *AIBase(void) {
    // 运行时可覆盖：把控制服务器地址写进任一文件
    NSString *cands[] = {
        @"/var/mobile/agent_base.txt",
        @"/var/mobile/Documents/agent_base.txt",
        [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
         stringByAppendingPathComponent:@"agent_base.txt"],
    };
    for (int i = 0; i < 3; i++) {
        @try {
            NSString *s = [NSString stringWithContentsOfFile:cands[i] encoding:NSUTF8StringEncoding error:nil];
            s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (s.length > 6) { AILog(@"  控制服务器(来自文件): %@", s); return s; }
        } @catch (id e) {}
    }
    // 默认走内置公网中继：手机主动出网来取指令，不要求用户有电脑、也不要求同网段。
    return @"https://aa0c466b5cdb559bb.app.workbuddy.host";
}


// ---------------------------------------------------------------------------
// 12b. 内置 HTTP 控制服务
//
//  为什么不再是「反向轮询外部服务器」：那需要额外部署一台中继，且手机必须能出网。
//  改成 dylib 自己监听一个端口 —— 手机和电脑在同一个 WiFi 下就能直接 curl，
//  这才是「像 API 一样随连随用」。反向轮询保留为可选（写了 base 才启用）。
// ---------------------------------------------------------------------------
static int    gSrvPort = 0;
static NSString *gSrvIp = nil;

static NSString *AIIpAddr(void) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return nil;
    NSString *res = nil;
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        const char *n = p->ifa_name ? p->ifa_name : "";
        if (strncmp(n, "en", 2) != 0) continue;          // en0 = Wi-Fi
        char buf[64];
        if (inet_ntop(AF_INET, &((struct sockaddr_in *)p->ifa_addr)->sin_addr, buf, sizeof(buf))) {
            res = [NSString stringWithUTF8String:buf];
            break;
        }
    }
    freeifaddrs(ifa);
    return res;
}

static NSString *AILogSnapshot(void) {
    if (!gLog) return @"(no log)";
    [gLogLock lock];
    NSString *t = [gLog copy];
    [gLogLock unlock];
    return t ?: @"";
}

static NSString *AIQv(NSString *q, NSString *k) {
    for (NSString *kv in [q componentsSeparatedByString:@"&"]) {
        NSArray *pp = [kv componentsSeparatedByString:@"="];
        if (pp.count == 2 && [pp[0] isEqualToString:k]) {
            return [pp[1] stringByRemovingPercentEncoding];
        }
    }
    return nil;
}

static void AIResp(int fd, int code, NSString *ctype, NSData *body) {
    NSString *h = [NSString stringWithFormat:
        @"HTTP/1.1 %d OK\r\nContent-Type: %@\r\nContent-Length: %lu\r\n"
        @"Connection: close\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        code, ctype, (unsigned long)body.length];
    NSData *hd = [h dataUsingEncoding:NSUTF8StringEncoding];
    if (!hd || !body) return;
    @try { send(fd, hd.bytes, hd.length, 0); send(fd, body.bytes, body.length, 0); } @catch (id e) {}
}

static void AIJson(int fd, NSDictionary *d) {
    NSData *b = [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
    AIResp(fd, 200, @"application/json; charset=utf-8", b ?: [NSData data]);
}

static NSString *AITreeOf(UIView *v, int depth, int maxDepth) {
    NSMutableString *m = [NSMutableString string];
    for (int i = 0; i < depth; i++) [m appendString:@"  "];
    CGRect f = v.frame;
    [m appendFormat:@"%@ (%.0f,%.0f,%.0f,%.0f)%@\n", NSStringFromClass([v class]),
     f.origin.x, f.origin.y, f.size.width, f.size.height, v.hidden ? @" hidden" : @""];
    if (depth >= maxDepth) return m;
    for (UIView *c in v.subviews) [m appendString:AITreeOf(c, depth + 1, maxDepth)];
    return m;
}

// v19：递归收集界面上所有「带文字」的控件，附带窗口坐标。
// 微信的 UITableView 能用 rows 读行文本，但快手这类自研列表（TKListView）不行，
// tree 也只打类名不给文本 —— 没有文本就无法在陌生 App 里导航。这个命令补上缺口。
// v20：从一个 view 上尽量榨出「它显示的文字」。
//
//   ★ 踩坑（快手）：快手侧边栏的文字在 `_TKLabel` 里，它是自绘控件、
//     不继承 UILabel，所以 v19 只认 UILabel/UIButton 的写法一条都读不到
//     （text 命令返回空字符串）。跨 App 想普适，必须三路兜底：
//       1) 标准控件（UILabel/UIButton/UITextField/UITextView）
//       2) 任何「碰巧有 text / attributedText 方法」的自绘控件（performSelector 试探）
//       3) 无障碍标签（accessibilityLabel/Value）—— 最通用的兜底
static NSString *AITextOfView(UIView *v);            // v21：AIDumpOf 在它定义之前要调用

// ---------------------------------------------------------------------------
// v23：性能阀门 —— v22 的一条 rows 命令把快手主线程卡死 5 分钟（心跳断了 369 秒）。
//
//   根因：AIRuntimeTextOf 对【每一个 view】都跑一遍 class_copyPropertyList，
//   还要沿 6 层父类各跑一次，每次最多 80 个属性各做 respondsToSelector。
//   快手单页视图上千个 → 上百万次 objc 调用 + 海量 malloc/free，全部压在主线程。
//
//   两级修复：
//     1) 属性名按 Class 缓存（同一个类只枚举一次，父类链一并合并进缓存）
//     2) 单次命令设总工作量预算，超了立刻收手 —— 宁可少报几条，绝不卡死
// ---------------------------------------------------------------------------
static NSMutableDictionary *gPropCache = nil;   // "类名" -> NSArray<NSString*> 候选属性名
static int  gTextBudget = 0;                    // 本次命令还能处理多少个 view
static void AIBudgetReset(int n) { gTextBudget = n; }
static BOOL AIBudgetTake(void) {
    if (gTextBudget <= 0) return NO;
    gTextBudget--;
    return YES;
}

// 某个类（含父类链 5 层）里「名字像文字」的属性名，只枚举一次并缓存
static NSArray *AITextPropNames(Class cls) {
    if (!cls) return @[];
    if (!gPropCache) gPropCache = [NSMutableDictionary dictionary];
    NSString *key = [NSString stringWithFormat:@"%s", class_getName(cls)];
    NSArray *cached = gPropCache[key];
    if (cached) return cached;

    NSMutableArray *m = [NSMutableArray array];
    Class c = cls; int lv = 0;
    while (c && lv++ < 5) {
        unsigned n = 0;
        objc_property_t *ps = class_copyPropertyList(c, &n);
        for (unsigned i = 0; i < n && i < 60; i++) {
            const char *pn = property_getName(ps[i]);
            if (!pn) continue;
            NSString *name = [[NSString alloc] initWithUTF8String:pn];
            NSString *ln = [name lowercaseString];
            if (!([ln containsString:@"text"] || [ln containsString:@"title"] ||
                  [ln containsString:@"content"] || [ln containsString:@"string"] ||
                  [ln containsString:@"label"] || [ln containsString:@"word"] ||
                  [ln containsString:@"desc"])) continue;
            if (![m containsObject:name]) [m addObject:name];
        }
        if (ps) free(ps);
        c = class_getSuperclass(c);
    }
    gPropCache[key] = m;
    return m;
}

// v21：自绘控件（快手 _TKLabel）既不继承 UILabel，也没有 accessibilityLabel，
//      文字藏在自定义属性里。用 runtime 枚举类的属性名，挑名字像「文字」的
//      逐个 performSelector 试探 —— 拿不到就 nil，绝不硬猜。
// v23：属性名单改为按类缓存，不再每个实例重复枚举（这是卡死的元凶）。
static NSString *AIRuntimeTextOf(id v) {
    if (!v) return nil;
    for (NSString *name in AITextPropNames([v class])) {
        SEL g = NSSelectorFromString(name);
        if (!g || ![v respondsToSelector:g]) continue;
        @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id r = [v performSelector:g];
#pragma clang diagnostic pop
            if ([r isKindOfClass:[NSString class]] && [(NSString *)r length] > 0 &&
                [(NSString *)r length] < 300) return (NSString *)r;
            if ([r isKindOfClass:[NSAttributedString class]] && [(NSAttributedString *)r length])
                return [(NSAttributedString *)r string];
        } @catch (id e) {}
    }
    return nil;
}

// v21：dump 一个对象里「所有可能是文字的东西」——查案用，不参与正常流程
static NSString *AIPropsOf(id v) {
    if (!v) return @"";
    NSMutableArray *parts = [NSMutableArray array];
    Class cls = [v class];
    int lv = 0;
    while (cls && lv++ < 4) {
        unsigned n = 0;
        objc_property_t *ps = class_copyPropertyList(cls, &n);
        for (unsigned i = 0; i < n && i < 80; i++) {
            const char *pn = property_getName(ps[i]);
            if (!pn) continue;
            NSString *name = [[NSString alloc] initWithUTF8String:pn];
            SEL g = NSSelectorFromString(name);
            if (!g || ![v respondsToSelector:g]) continue;
            @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                id r = [v performSelector:g];
#pragma clang diagnostic pop
                NSString *s = nil;
                if ([r isKindOfClass:[NSString class]]) s = r;
                else if ([r isKindOfClass:[NSAttributedString class]]) s = [(NSAttributedString *)r string];
                else if ([r isKindOfClass:[NSNumber class]]) s = [(NSNumber *)r stringValue];
                if (!s) continue;
                if (s.length > 40) s = [[s substringToIndex:40] stringByAppendingString:@"…"];
                [parts addObject:[NSString stringWithFormat:@"%@=%@", name, s]];
            } @catch (id e) {}
        }
        if (ps) free(ps);
        cls = class_getSuperclass(cls);
    }
    return [parts componentsJoinedByString:@", "];
}

static NSString *AIDumpOf(UIView *v, int depth, int maxDepth) {
    NSMutableString *m = [NSMutableString string];
    CGRect ab = CGRectZero;
    @try { ab = [v convertRect:v.bounds toView:nil]; } @catch (id e) {}
    NSMutableString *ind = [NSMutableString string];
    for (int i = 0; i < depth; i++) [ind appendString:@"  "];
    [m appendFormat:@"%@%@ (%.0f,%.0f %.0fx%.0f)", ind, NSStringFromClass([v class]),
     ab.origin.x, ab.origin.y, ab.size.width, ab.size.height];
    NSString *t = AITextOfView(v);
    if (t.length) [m appendFormat:@"  TXT=%@", t];
    NSString *p = AIPropsOf(v);
    if (p.length) [m appendFormat:@"\n%@  {%@}", ind, p];
    else [m appendString:@"\n"];
    if (depth >= maxDepth) return m;
    for (UIView *c in v.subviews) [m appendString:AIDumpOf(c, depth + 1, maxDepth)];
    return m;
}

static NSString *AITextOfView(UIView *v) {
    if (!v) return nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    @try {
        if ([v respondsToSelector:@selector(text)]) {
            id r = [v performSelector:@selector(text)];
            if ([r isKindOfClass:[NSString class]] && [(NSString *)r length]) return (NSString *)r;
            if ([r isKindOfClass:[NSAttributedString class]] && [(NSAttributedString *)r length])
                return [(NSAttributedString *)r string];
        }
        if ([v respondsToSelector:@selector(attributedText)]) {
            id r = [v performSelector:@selector(attributedText)];
            if ([r isKindOfClass:[NSAttributedString class]] && [(NSAttributedString *)r length])
                return [(NSAttributedString *)r string];
        }
        if ([v respondsToSelector:@selector(currentTitle)]) {
            id r = [v performSelector:@selector(currentTitle)];
            if ([r isKindOfClass:[NSString class]] && [(NSString *)r length]) return (NSString *)r;
        }
        if ([v respondsToSelector:@selector(placeholder)]) {
            id r = [v performSelector:@selector(placeholder)];
            if ([r isKindOfClass:[NSString class]] && [(NSString *)r length])
                return [NSString stringWithFormat:@"[%@]", r];
        }
    } @catch (id e) {}
#pragma clang diagnostic pop
    @try { NSString *a = v.accessibilityLabel; if (a.length) return a; } @catch (id e) {}
    @try { NSString *a = v.accessibilityValue; if (a.length) return a; } @catch (id e) {}
    @try { NSString *a = AIRuntimeTextOf(v); if (a.length) return a; } @catch (id e) {}   // v21 自绘控件兜底
    return nil;
}

// parentTxt：父 view 已经输出过的文本。容器常把子控件的文字抄到自己的
// accessibilityLabel 上，不去重的话快手这种深树会刷出满屏重复行。
static NSString *AITextListD(UIView *v, int depth, int maxDepth, NSString *parentTxt) {
    NSMutableString *m = [NSMutableString string];
    if (!AIBudgetTake()) return m;          // v23：预算用完就收手，绝不让主线程陷进去
    CGRect ab = CGRectZero;
    @try { ab = [v convertRect:v.bounds toView:nil]; } @catch (id e) {}
    NSString *txt = AITextOfView(v);
    // 只看屏幕内的：离屏/零尺寸的控件坐标没意义，还会把结果刷爆
    BOOL onScreen = (ab.size.width > 0 && ab.size.height > 0 &&
                     ab.origin.y < 900 && ab.origin.y + ab.size.height > -60);
    if (txt.length && onScreen && ![txt isEqualToString:parentTxt]) {
        NSString *oneLine = [txt stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
        if (oneLine.length > 60) oneLine = [oneLine substringToIndex:60];
        [m appendFormat:@"(%d) %.0f,%.0f %.0fx%.0f | %@\n",
         depth, ab.origin.x, ab.origin.y, ab.size.width, ab.size.height, oneLine];
    }
    if (depth >= maxDepth) return m;
    NSString *pass = txt.length ? txt : parentTxt;
    for (UIView *c in v.subviews) [m appendString:AITextListD(c, depth + 1, maxDepth, pass)];
    return m;
}

static NSString *AITextList(UIView *v, int depth, int maxDepth) {
    return AITextListD(v, depth, maxDepth, nil);
}

static void AIServeFd(int fd) {
    NSMutableData *req = [NSMutableData data];
    char buf[4096];
    NSData *sep = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
    while (req.length < 65536) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        [req appendBytes:buf length:(NSUInteger)n];
        if ([req rangeOfData:sep options:0 range:NSMakeRange(0, req.length)].location != NSNotFound) break;
    }
    NSString *s = [[NSString alloc] initWithData:req encoding:NSUTF8StringEncoding] ?: @"";
    NSArray *lines = [s componentsSeparatedByString:@"\r\n"];
    NSString *first = lines.count ? lines[0] : @"";
    NSArray *parts = [first componentsSeparatedByString:@" "];
    NSString *tgt = parts.count > 1 ? parts[1] : @"/";
    NSString *path = tgt, *q = @"";
    NSRange qm = [tgt rangeOfString:@"?"];
    if (qm.location != NSNotFound) {
        path = [tgt substringToIndex:qm.location];
        q = [tgt substringFromIndex:qm.location + 1];
    }

    if ([path isEqualToString:@"/overlay"]) {
        NSString *on = AIQv(q, @"on");
        BOOL vis = !(on && ([on isEqualToString:@"0"] || [on isEqualToString:@"false"]
                            || [on isEqualToString:@"off"] || [on isEqualToString:@"hide"]));
        AISetOverlayVisible(vis);
        AIJson(fd, @{@"ok": @YES, @"op": @"overlay", @"visible": @(vis)});
        return;
    }
    if ([path isEqualToString:@"/status"]) {
        AIJson(fd, @{@"ok": @YES, @"proc": gProcName, @"bundle": gBundleId,
                     @"dev": gDevId, @"pid": @(getpid()),
                     @"tap": @(gBestTap), @"shot": @(gBestShot),
                     @"mon": @(gMonHits), @"se": @(gSendEventHits),
                     @"targetViewHits": @(gTargetHits), @"actionHits": @(gActionHits),
                     @"overlay": gOverlayWindow && !gOverlayWindow.hidden ? @"on" : @"off",
                     @"port": @(gSrvPort), @"ip": gSrvIp ?: @""});
        return;
    }
    if ([path isEqualToString:@"/tap"]) {
        CGFloat x = [AIQv(q, @"x") floatValue];
        CGFloat y = [AIQv(q, @"y") floatValue];
        __block BOOL ok = NO;
        AIMainSync(^{ @try { ok = AIFakeTapAtWindowPoint(CGPointMake(x, y)); } @catch (id e) {} });
        AIJson(fd, @{@"ok": @(ok), @"op": @"tap", @"x": @(x), @"y": @(y), @"chan": @(gBestTap)});
        AILog(@"  [http] tap (%.0f,%.0f) -> %@", x, y, ok ? @"OK" : @"FAIL");
        return;
    }
    if ([path isEqualToString:@"/swipe"]) {
        CGFloat x1 = [AIQv(q, @"x1") floatValue], y1 = [AIQv(q, @"y1") floatValue];
        CGFloat x2 = [AIQv(q, @"x2") floatValue], y2 = [AIQv(q, @"y2") floatValue];
        int steps = [AIQv(q, @"steps") intValue]; if (steps < 1) steps = 12;
        double dur = [AIQv(q, @"dur") doubleValue]; if (dur <= 0) dur = 0.35;
        __block BOOL ok = NO;
        AIMainSync(^{ @try { ok = AIFakeSwipe(CGPointMake(x1, y1), CGPointMake(x2, y2), steps, dur); }
                     @catch (id e) {} });
        AIJson(fd, @{@"ok": @(ok), @"op": @"swipe", @"steps": @(steps)});
        AILog(@"  [http] swipe (%.0f,%.0f)->(%.0f,%.0f) -> %@", x1, y1, x2, y2, ok ? @"OK" : @"FAIL");
        return;
    }
    if ([path isEqualToString:@"/shot"]) {
        __block NSData *png = nil;
        AIMainSync(^{
            @try {
                UIImage *im = AIShotByBest();
                png = im ? UIImagePNGRepresentation(im) : nil;
            } @catch (id e) {}
        });
        if (!png) { AIJson(fd, @{@"ok": @NO, @"op": @"shot", @"err": @"no image"}); return; }
        NSString *fmt = AIQv(q, @"fmt");
        if ([fmt isEqualToString:@"b64"]) {
            AIJson(fd, @{@"ok": @YES, @"op": @"shot", @"w": @(0), @"b64": [png base64EncodedStringWithOptions:0]});
        } else {
            AIResp(fd, 200, @"image/png", png);
        }
        AILog(@"  [http] shot -> %luB", (unsigned long)png.length);
        return;
    }
    if ([path isEqualToString:@"/report"]) {
        AIResp(fd, 200, @"text/plain; charset=utf-8",
               [AILogSnapshot() dataUsingEncoding:NSUTF8StringEncoding]);
        return;
    }
    if ([path isEqualToString:@"/log"]) {
        NSString *t = AILogSnapshot();
        NSArray *ls = [t componentsSeparatedByString:@"\n"];
        NSUInteger n = ls.count;
        NSUInteger want = (NSUInteger)[AIQv(q, @"n") integerValue];
        if (want == 0) want = 200;
        NSArray *tail = (n > want) ? [ls subarrayWithRange:NSMakeRange(n - want, want)] : ls;
        AIResp(fd, 200, @"text/plain; charset=utf-8",
               [[tail componentsJoinedByString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]);
        return;
    }
    if ([path isEqualToString:@"/tree"]) {
        __block NSString *tree = @"(none)";
        AIMainSync(^{
            @try {
                UIWindow *w = AIHostWindow();
                UIView *root = w ? (w.rootViewController.view ?: w) : nil;
                if (root) tree = AITreeOf(root, 0, 10);
            } @catch (id e) {}
        });
        AIResp(fd, 200, @"text/plain; charset=utf-8", [tree dataUsingEncoding:NSUTF8StringEncoding]);
        return;
    }
    // 首页：极简说明
    NSString *ip = gSrvIp ?: @"?";
    NSString *help = [NSString stringWithFormat:
        @"AgentInject2 控制 API\n"
        @"  GET /status              -> 状态 JSON\n"
        @"  GET /tap?x=195&y=422     -> 点击屏幕坐标\n"
        @"  GET /swipe?x1=&y1=&x2=&y2=&steps=12&dur=0.35\n"
        @"  GET /shot                -> PNG 截图（/shot?fmt=b64 拿 base64）\n"
        @"  GET /tree                -> 视图树\n"
        @"  GET /overlay?on=0        -> 收起盖屏（必须先做这步，否则点击被盖屏拦截）\n"
        @"  GET /overlay?on=1        -> 恢复盖屏\n"
        @"  GET /report  /log?n=200  -> 报告 / 日志尾\n"
        @"\n本机: http://%@:%d/\n通道: tap=%d shot=%d\n",
        ip, gSrvPort, gBestTap, gBestShot];
    AIResp(fd, 200, @"text/plain; charset=utf-8", [help dataUsingEncoding:NSUTF8StringEncoding]);
}

static void AIServerLoop(int port) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return;
    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((in_port_t)port);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(sfd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(sfd); return; }
    if (listen(sfd, 8) < 0) { close(sfd); return; }
    gSrvPort = port;
    gSrvIp = AIIpAddr();
    AILog(@"  ★ HTTP 控制服务已启动: http://%@:%d/", gSrvIp ?: @"?", port);
    while (1) {
        int fd = accept(sfd, NULL, NULL);
        if (fd < 0) continue;
        @autoreleasepool { AIServeFd(fd); }
        close(fd);
    }
}

static void AIStartServer(void) {
    static BOOL started = NO;
    if (started) return;
    started = YES;
    for (int p = 8080; p <= 8085; p++) {
        // 先试绑一下，成功才起线程
        int t = socket(AF_INET, SOCK_STREAM, 0);
        if (t < 0) return;
        int yes = 1; setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons((in_port_t)p); a.sin_addr.s_addr = INADDR_ANY;
        int r = bind(t, (struct sockaddr *)&a, sizeof(a));
        close(t);
        if (r == 0) {
            int port = p;
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
                AIServerLoop(port);
            });
            return;
        }
    }
    AILog(@"  ❌ 8080-8085 全部绑定失败");
}

// 统一上报：所有结果都 POST 回中继，我在沙箱里 GET /report?dev=... 就能读到
static void AIReportDict(NSDictionary *d) {
    NSMutableDictionary *m = [d mutableCopy];
    m[@"dev"] = gDevId ?: @"?";
    m[@"ts"]  = @((long long)[[NSDate date] timeIntervalSince1970]);
    NSData *bd = [NSJSONSerialization dataWithJSONObject:m options:0 error:nil];
    if (!bd) return;
    @try {
        NSError *e = nil;
        AIHttpErr([(gActiveBase ?: gBase) stringByAppendingString:@"/report"], bd, 15.0, &e);
        if (e) {
            gRepErr++; gLastErrCode = e.code; gLastErrText = e.localizedDescription;
            AILog(@"  ⚠️ 上报失败(%@): %@ (code=%ld)", m[@"op"], e.localizedDescription, (long)e.code);
        } else {
            gRepOK++;
        }
        AIHudApply();
    } @catch (id e) {}
}

static void AIExecCmd(NSDictionary *cmd) {
    NSString *op = cmd[@"op"];
    if (!op) return;
    if ([op isEqualToString:@"tap"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        BOOL ok = NO;
        if (gBestTap == 1 && gDispatch && gBestClient) {
            @try {
                for (int ph = 0; ph < 3; ph++) {
                    IOHIDEventRef ev = NULL;
                    if (gBestTapForm == 0)      ev = AIMakeComposite(x, y, (TPPhase)ph);
                    else if (gBestTapForm == 1) ev = AIMakeBareFinger(x, y, (TPPhase)ph);
                    else                        ev = AIMakeOldFinger(x, y, (TPPhase)ph);
                    if (!ev) continue;
                    if (gSetSender) gSetSender(ev, 0x4001ULL);
                    gDispatch(gBestClient, ev);
                    CFRelease(ev);
                    usleep(60000);
                }
                ok = YES;
            } @catch (id e) {}
        }
        // ★ v13：优先走 sendEvent 正规链路（UIKit 自己 hitTest + 手势识别）。
        //   旧路径（直接调 view.touchesBegan:）只对「自己处理触摸的 view」有效。
        BOOL viaSend = NO;
        if (!ok) {
            @try { viaSend = AIMainSyncBool(^{ return AIDispatchFakeViaSendEvent(CGPointMake(x, y), 2, 0.03); }); }
            @catch (id e) {}
            if (viaSend) ok = YES;   // v14 修复：v13 忘了置位，导致成功后又去跑一遍必定失败的旧路径
        }
        if (!ok && gBestTap == 4) { @try { ok = AIFakeTapAtWindowPoint(CGPointMake(x, y)); } @catch (id e) {} }
        if (!ok) { @try { ok = AITapInProcess(CGPointMake(x, y)); } @catch (id e) {} }
        AILog(@"  [cmd] tap (%.0f,%.0f) 通道%d -> %@ (正规路径:%@)",
              x, y, gBestTap, ok ? @"OK" : @"FAIL", viaSend ? @"成功" : @"未确认");
        AIReportDict(@{@"op": @"tap", @"ok": @(ok), @"viaSendEvent": @(viaSend),
                       @"se": @(gSendEventHits), @"act": @(gActionHits),
                       @"x": @(x), @"y": @(y), @"chan": @(gBestTap)});
    } else if ([op isEqualToString:@"shot"]) {
        UIImage *im = AIShotByBest();
        NSData *png = im ? UIImagePNGRepresentation(im) : nil;
        NSString *b64 = png ? [png base64EncodedStringWithOptions:0] : @"";
        NSDictionary *rep = @{@"dev": gDevId, @"op": @"shot",
                              @"ok": @(b64.length > 0), @"b64": b64};
        NSData *bd = [NSJSONSerialization dataWithJSONObject:rep options:0 error:nil];
        AIReportDict(@{@"op": @"shot", @"ok": @(b64.length > 0), @"b64": b64});
        AILog(@"  [cmd] shot -> %luB", (unsigned long)b64.length);
    } else if ([op isEqualToString:@"swipe"]) {
        CGFloat x1 = [cmd[@"x1"] floatValue], y1 = [cmd[@"y1"] floatValue];
        CGFloat x2 = [cmd[@"x2"] floatValue], y2 = [cmd[@"y2"] floatValue];
        int steps = [cmd[@"steps"] intValue];  if (steps < 1) steps = 12;
        double dur = [cmd[@"dur"] doubleValue]; if (dur <= 0) dur = 0.35;
        __block BOOL ok = NO;
        AIMainSync(^{ @try { ok = AIFakeSwipe(CGPointMake(x1, y1), CGPointMake(x2, y2), steps, dur); }
                     @catch (id e) {} });
        AIReportDict(@{@"op": @"swipe", @"ok": @(ok), @"steps": @(steps)});
        AILog(@"  [cmd] swipe -> %@", ok ? @"OK" : @"FAIL");
    } else if ([op isEqualToString:@"tree"]) {
        int wi = cmd[@"win"] ? [cmd[@"win"] intValue] : gWinIdx;
        __block NSString *tree = @"(none)";
        AIMainSync(^{
            @try {
                int old = gWinIdx; gWinIdx = wi;
                UIWindow *w = AIHostWindow();
                gWinIdx = old;
                // v23：直接从 window 自身开始，不要只走 rootViewController.view ——
                // 侧边栏/弹层常直接挂在 window 上，走 rootVC.view 会整个漏掉。
                if (w) tree = AITreeOf(w, 0, 12);
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"tree", @"ok": @YES, @"tree": tree});
    } else if ([op isEqualToString:@"wins"]) {        // v23：宿主开了哪几个窗口，各自多少节点
        NSMutableArray *lines = [NSMutableArray array];
        NSArray *ws = AIHostWindows();
        for (int i = 0; i < (int)ws.count; i++) {
            UIWindow *w = ws[i];
            CGRect f = w.frame;
            [lines addObject:[NSString stringWithFormat:@"#%d %@ 框(%.0f,%.0f,%.0f,%.0f) 节点%d %@%@%@",
                              i, NSStringFromClass([w class]),
                              f.origin.x, f.origin.y, f.size.width, f.size.height,
                              AICountNodes(w, 0, 14, 600),
                              w.isKeyWindow ? @"[key]" : @"",
                              w.hidden ? @"[hidden]" : @"",
                              (i == gWinIdx) ? @"[已锁定]" : @""]];
        }
        AIReportDict(@{@"op": @"wins", @"ok": @YES, @"lock": @(gWinIdx),
                       @"text": [lines componentsJoinedByString:@"\n"]});
    } else if ([op isEqualToString:@"win"]) {         // v23：把后续操作锁定到某个窗口
        int wi = [cmd[@"i"] intValue];
        gWinIdx = (wi < 0) ? -1 : wi;
        AIReportDict(@{@"op": @"win", @"ok": @YES, @"lock": @(gWinIdx),
                       @"txt": [NSString stringWithFormat:@"已锁定窗口 #%d", gWinIdx]});
    } else if ([op isEqualToString:@"gtap"]) {        // v23：手势直达，专治自绘控件点不动
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSDictionary *r = nil;
        AIMainSync(^{ @try { r = AIGestureTapAt(CGPointMake(x, y)); } @catch (id e) {} });
        NSMutableDictionary *rep = [(r ?: @{@"ok": @NO, @"err": @"异常"}) mutableCopy];
        rep[@"op"] = @"gtap"; rep[@"x"] = @(x); rep[@"y"] = @(y);
        AIReportDict(rep);
        AILog(@"  [cmd] gtap (%.0f,%.0f) -> %@ %@", x, y, rep[@"ok"], rep[@"how"] ?: rep[@"err"]);
    } else if ([op isEqualToString:@"chain"]) {       // v23：某坐标的父链 + 每层挂了什么手势
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSString *s = @"(none)";
        AIMainSync(^{
            @try {
                UIView *hit = AIHitAtPoint(CGPointMake(x, y));
                s = hit ? AIChainOf(hit) : @"(该坐标没命中任何 view)";
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"chain", @"ok": @YES, @"x": @(x), @"y": @(y), @"text": s});
    } else if ([op isEqualToString:@"text"]) {        // v19：读界面文本（带窗口坐标）
        NSString *kw = cmd[@"kw"];
        int wi = cmd[@"win"] ? [cmd[@"win"] intValue] : gWinIdx;
        __block NSString *txt = @"(none)";
        AIMainSync(^{
            @try {
                int old = gWinIdx; gWinIdx = wi;
                UIWindow *w = AIHostWindow();
                gWinIdx = old;
                AIBudgetReset(2500);        // v23：快手单页上千 view，必须设上限
                if (w) txt = AITextList(w, 0, 30);
            } @catch (id e) {}
        });
        if (kw.length) {
            NSMutableString *f = [NSMutableString string];
            for (NSString *line in [txt componentsSeparatedByString:@"\n"])
                if (line.length && [line rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound)
                    [f appendFormat:@"%@\n", line];
            txt = f;
        }
        AIReportDict(@{@"op": @"text", @"ok": @YES, @"text": txt});
    } else if ([op isEqualToString:@"dump"]) {        // v21：按坐标挖这个对象的所有属性（查自绘控件文字藏哪）
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        int deep = cmd[@"deep"] ? [cmd[@"deep"] intValue] : 2;
        __block NSString *s = @"(none)";
        AIMainSync(^{
            @try {
                UIView *hit = AIHitAtPoint(CGPointMake(x, y));   // v23：跨窗口命中
                if (hit) s = AIDumpOf(hit, 0, deep);
                else s = @"(该坐标没命中任何 view)";
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"dump", @"ok": @YES, @"x": @(x), @"y": @(y), @"text": s});
        AILog(@"  [cmd] dump (%.0f,%.0f) deep=%d", x, y, deep);
    } else if ([op isEqualToString:@"update"]) {      // v20：推一份新 dylib 到手机上
        NSString *r = AIUpdateFrom(cmd[@"url"], cmd[@"ver"]);
        AILog(@"  [cmd] update -> %@", r);
        AIReportDict(@{@"op": @"update", @"ok": @([r hasPrefix:@"已装"]), @"txt": r});
    } else if ([op isEqualToString:@"core"]) {        // v20：本地已缓存的 core 一览
        NSString *dir = AICoreDir() ?: @"(无)";
        NSString *have = AINewerCorePath();
        NSArray *fs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
        AIReportDict(@{@"op": @"core", @"ok": @YES, @"ver": kAIVer, @"dir": dir,
                       @"files": fs ?: @[], @"pending": have ?: @""});
    } else if ([op isEqualToString:@"ball"]) {        // v20：悬浮球显隐
        BOOL on = cmd[@"on"] ? ([cmd[@"on"] intValue] != 0) : YES;
        AISetFlag(@"ball", on);
        if (on) { gFloatExpanded = NO; }
        AIFloatApply();
        AIReportDict(@{@"op": @"ball", @"ok": @YES, @"visible": @(on)});
    } else if ([op isEqualToString:@"overlay"]) {
        id ov = cmd[@"on"];
        BOOL vis = ov ? ([ov intValue] != 0) : NO;
        AISetOverlayVisible(vis);
        AIReportDict(@{@"op": @"overlay", @"ok": @YES, @"visible": @(vis)});
    } else if ([op isEqualToString:@"status"]) {
        AIReportDict(@{@"op": @"status", @"ok": @YES, @"ver": kAIVer,
                       @"proc": gProcName, @"bundle": gBundleId, @"pid": @(getpid()),
                       @"tap": @(gBestTap), @"shot": @(gBestShot),
                       @"mon": @(gMonHits), @"se": @(gSendEventHits),
                       @"tvhits": @(gTargetHits), @"act": @(gActionHits),
                       @"overlay": (gOverlayWindow && !gOverlayWindow.hidden) ? @"on" : @"off"});
    } else if ([op isEqualToString:@"log"]) {
        NSString *t = AILogSnapshot();
        AIReportDict(@{@"op": @"log", @"ok": @YES, @"text": t});
    } else if ([op isEqualToString:@"toast"]) {
        // 我主动说话 -> 手机屏幕顶端弹出来。用户只要回一句「看到了」就够了。
        NSString *t = cmd[@"text"] ?: @"(空消息)";
        AIToast(t);
        AIReportDict(@{@"op": @"toast", @"ok": @YES, @"shown": t});
    } else if ([op isEqualToString:@"hud"]) {
        BOOL v = cmd[@"on"] ? ([cmd[@"on"] intValue] != 0) : YES;
        AISetHudVisible(v);
        AIReportDict(@{@"op": @"hud", @"ok": @YES, @"visible": @(v)});
    } else if ([op isEqualToString:@"probe"]) {
        // 我得先看清「这个坐标上到底是什么」，再决定怎么点
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSDictionary *d = nil;
        AIMainSync(^{ @try { d = AIProbeAt(CGPointMake(x, y)); } @catch (id e) {} });
        AILog(@"  [cmd] probe (%.0f,%.0f) -> %@", x, y, d);
        AIReportDict(@{@"op": @"probe", @"ok": @(d != nil), @"x": @(x), @"y": @(y),
                       @"info": d ?: @{@"err": @"probe 返回 nil"}});
    } else if ([op isEqualToString:@"tapui"]) {
        // 直接触发控件 action —— 不是模拟手指，但效果等价且 100% 可靠
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block BOOL ok = NO; __block NSString *desc = nil;
        AIMainSync(^{ @try { ok = AITapUIControlAt(CGPointMake(x, y), &desc); } @catch (id e) {} });
        AILog(@"  [cmd] tapui (%.0f,%.0f) -> %@ %@", x, y, ok ? @"OK" : @"FAIL", desc ?: @"");
        AIReportDict(@{@"op": @"tapui", @"ok": @(ok), @"x": @(x), @"y": @(y),
                       @"desc": desc ?: @"", @"act": @(gActionHits)});
    } else if ([op isEqualToString:@"rows"]) {
        // v15：一眼看清屏幕上有哪些表格行 + 每行的屏幕中心点
        __block NSString *s = @"(none)";
        AIMainSync(^{ @try { AIBudgetReset(3000); s = AIRowsInfo(); } @catch (id e) {} });
        AIReportDict(@{@"op": @"rows", @"ok": @YES, @"text": s});
        AILog(@"  [cmd] rows -> %lu 行", (unsigned long)[s componentsSeparatedByString:@"\n"].count);
    } else if ([op isEqualToString:@"pick"]) {
        // v15：按坐标选中一行（表格行走 delegate，按钮走 sendActions）
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSDictionary *d = nil;
        AIMainSync(^{ @try { d = AIPickAt(CGPointMake(x, y)); } @catch (id e) {} });
        AILog(@"  [cmd] pick (%.0f,%.0f) -> %@", x, y, d);
        AIReportDict(@{@"op": @"pick", @"x": @(x), @"y": @(y), @"info": d ?: @{@"err": @"pick 返回 nil"}});
    } else if ([op isEqualToString:@"picktxt"]) {
        // v15：按文本选中一行 —— 走位最省事的一条指令
        NSString *kw = cmd[@"text"] ?: @"";
        __block NSDictionary *d = nil;
        AIMainSync(^{ @try { AIBudgetReset(3000); d = AIPickByText(kw); } @catch (id e) {} });
        AILog(@"  [cmd] picktxt '%@' -> %@", kw, d);
        AIReportDict(@{@"op": @"picktxt", @"text": kw, @"info": d ?: @{@"err": @"picktxt 返回 nil"}});
    } else if ([op isEqualToString:@"macro"]) {
        // v16：一串动作本地连跑 —— 往返从 N 次降到 1 次，这是提速的关键
        NSArray *steps = cmd[@"steps"];
        double gapMs = [cmd[@"gap"] doubleValue]; if (gapMs <= 0) gapMs = 700;
        if (![steps isKindOfClass:[NSArray class]] || !steps.count) {
            AIReportDict(@{@"op": @"macro", @"ok": @NO, @"err": @"steps 为空"});
            return;
        }
        NSArray *res = AIRunMacro(steps, gapMs);
        AIReportDict(@{@"op": @"macro", @"ok": @YES, @"n": @(res.count), @"results": res});
        AILog(@"  [cmd] macro %lu 步完成", (unsigned long)res.count);
    } else if ([op isEqualToString:@"scroll"]) {
        // v17：伪触摸滑动无效，直接改 contentOffset
        CGPoint p = CGPointMake([cmd[@"x"] floatValue], [cmd[@"y"] floatValue]);
        double dy = [cmd[@"dy"] doubleValue];
        double dx = [cmd[@"dx"] doubleValue];
        BOOL anim = [cmd[@"anim"] respondsToSelector:@selector(boolValue)] ? [cmd[@"anim"] boolValue] : YES;
        __block NSDictionary *d = nil;
        AIMainSync(^{ @try { d = AIScrollAt(p, dy, dx, anim); } @catch (NSException *e) {} });
        AILog(@"  [cmd] scroll dy=%.0f -> %@", dy, d);
        AIReportDict(@{@"op": @"scroll", @"info": d ?: @{@"err": @"scroll 返回 nil"}});
    } else if ([op isEqualToString:@"back"]) {
        // v18：绕开 UI，直接命令导航栈返回（治 Flutter/游戏这类"看得见点不着"的返回键）
        NSString *t = AIBack();
        AILog(@"  [cmd] back -> %@", t);
        AIReportDict(@{@"op": @"back", @"ok": @(![t hasPrefix:@"act=none"]), @"txt": t});
    } else if ([op isEqualToString:@"nav"]) {
        NSString *t = AINavInfo();
        AILog(@"  [cmd] nav:\n%@", t);
        AIReportDict(@{@"op": @"nav", @"ok": @YES, @"txt": t});
    } else if ([op isEqualToString:@"diag"]) {
        NSString *s = AINetDiag();
        gDiagText = s;
        AIHudApply();
        AIReportDict(@{@"op": @"diag", @"ok": @YES, @"text": s});
    }
}

// HUD 每秒刷一次：轮询的成败数字是活的，卡住不刷新本身就是一种诊断信息。
static void AIHudTickLoop(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try { AIHudApply(); } @catch (id e) {}
        AIHudTickLoop();
    });
}

static BOOL gNetStarted = NO;
// v16：自适应轮询间隔（刚干完活 -> 0.35s 快轮询；空闲 -> 逐步退回 2.5s）
static double gPollGap = 2.0;
static double gLastBeat = 0;

static void AINetLoop(void) {
    if (gNetStarted) return;    // 幂等：早期先起一次网络，后面再调不会重复启动
    gNetStarted = YES;
    AILog(@"==== [6] 控制通道 ====");

    // 开机先做一次裸 TCP 探测，结论直接写到状态条上 —— 不用等用户点任何按钮。
    // 这样即使 NSURLSession 全程 -1009，我也能立刻知道 TCP 层到底通不通。
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSString *t1 = AITcpTest("49.233.240.214", 443, 6.0);
            NSString *t2 = AITcpTest("220.181.38.148", 443, 6.0);
            gDiagText = [NSString stringWithFormat:@"⓪裸TCP 中继%@ 百度%@", t1, t2];
            AILog(@"  [0c] 裸 TCP 探测: 中继(%@) 百度(%@)", t1, t2);
            AIHudApply();
        }
    });
    @try { AIStartServer(); AISleep(0.6); } @catch (NSException *e) { AILog(@"  服务启动异常 %@", e); }  // 等端口真正 bind 上再打印
    gBase = AIBase();
    gActiveBase = gBase;
    AILog(@"  版本=%@ 中继: %@", kAIVer, gBase);
    if ([gBase containsString:@"invalid"]) { AILog(@"  地址无效，轮询不启动"); AIHudApply(); return; }

    // 后台任务：锁屏/切走后尽量多撑一会儿，别一退后台就断线
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIApplication *ap = [UIApplication sharedApplication];
            gBgTask = [ap beginBackgroundTaskWithName:@"AIPoll" expirationHandler:^{
                @try { if (gBgActive) [ap endBackgroundTask:gBgTask]; } @catch (id e) {}
                gBgActive = NO; gBgTask = 0;
            }];
            gBgActive = (gBgTask != 0);
            AILog(@"  后台任务: %@", gBgActive ? @"已申请（锁屏后能多撑一会儿）" : @"申请失败");
        } @catch (id e) {}
    });

    AIHudApply();
    AIHudTickLoop();

    // 上线即报到：我在中继那边 GET /peek 就能看到这台设备的 dev id
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        AIReportDict(@{@"op": @"hello", @"proc": gProcName, @"bundle": gBundleId,
                       @"pid": @(getpid()), @"ver": kAIVer, @"tap": @(gBestTap), @"shot": @(gBestShot),
                       @"tvhits": @(gTargetHits), @"act": @(gActionHits)});
        AILog(@"  已向中继报到 dev=%@  中继=%@", gDevId, gBase);
    });
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        int failRun = 0;
        while (1) {
            @autoreleasepool {
                @try {
                    NSString *u = [gActiveBase stringByAppendingFormat:@"/poll?dev=%@", gDevId];
                    NSError *pe = nil; NSData *d = nil;
                    BOOL ok = AIHttpEx(u, nil, 8.0,
                                       [gActiveBase hasPrefix:@"https://4"],   // IP 兜底时才信任任意证书
                                       [gActiveBase hasPrefix:@"https://4"] ? @"aa0c466b5cdb559bb.app.workbuddy.host" : nil,
                                       &d, &pe, NULL, NULL);
                    if (ok) {
                        gPollOK++; failRun = 0;
                        if (gPollOK == 1) {
                            AILog(@"  ✅ 首次轮询成功，已上线 -> %@", gActiveBase);
                            AIShowOverlay();     // 立刻把结论刷到盖屏上，不用用户做任何操作
                        }
                    } else {
                        gPollErr++; failRun++;
                        gLastErrCode = pe ? pe.code : -999;
                        gLastErrText = pe.localizedDescription;
                        AILog(@"  ⚠️ 轮询失败: %@ (code=%ld)", pe.localizedDescription, (long)gLastErrCode);
                        if (gPollErr == 1 || gPollErr == 3) AIShowOverlay();   // 首败/三败时刷一次盖屏，别让用户看旧快照
                        // 域名连续挂 4 次 -> 切 IP 直连兜底（DNS 被污染时救命）
                        if (failRun >= 4 && ![gActiveBase hasPrefix:@"https://4"]) {
                            gActiveBase = @"https://49.233.240.214";
                            AILog(@"  ↩️ 域名不通，切换 IP 直连兜底: %@", gActiveBase);
                            failRun = 0;
                        }
                    }
                    BOOL gotCmd = NO;
                    if (d.length) {
                        id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                        if ([j isKindOfClass:[NSDictionary class]]) { gCmdGot++; AIExecCmd(j); gotCmd = YES; }
                        else if ([j isKindOfClass:[NSArray class]]) {
                            NSArray *arr = (NSArray *)j;
                            gotCmd = arr.count > 0;
                            for (NSDictionary *c in arr) { gCmdGot++; AIExecCmd(c); }
                        }
                    }
                    // v16 自适应轮询：刚执行过指令说明"正在被操作"，立刻切快轮询抓紧接下一串；
                    // 空闲下来再逐步退回慢轮询省电。固定 2 秒是之前最大的速度瓶颈。
                    if (gotCmd) gPollGap = 0.35;
                    else        gPollGap = MIN(gPollGap * 1.7, 2.5);
                } @catch (NSException *e) {}
            }
            // beat 改成按时间（20 秒一次），不再按轮询次数 —— 次数会随 gap 变化而失控
            double now = [[NSDate date] timeIntervalSince1970];
            if (now - gLastBeat > 20) {
                gLastBeat = now;
                AIReportDict(@{@"op": @"beat", @"ver": kAIVer, @"tap": @(gBestTap), @"shot": @(gBestShot),
                               @"tvhits": @(gTargetHits), @"act": @(gActionHits), @"gap": @(gPollGap)});
            }
            [NSThread sleepForTimeInterval:gPollGap];
        }
    });
    AILog(@"  轮询已启动(%@) -> %@", kAIVer, gBase);
}

// ---------------------------------------------------------------------------
// 13. 盖屏报告
// ---------------------------------------------------------------------------
// 复制按钮的 target：把整份报告塞进系统剪贴板，用户直接粘贴回来，
// 不用手打、也不依赖截图能不能传过来。
@interface AIReportTarget : NSObject
@end
@implementation AIReportTarget
- (void)testTapButton:(id)sender  { AITestTapButton(); }
- (void)pingNow:(id)sender {
    AILog(@"==== [8] 手动上报 ====");
    AILog(@"  中继=%@ dev=%@", gBase, gDevId);
    NSError *e = nil;
    NSData *r = AIHttpErr([gBase stringByAppendingFormat:@"/poll?dev=%@", gDevId], nil, 10.0, &e);
    if (e) { AILog(@"  ❌ 轮询失败: %@ (code=%ld)", e.localizedDescription, (long)e.code); }
    else   { AILog(@"  ✅ 轮询成功，收到 %lu 字节", (unsigned long)(r ? r.length : 0)); }
    AIReportDict(@{@"op": @"status", @"ok": @YES, @"proc": gProcName, @"bundle": gBundleId,
                   @"tap": @(gBestTap), @"shot": @(gBestShot), @"act": @(gActionHits)});
    AILog(@"  已上报 status，看上面有没有 ⚠️ 上报失败");
    AIShowOverlay();
}
- (void)netDiag:(id)sender {
    AILog(@"==== [9] 网络自检（结果会写在屏幕顶端） ====");
    gDiagText = @"自检中…";
    AIHudApply();
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSString *s = AINetDiag();
            gDiagText = s;
            AIHudApply();
            AILog(@"  自检结果已写到屏幕顶端状态条");
        }
    });
}
- (void)toggleHud:(id)sender {
    AISetHudVisible(!gHudWanted);
    AILog(@"  顶端状态条: %@", gHudWanted ? @"显示" : @"隐藏");
}
- (void)testTapCenter:(id)sender  {
    CGSize sc = [UIScreen mainScreen].bounds.size;
    AITestTapAt(CGPointMake(sc.width * 0.5, sc.height * 0.5), @"屏幕中心");
}
- (void)toggleOverlay:(id)sender {
    BOOL nowVisible = gOverlayWindow ? !gOverlayWindow.hidden : NO;
    AISetOverlayVisible(!nowVisible);   // 可见就收起，收起就放回
}
- (void)copyTail:(id)sender {
    @try {
        [gLogLock lock]; NSString *t = [gLog copy]; [gLogLock unlock];
        NSArray *lines = [t componentsSeparatedByString:@"\n"];
        NSArray *tail = ([lines count] > 25) ? [lines subarrayWithRange:NSMakeRange([lines count] - 25, 25)] : lines;
        NSString *short1 = [NSString stringWithFormat:@"AI2 结论 tap=%d shot=%d se=%d tvhits=%d act=%d\n---\n%@",
                            gBestTap, gBestShot, gSendEventHits, gTargetHits, gActionHits,
                            [tail componentsJoinedByString:@"\n"]];
        [UIPasteboard generalPasteboard].string = short1;
        AILog(@"已复制结论（%lu 字符）", (unsigned long)short1.length);
    } @catch (NSException *e) { AILog(@"复制异常 %@", e); }
}
- (void)copyReport:(id)sender {
    @try {
        [gLogLock lock]; NSString *t = [gLog copy]; [gLogLock unlock];
        [UIPasteboard generalPasteboard].string = t;
        AILog(@"报告已复制到剪贴板（%lu 字符）", (unsigned long)t.length);
        // 复制完给个视觉反馈
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"已复制"
                                                                       message:[NSString stringWithFormat:@"%lu 字符，去聊天里长按粘贴", (unsigned long)t.length]
                                                                preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            @try {
                UIViewController *root = gOverlayWindow ? gOverlayWindow.rootViewController : nil;
                if (root) [root presentViewController:ac animated:YES completion:nil];
            } @catch (NSException *e) {}
        });
    } @catch (NSException *e) { AILog(@"复制异常 %@", e); }
}
@end
static AIReportTarget *gRT = nil;

// ★ 关键修复：UIWindow 必须用 static 强引用持有。
//   上一版它是局部变量，makeKeyAndVisible 后 ARC 立刻释放，窗口活不下来
//   —— 这就是「注入了但什么都没出现」最可能的原因。

// ---------------------------------------------------------------------------
// v10：顶端常驻状态条（HUD）
//
//   独立于盖屏存在 —— 收起盖屏做点击测试时它也还在，所以我能一直看到网络状态。
//   userInteractionEnabled=NO，不拦截任何点击。
// ---------------------------------------------------------------------------
static UIWindowScene *AIFirstWindowScene(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if (!app || ![app respondsToSelector:@selector(connectedScenes)]) return nil;
    id scenes = [app performSelector:@selector(connectedScenes)];
    if (![scenes isKindOfClass:[NSSet class]]) return nil;
    for (id sc in (NSSet *)scenes) if ([sc isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)sc;
    return nil;
}

static NSString *AIHudText(void) {
    NSString *net;
    if (gPollOK > 0) {
        net = (gPollErr > 0) ? [NSString stringWithFormat:@"网✅%d/❌%d", gPollOK, gPollErr]
                             : [NSString stringWithFormat:@"网✅%d", gPollOK];
    } else if (gPollErr > 0) {
        net = [NSString stringWithFormat:@"网❌%ld", gLastErrCode];
    } else {
        net = @"网…";
    }
    NSString *did = gDevId ?: @"?";
    if (did.length > 8) did = [did substringFromIndex:did.length - 8];
    NSString *s = [NSString stringWithFormat:@"%@ %@ 报%d/%d 令%d", kAIVer, net, gRepOK, gRepErr, gCmdGot];
    if (gToastText.length)     s = [s stringByAppendingFormat:@"\n📢 %@", gToastText];
    else if (gDiagText.length) s = [s stringByAppendingFormat:@"\n%@", gDiagText];
    else                       s = [s stringByAppendingFormat:@" dev=%@", did];
    return s;
}

static void AIHudApply(void) {
    if (!gHudWanted || gIsSpringBoard) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            CGRect f = [UIScreen mainScreen].bounds;
            CGFloat h = (gToastText.length || gDiagText.length) ? 56 : 26;
            CGRect hf = CGRectMake(0, 0, f.size.width, h);
            if (!gHudWindow) {
                UIWindowScene *sc = AIFirstWindowScene();
                if (sc) {
                    // ★ v11 修复：iOS 13+ 必须用 initWithWindowScene:。用 initWithFrame:
                    //   建出来的 UIWindow 不属于任何 scene —— 它会显示，但 scene 不认它，
                    //   makeKeyAndVisible 之后【按键事件投递链会断掉】，表现就是
                    //   sendEvent 计数永远是 0、屏幕上点哪儿都没反应。
                    //   v10 的 se=0 就是这个原因（v9 时还是 se=366~398）。
                    gHudWindow = [[UIWindow alloc] initWithWindowScene:sc];
                    gHudWindow.frame = hf;
                } else {
                    gHudWindow = [[UIWindow alloc] initWithFrame:hf];
                }
                gHudWindow.windowLevel = UIWindowLevelStatusBar + 500;
                gHudWindow.backgroundColor = [UIColor clearColor];
                gHudWindow.userInteractionEnabled = NO;   // 绝不能挡住点击
                UIView *bg = [[UIView alloc] initWithFrame:hf];
                bg.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.78];
                gHudLabel = [[UILabel alloc] initWithFrame:CGRectMake(4, 0, f.size.width - 8, h)];
                gHudLabel.numberOfLines = 0;
                gHudLabel.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:11];
                gHudLabel.textAlignment = NSTextAlignmentCenter;
                [bg addSubview:gHudLabel];
                UIViewController *vc = [UIViewController new];
                vc.view = bg;
                gHudWindow.rootViewController = vc;

                // ★ 绝不能用 makeKeyAndVisible —— 那会把 App 自己的窗口挤成非 key，
                //   事件链直接断掉（v10 实测 se=0 的元凶之一）。
                //   只显示、不抢 key。
                gHudWindow.hidden = NO;
            }
            gHudWindow.frame = hf;
            gHudWindow.hidden = NO;
            gHudLabel.frame = CGRectMake(4, 0, f.size.width - 8, h);
            gHudLabel.text = AIHudText();
            gHudLabel.textColor = (gPollOK > 0) ? [UIColor greenColor]
                                : ((gPollErr > 0) ? [UIColor redColor] : [UIColor yellowColor]);
            // v20：顺手把悬浮球上的心跳数字也刷一下（内部有 1.5s 节流）
            @try { AIFloatApply(); } @catch (id e) {}
        } @catch (NSException *e) {}
    });
}

static void AISetHudVisible(BOOL vis) {
    gHudWanted = vis;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try { gHudWindow.hidden = !vis; if (vis) AIHudApply(); } @catch (id e) {}
    });
}

// 我从中继下发的一句话直接弹到手机屏幕上：
// 用户什么都不用做，只要告诉我「看到了 / 没看到」，链路通不通立刻有结论。
static void AIToast(NSString *txt) {
    if (!txt.length) return;
    gToastText = txt;
    AILog(@"  📢 收到中继消息: %@", txt);
    AIHudApply();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ gToastText = nil; AIHudApply(); });
}

// ---------------------------------------------------------------------------
// v12：原始 BSD socket 连通性测试
//
//   为什么必须有这个：真机实测所有 NSURLSession 请求都返回 -1009
//   （"The Internet connection appears to be offline"），但这句话太笼统了 ——
//   它既可能是「真的没网」，也可能是「沙箱不让这个 App 联网」，
//   还可能是「只有 CFNetwork 被拦，裸 socket 反而能通」。
//
//   下面的测试用 connect() 直接连 IP:443，绕开 CFNetwork / TLS / ATS / 代理，
//   只看 TCP 层能不能出去。三种结果对应三种完全不同的病因：
//     ✅ TCP 能连上     -> 网络没问题，是 CFNetwork/ATS 被拦 -> 换裸 socket 发 HTTP 就完事
//     ❌ 报 ERRNODEV/ENETDOWN -> 系统确实认为无网（或该 App 被禁网）
//     ❌ 报 EHOSTUNREACH/ETIMEDOUT -> 网络可达但被中间设备阻断（热点限制/运营商）
// ---------------------------------------------------------------------------
static NSString *AITcpTest(const char *host, int port, double tmoSec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return [NSString stringWithFormat:@"socket()=%d(%s)", errno, strerror(errno)];

    // 非阻塞 + select 超时，避免卡死主线程
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &a.sin_addr);

    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    int saved = errno;
    if (r == 0) { close(fd); return @"✅TCP已连"; }

    if (saved == EINPROGRESS) {
        fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
        struct timeval tv; tv.tv_sec = (long)tmoSec; tv.tv_usec = 0;
        int sel = select(fd + 1, NULL, &wf, NULL, &tv);
        if (sel > 0) {
            int soerr = 0; socklen_t l = sizeof(soerr);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
            close(fd);
            if (soerr == 0) return @"✅TCP已连";
            return [NSString stringWithFormat:@"❌%d(%s)", soerr, strerror(soerr)];
        }
        close(fd);
        return sel == 0 ? @"❌超时" : [NSString stringWithFormat:@"❌select=%d(%s)", errno, strerror(errno)];
    }
    close(fd);
    return [NSString stringWithFormat:@"❌%d(%s)", saved, strerror(saved)];
}

// 网络自检：五个目标各打一次，把结果写进 gDiagText 直接画在屏幕顶端。
// 这样「到底是一点网都没有、还是只有我们这个域名不通、还是 DNS 挂了」一目了然。
static NSString *AINetDiag(void) {
    NSMutableString *s = [NSMutableString string];
    NSData *out = nil; NSError *e = nil; NSInteger code = 0; NSTimeInterval ms = 0;

    // 0) 裸 socket：绕开 CFNetwork，只看 TCP 层
    NSString *t1 = AITcpTest("49.233.240.214", 443, 6.0);
    NSString *t2 = AITcpTest("220.181.38.148", 443, 6.0);   // 百度，对照组
    [s appendFormat:@"⓪裸TCP 中继%@ 百度%@\n", t1, t2];

    // 1) 对照组：苹果官网。这个都不通 = 手机压根没网
    BOOL ok1 = AIHttpEx(@"https://www.apple.com/library/test/success.html", nil, 10.0,
                        NO, nil, &out, &e, &code, &ms);
    [s appendFormat:@"①苹果 %@ %@\n", ok1 ? @"✅" : @"❌",
     ok1 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 2) 主链路：域名 HTTPS 轮询
    NSString *base = gActiveBase ?: gBase ?: AIBase();
    e = nil; code = 0; ms = 0;
    BOOL ok2 = AIHttpEx([base stringByAppendingFormat:@"/poll?dev=%@", gDevId], nil, 10.0,
                        NO, nil, &out, &e, &code, &ms);
    [s appendFormat:@"②中继域名 %@ %@\n", ok2 ? @"✅" : @"❌",
     ok2 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 3) 兜底：IP 直连 + 信任证书 + 覆盖 Host（域名 DNS 挂了就靠这条）
    e = nil; code = 0; ms = 0;
    BOOL ok3 = AIHttpEx(@"https://49.233.240.214/poll?dev=DIAG", nil, 10.0,
                        YES, @"aa0c466b5cdb559bb.app.workbuddy.host", &out, &e, &code, &ms);
    [s appendFormat:@"③IP直连 %@ %@\n", ok3 ? @"✅" : @"❌",
     ok3 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 4) 上报能不能出去
    e = nil; code = 0; ms = 0;
    NSData *bd = [NSJSONSerialization dataWithJSONObject:@{@"dev": gDevId ?: @"?", @"op": @"diag"} options:0 error:nil];
    BOOL ok4 = AIHttpEx([base stringByAppendingString:@"/report"], bd, 10.0, NO, nil, &out, &e, &code, &ms);
    [s appendFormat:@"④上报 %@ %@", ok4 ? @"✅" : @"❌",
     ok4 ? [NSString stringWithFormat:@"%ld", (long)code] : [NSString stringWithFormat:@"%ld", (long)e.code]];

    AILog(@"==== [9] 网络自检 ====\n%@", s);
    return s;
}

static void AIShowOverlayText(NSString *txt, BOOL done, NSString *banner) {
    if (gIsSpringBoard) { AILog(@"SpringBoard 进程，跳过盖屏"); return; }
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            CGRect f = [UIScreen mainScreen].bounds;
            if (!gOverlayWindow) {
                gOverlayWindow = [[UIWindow alloc] initWithFrame:f];
                gOverlayWindow.windowLevel = UIWindowLevelStatusBar + 100;
                gOverlayWindow.backgroundColor = [UIColor blackColor];
            }
            gOverlayWindow.frame = f;

            UIView *root = [[UIView alloc] initWithFrame:f];
            root.backgroundColor = [UIColor blackColor];

            CGFloat top = 62;   // 上方 60pt 留给 v10 常驻状态条（HUD），别被它压住
            if (banner) {
                // 结论横幅：放最顶部，大字，一眼能看到，不用滚
                UILabel *bl = [[UILabel alloc] initWithFrame:CGRectMake(6, 30, f.size.width - 12, 40)];
                bl.textColor = [UIColor whiteColor];
                bl.backgroundColor = [UIColor redColor];
                bl.font = [UIFont boldSystemFontOfSize:15];
                bl.textAlignment = NSTextAlignmentCenter;
                bl.numberOfLines = 2;
                bl.text = banner;
                [root addSubview:bl];
                top = 78;
            }

            if (done) {
                // ★ v10 修复：v6~v9 里 b3~b6 全部漏了 addSubview，而且 frame 都写成
                //   (162, top) 互相重叠 —— 结果「收起盖屏 / 实测点击 / 立即上报」
                //   这三个按钮从来没出现在屏幕上，点了也没反应。
                //   改成统一的「两列网格」构造器，逐个 addSubview，杜绝再漏。
                if (!gRT) gRT = [AIReportTarget new];
                CGFloat bw = (f.size.width - 18) / 2.0;
                // 注意：ARC 禁止 struct 内嵌 OC 对象，所以标题/SEL/配色拆成三个平行的 C 数组
                NSString *bt[] = {@"复制结论(短)", @"复制全文(长)",
                                  @"收起盖屏(露出App)", @"▶ 实测:点App第一个按钮",
                                  @"▶ 实测:点屏幕中心", @"▶ 立即上报(让我看到你)",
                                  @"▶ 网络自检(结果写屏上)", @"显示/隐藏 顶端状态条"};
                SEL ba[] = {@selector(copyTail:), @selector(copyReport:),
                            @selector(toggleOverlay:), @selector(testTapButton:),
                            @selector(testTapCenter:), @selector(pingNow:),
                            @selector(netDiag:), @selector(toggleHud:)};
                UIColor *bc[] = {[UIColor colorWithWhite:0.25 alpha:1],
                                 [UIColor colorWithWhite:0.25 alpha:1],
                                 [UIColor colorWithWhite:0.25 alpha:1],
                                 [UIColor colorWithRed:0.10 green:0.35 blue:0.15 alpha:1],
                                 [UIColor colorWithRed:0.10 green:0.35 blue:0.15 alpha:1],
                                 [UIColor colorWithRed:0.45 green:0.15 blue:0.15 alpha:1],
                                 [UIColor colorWithRed:0.15 green:0.25 blue:0.45 alpha:1],
                                 [UIColor colorWithWhite:0.25 alpha:1]};
                for (int i = 0; i < 8; i++) {
                    CGFloat bx = (i % 2 == 0) ? 6 : (12 + bw);
                    CGFloat by = top + (i / 2) * 42;
                    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
                    b.frame = CGRectMake(bx, by, bw, 38);
                    b.backgroundColor = bc[i];
                    [b setTitle:bt[i] forState:UIControlStateNormal];
                    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                    b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
                    b.titleLabel.adjustsFontSizeToFitWidth = YES;
                    [b addTarget:gRT action:ba[i] forControlEvents:UIControlEventTouchUpInside];
                    [root addSubview:b];
                }
                top += 42 * 4;
            } else {
                UILabel *h = [[UILabel alloc] initWithFrame:CGRectMake(8, top, f.size.width - 16, 36)];
                h.textColor = [UIColor yellowColor];
                h.font = [UIFont boldSystemFontOfSize:13];
                h.text = @"AgentInject2 已加载 · 正在自检…";
                [root addSubview:h];
                top += 40;
            }

            UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, top, f.size.width, f.size.height - top)];
            sv.backgroundColor = [UIColor blackColor];
            UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(8, 8, f.size.width - 16, 0)];
            lb.numberOfLines = 0;
            lb.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:10];
            lb.textColor = done ? [UIColor greenColor] : [UIColor yellowColor];
            lb.text = txt;
            [lb sizeToFit];
            sv.contentSize = CGSizeMake(f.size.width, lb.bounds.size.height + 60);
            [sv addSubview:lb];
            [root addSubview:sv];

            UIViewController *vc = [UIViewController new];
            vc.view = root;
            gOverlayWindow.rootViewController = vc;

            // ★ 盖屏是「操作界面」，它确实需要能接收点击，所以它用 makeKeyAndVisible
            //   是对的。但必须保证它在窗口层级里【只被 makeKey 一次】，不能反复抢。
            if (!gOverlayWindow.isKeyWindow) [gOverlayWindow makeKeyAndVisible];
            else gOverlayWindow.hidden = NO;

            // 盖屏一显示就把 HUD 拉回来 —— 否则 HUD 会被盖屏压在下面看不见，
            // 用户就没法把「网✅/网❌」念给我听了。
            if (gHudWanted) AIHudApply();
            AILog(@"盖屏已刷新（%lu 字符, done=%d）", (unsigned long)txt.length, done);
        } @catch (NSException *e) { AILog(@"盖屏异常 %@", e); }
    });
}

// 找到 App 里第一个可见、可交互的 UIButton，返回它的屏幕中心坐标
static BOOL AIFindFirstButton(CGPoint *outPt, NSString **outDesc) {
    UIWindow *w = AIHostWindow();
    if (!w) return NO;
    NSMutableArray *q = [NSMutableArray arrayWithObject:(w.rootViewController.view ?: w)];
    int guard = 0;
    while (q.count && guard++ < 4000) {
        UIView *v = q.firstObject;
        [q removeObjectAtIndex:0];
        if (!v || v.hidden || v.alpha < 0.05) continue;
        if ([v isKindOfClass:[UIButton class]] && v.userInteractionEnabled) {
            CGRect r = [v convertRect:v.bounds toView:nil];
            CGPoint c = CGPointMake(CGRectGetMidX(r), CGRectGetMidY(r));
            if (outPt) *outPt = c;
            if (outDesc) *outDesc = [NSString stringWithFormat:@"UIButton(%@) 屏幕中心(%.0f,%.0f)",
                                     NSStringFromClass([v class]), c.x, c.y];
            return YES;
        }
        for (UIView *sub in v.subviews) [q addObject:sub];
    }
    return NO;
}

// 【一键实测】在 App 内完成整个闭环，不需要电脑、不需要第二台设备。
// 主线程上：收起盖屏（露出 App） -> 等一拍 -> 发点击 -> 等一拍 -> 记录 -> 恢复盖屏刷新报告。
static void AITestTapAt(CGPoint pt, NSString *desc) {
    AILog(@"==== [7] 真实点击实测 %@ ====", desc ?: @"");
    int a0 = gActionHits;
    int t0 = gTargetHits;

    BOOL hadOverlay = (gOverlayWindow && !gOverlayWindow.hidden);
    if (hadOverlay) { gOverlayWindow.hidden = YES; AISleep(0.5); }

    AILog(@"  盖屏已收起，点 (%.0f,%.0f)", pt.x, pt.y);
    BOOL ok = AIFakeTapAtWindowPoint(pt);
    AISleep(0.5);

    AILog(@"  投递=%@   ★控件事件 sendAction +%d (%@)   touchesBegan +%d",
          ok ? @"已投递" : @"失败", gActionHits - a0, gLastAction ?: @"-", gTargetHits - t0);

    if (hadOverlay) {
        gOverlayWindow.hidden = NO;
        [gOverlayWindow makeKeyAndVisible];
        AISleep(0.2);
        AIShowOverlay();
    }
}

static void AITestTapButton(void) {
    CGPoint pt = CGPointZero;
    NSString *desc = nil;
    if (!AIFindFirstButton(&pt, &desc)) { AILog(@"  没找到可点的 UIButton"); AIShowOverlay(); return; }
    AITestTapAt(pt, desc);
}

static void AIShowOverlay(void) {
    [gLogLock lock]; NSString *txt = [gLog copy]; [gLogLock unlock];
    NSString *banner = [NSString stringWithFormat:@"AI2 %@ 结论 tap=%d shot=%d se=%d tvhits=%d act=%d | 网✅%d/❌%d 报%d/%d",
                        kAIVer, gBestTap, gBestShot, gSendEventHits, gTargetHits, gActionHits,
                        gPollOK, gPollErr, gRepOK, gRepErr];
    AIShowOverlayText(txt, YES, banner);
}

// 盖屏开关：盖屏在的时候会拦截所有 hitTest，API 点击根本到不了 App。
// 所以必须能一键收起来。hidden 只是把窗口藏起来，对象还留着，随时能放回来。
static void AISetOverlayVisible(BOOL vis) {
    if (!gOverlayWindow) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        gOverlayWindow.hidden = !vis;
        if (vis) [gOverlayWindow makeKeyAndVisible];
        AILog(@"  [overlay] 盖屏已%@", vis ? @"恢复显示" : @"收起（露出 App，API 点击生效）");
    });
}

// ---------------------------------------------------------------------------
// 14. 启动
// ---------------------------------------------------------------------------
static void AIBoot(void) {
    if (gBooted) return;
    gBooted = YES;
    AILog(@"########## AgentInject2 boot ##########");
    AILog(@"boot 触发来源: %@", gBootSrc);
    // v20：默认不再糊一层全屏盖屏（用户吐槽太碍事），只挂一个可拖动的小悬浮球。
    // 想要全屏诊断报告的，在悬浮球面板里把「诊断盖屏」打开。
    @try { AIFloatApply(); } @catch (NSException *e) { AILog(@"float 异常 %@", e); }
    if (AIFlag(@"sw1", NO)) AIShowOverlayText(@"AgentInject2 已加载 ✓\n正在自检，请稍候…", NO, nil);
    // 后台看看仓库里有没有比我新的版本（有就先下下来，下次重开 App 生效）
    if (AIFlag(@"autoupd", YES)) { @try { AICheckUpdateAsync(); } @catch (NSException *e) {} }

    @try { AIEnv(); }          @catch (NSException *e) { AILog(@"env 异常 %@", e); }
    // ★ 网络尽早起来：放在耗时的 HID 矩阵测试之前。
    //   不然一旦某个自检环节卡住/崩了，就永远走不到联网，我这边只能看到「设备不上线」。
    @try { AINetLoop(); }      @catch (NSException *e) { AILog(@"net 异常 %@", e); }
    @try { AIDumpWindows(); }  @catch (NSException *e) { AILog(@"win 异常 %@", e); }
    @try { AIHookSendEvent(); } @catch (NSException *e) { AILog(@"hook 异常 %@", e); }
    @try { AIHookSendAction(); } @catch (NSException *e) { AILog(@"hookAction 异常 %@", e); }
    @try { AILoadHID(); }      @catch (NSException *e) { AILog(@"loadHID 异常 %@", e); }

    // HID 测试必须在有 runloop 的线程上（monitor 回调靠它）
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CFRunLoopRef rl = CFRunLoopGetCurrent();
        @try { AISetupMonitor(rl); } @catch (NSException *e) { AILog(@"monitor 异常 %@", e); }
        @try { AIHidMatrix(rl); }    @catch (NSException *e) { AILog(@"matrix 异常 %@", e); }

        dispatch_async(dispatch_get_main_queue(), ^{
            @try { AIDumpTouchAPI(); } @catch (NSException *e) { AILog(@"dump 异常 %@", e); }
            // 进程内 UIKit 路线补测
            @try {
                AILog(@"==== [3b] 进程内 UIKit 合成 ====");
                int s0 = gSendEventHits;
                CGSize s = [UIScreen mainScreen].bounds.size;
                BOOL ok = AITapInProcess(CGPointMake(s.width * 0.5, s.height * 0.5));
                usleep(500000);
                AILog(@"  AITapInProcess -> %@ sendEvent+%d", ok ? @"已投递" : @"失败", gSendEventHits - s0);
                if (gSendEventHits - s0 > 0 && gBestTap == 0) { gBestTap = 2; AILog(@"  ↑ 选定为进程内 UIKit 通道"); }
            } @catch (NSException *e) { AILog(@"inproc 异常 %@", e); }
            @try { AIFakeTapTest(); } @catch (NSException *e) { AILog(@"faketap 异常 %@", e); }
            @try { AITargetViewTest(); } @catch (NSException *e) { AILog(@"targetview 异常 %@", e); }
            @try { AIControlProbe(); } @catch (NSException *e) { AILog(@"control 异常 %@", e); }
            @try { AIShotMatrix(); } @catch (NSException *e) { AILog(@"shot 异常 %@", e); }
            @try { AINetLoop(); }    @catch (NSException *e) { AILog(@"net 异常 %@", e); }

            AILog(@"########## 结论: tap=%d shot=%d mon=%d se=%d tvhits=%d act=%d ##########",
                  gBestTap, gBestShot, gMonHits, gSendEventHits, gTargetHits, gActionHits);
            if (gSrvPort) AILog(@"########## 控制: http://%@:%d/status ##########", gSrvIp ?: @"?", gSrvPort);
            @try { AIWriteReport(); } @catch (NSException *e) {}
            @try { AIFloatApply(); }  @catch (NSException *e) {}
            if (AIFlag(@"sw1", NO)) { @try { AIShowOverlay(); } @catch (NSException *e) {} }
        });
    });
}

// CFNotificationCenterAddObserver 只接受【函数指针】(CFNotificationCallback)，
// 不能传 block —— 传 block 会报 incompatible type 编译错误。
static void AINotifyCb(CFNotificationCenterRef c, void *o, CFStringRef n,
                       const void *obj, CFDictionaryRef ui) {
    (void)c; (void)o; (void)n; (void)obj; (void)ui;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!gBooted) gBootSrc = @"通知(didFinishLaunching+6s)";
        @try { AIBoot(); } @catch (NSException *e) { NSLog(@"[AI2] boot ex %@", e); }
    });
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 14b. v20：内置更新（OTA）—— 注入一次，以后我推新版你只要重开 App
//
//   背景：用户受够了「每改一版就要 TrollFools 重新注入一遍」。
//
//   机制（两阶段，进程内不卸载旧 dylib）：
//     ① 注入进去的这份 dylib 自己就是一个「引导器」：启动时去沙盒
//        Documents/agentcore/ 里翻一翻，如果有【版本比自己新】的
//        AgentInject2-vNN.dylib，就 dlopen 它、调它的 AgentCoreStart，
//        然后自己直接退场（不装 hook、不起网络线程）。
//     ② 新 dylib 从哪来？两条路：
//        - 我主动下发 {"op":"update","ver":"21","url":"..."} 让它下载；
//        - 它自己每次启动顺手问一句仓库里的 version.json，有新版就下载，
//          下一次冷启动自动接管。
//    因为不卸载旧副本，同一进程里「热切换」会让两份代码同时跑（两个心跳），
//    所以这里刻意选择【下载后下次启动生效】—— 换来的好处是零风险：
//    下载完先 dlopen 校验一遍，加载不了就丢弃，绝不会把 App 搞崩。
// ---------------------------------------------------------------------------
static NSString *AICoreDir(void) {
    NSArray *ps = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (!ps.count) return nil;
    NSString *d = [ps.firstObject stringByAppendingPathComponent:@"agentcore"];
    [[NSFileManager defaultManager] createDirectoryAtPath:d
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return d;
}

// "v20" / "AgentInject2-v21.dylib" -> 20 / 21
static int AIVerNum(NSString *s) {
    int n = 0; BOOL dig = NO;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c >= '0' && c <= '9') { dig = YES; n = n * 10 + (int)(c - '0'); }
        else if (dig) break;
    }
    return n;
}

// 本地缓存里有没有比我新的 core？有就返回它的路径
static NSString *AINewerCorePath(void) {
    NSString *dir = AICoreDir();
    if (!dir) return nil;
    int my = AIVerNum(kAIVer);
    NSArray *fs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    int best = my; NSString *bp = nil;
    for (NSString *f in fs) {
        if (![f hasPrefix:@"AgentInject2-v"] || ![f hasSuffix:@".dylib"]) continue;
        int n = AIVerNum(f);
        if (n > best) { best = n; bp = [dir stringByAppendingPathComponent:f]; }
    }
    return bp;
}

// 把活交给本地更新的那份 core，自己不再初始化
static BOOL AIHandoffToNewer(void) {
    static BOOL done = NO;
    if (done) return YES;                       // +load 和 constructor 会各调一次
    NSString *p = AINewerCorePath();
    if (!p) return NO;
    void *h = dlopen([p fileSystemRepresentation], RTLD_NOW);
    if (!h) { AILog(@"  ⚠️ 新版 %@ 加载失败: %s", p.lastPathComponent, dlerror() ?: ""); return NO; }
    void (*start)(void) = dlsym(h, "AgentCoreStart");
    if (!start) { AILog(@"  ⚠️ 新版 %@ 里没有 AgentCoreStart", p.lastPathComponent); return NO; }
    done = YES;
    AILog(@"★ 内置更新：本机 v%@ -> %@，本副本退场", kAIVer, p.lastPathComponent);
    @try { start(); } @catch (NSException *e) { AILog(@"  新版启动异常 %@", e); }
    return YES;
}

// 被引导器 dlopen 进来时的入口（必须是 default visibility，否则 dlsym 找不到）
__attribute__((visibility("default")))
void AgentCoreStart(void) { AIInstall(); }

// 下载一份新 core：先存临时文件 → dlopen 校验能不能加载 → 通过才转正
static NSString *AIUpdateFrom(NSString *urlStr, NSString *ver) {
    if (!urlStr.length || !ver.length) return @"缺少 url / ver";
    NSData *d = nil; NSInteger code = 0;
    BOOL ok = AIHttpEx(urlStr, nil, 40.0, YES, nil, &d, nil, &code, nil);
    if (!ok || !d.length) return [NSString stringWithFormat:@"下载失败 (code=%d, %luB)",
                                  (int)code, (unsigned long)d.length];
    if (code >= 400) return [NSString stringWithFormat:@"HTTP %d", (int)code];
    if (d.length < 20000) return [NSString stringWithFormat:@"文件太小(%luB)，不像 dylib", (unsigned long)d.length];

    NSString *dir = AICoreDir();
    if (!dir) return @"拿不到 Documents 目录";
    NSString *tmp = [dir stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"tmp-%d.dylib",
                      (int)[[NSDate date] timeIntervalSince1970]]];
    [d writeToFile:tmp atomically:YES];
    void *h = dlopen([tmp fileSystemRepresentation], RTLD_NOW);   // ★ 先验证能加载
    if (!h) {
        NSString *err = [NSString stringWithUTF8String:dlerror() ?: "?"];
        [[NSFileManager defaultManager] removeItemAtPath:tmp error:nil];
        return [@"校验失败(未生效): " stringByAppendingString:err];
    }
    dlclose(h);
    NSString *dst = [dir stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"AgentInject2-v%@.dylib", ver]];
    [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];
    NSError *e = nil;
    [[NSFileManager defaultManager] moveItemAtPath:tmp toPath:dst error:&e];
    if (e) return [@"落盘失败: " stringByAppendingString:e.localizedDescription];
    return [NSString stringWithFormat:@"已装 v%@ (%luB)，重开 App 生效", ver, (unsigned long)d.length];
}

// 启动时顺手看看仓库里有没有新版（后台，失败就算了，下次启动还会再试）
#define AI_MANIFEST @"https://raw.githubusercontent.com/857386461/poc-agent/master/version.json"
static void AICheckUpdateAsync(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            NSData *d = nil; NSInteger code = 0;
            BOOL ok = AIHttpEx(AI_MANIFEST, nil, 20.0, YES, nil, &d, nil, &code, nil);
            if (!ok || !d.length || code >= 400) return;
            id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if (![j isKindOfClass:[NSDictionary class]]) return;
            NSString *ver = [j objectForKey:@"ver"];
            NSString *url = [j objectForKey:@"url"];
            if (!ver.length || !url.length) return;
            int nv = AIVerNum([NSString stringWithFormat:@"v%@", ver]);
            if (nv <= AIVerNum(kAIVer)) return;                    // 不比我新
            NSString *have = AINewerCorePath();
            if (have && AIVerNum(have) >= nv) return;              // 已经下过了
            NSString *r = AIUpdateFrom(url, [NSString stringWithFormat:@"%d", nv]);
            AILog(@"  自动更新: %@", r);
        }
    });
}

// ---------------------------------------------------------------------------
// 14c. v20：悬浮球 —— 用户吐槽「盖屏太碍事」，默认只留一个小圆点
//
//   小圆点可拖动，点一下展开面板：版本/心跳一览 + 几个开关。
//   开关状态存 NSUserDefaults，重开 App 也记得住。
// ---------------------------------------------------------------------------
@interface AIFloatTarget : NSObject
@end
@implementation AIFloatTarget
- (void)ballTapped:(id)sender {
    gFloatExpanded = !gFloatExpanded;
    gFloatForce = YES;                  // 点了就要立刻响应，别被节流挡住
    AIFloatApply();
}
- (void)ballDragged:(UIPanGestureRecognizer *)g {
    if (!gFloatWindow) return;
    CGPoint t = [g translationInView:gFloatWindow];
    [g setTranslation:CGPointZero inView:gFloatWindow];
    UIView *ball = [gFloatWindow viewWithTag:701];
    if (!ball) return;
    CGSize sc = [UIScreen mainScreen].bounds.size;
    CGFloat x = MIN(MAX(ball.center.x + t.x, 30), sc.width  - 30);
    CGFloat y = MIN(MAX(ball.center.y + t.y, 90), sc.height - 90);
    ball.center = CGPointMake(x, y);
    if (g.state == UIGestureRecognizerStateEnded) {
        AISetFlag(@"fx", (x - 30) / MAX(1, sc.width  - 60));
        AISetFlag(@"fy", (y - 90) / MAX(1, sc.height - 180));
        // 位置存成 0~1 的比例，换机型/转屏也不会跑到屏幕外
        [[NSUserDefaults standardUserDefaults] setFloat:(float)((x - 30) / MAX(1, sc.width  - 60)) forKey:AIK(@"fpx")];
        [[NSUserDefaults standardUserDefaults] setFloat:(float)((y - 90) / MAX(1, sc.height - 180)) forKey:AIK(@"fpy")];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
}
- (void)sw:(UISwitch *)s {
    NSString *k = [NSString stringWithFormat:@"sw%d", (int)s.tag];
    BOOL on = s.isOn;
    AISetFlag(k, on);
    if (s.tag == 0) { AISetHudVisible(on); AILog(@"  状态条: %@", on ? @"开" : @"关"); }
    if (s.tag == 1) { AISetOverlayVisible(on); AILog(@"  诊断盖屏: %@", on ? @"开" : @"关"); }
    if (s.tag == 3) { AISetFlag(@"autoupd", on); AILog(@"  自动更新: %@", on ? @"开" : @"关"); }
    gFloatForce = YES;
    AIFloatApply();
}
- (void)collapse:(id)sender { gFloatExpanded = NO; gFloatForce = YES; AIFloatApply(); }
- (void)hideBall:(id)sender {
    AISetFlag(@"ball", NO);
    gFloatForce = YES;
    AIFloatApply();
    AIToast(@"悬浮球已隐藏（发 ball=1 找回）");
}
@end
static AIFloatTarget *gFT = nil;

static void AIFloatApply(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AIFloatApply(); });
        return;
    }
    // 心跳每秒都在调，别把 UI 重绘也拖成每秒一次
    CFTimeInterval now = CFAbsoluteTimeGetCurrent();
    if (!gFloatForce && now - gFloatLast < 1.5) return;
    gFloatLast = now; gFloatForce = NO;
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        if (!gFT) gFT = [AIFloatTarget new];
        CGSize sc = [UIScreen mainScreen].bounds.size;

        if (!gFloatWindow) {
            UIWindowScene *scn = AIFirstWindowScene();
            if (scn) gFloatWindow = [[UIWindow alloc] initWithWindowScene:scn];
            else     gFloatWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            gFloatWindow.windowLevel = UIWindowLevelStatusBar + 900;
            gFloatWindow.backgroundColor = [UIColor clearColor];
            gFloatWindow.rootViewController = [UIViewController new];
            gFloatWindow.rootViewController.view.backgroundColor = [UIColor clearColor];
        }
        UIView *host = gFloatWindow.rootViewController.view;
        for (UIView *v in host.subviews) [v removeFromSuperview];

        BOOL want = AIFlag(@"ball", YES);
        gFloatWindow.hidden = !want;
        if (!want) return;

        float px = [[NSUserDefaults standardUserDefaults] floatForKey:AIK(@"fpx")];
        float py = [[NSUserDefaults standardUserDefaults] floatForKey:AIK(@"fpy")];
        if (px <= 0 && py <= 0) { px = 0.86f; py = 0.42f; }        // 默认右侧中间
        CGPoint c = CGPointMake(30 + px * (sc.width - 60), 90 + py * (sc.height - 180));

        if (!gFloatExpanded) {
            gFloatWindow.frame = CGRectMake(c.x - 30, c.y - 30, 60, 60);
            UIView *ball = [[UIView alloc] initWithFrame:CGRectMake(2, 2, 56, 56)];
            ball.tag = 701;
            ball.layer.cornerRadius = 28;
            ball.layer.masksToBounds = YES;
            ball.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.62];
            UILabel *lb = [[UILabel alloc] initWithFrame:ball.bounds];
            lb.text = [NSString stringWithFormat:@"%@\n%d", kAIVer, gCmdGot];
            lb.numberOfLines = 2; lb.textAlignment = NSTextAlignmentCenter;
            lb.font = [UIFont boldSystemFontOfSize:13];
            lb.textColor = (gPollErr > 0 && gPollOK == 0) ? [UIColor systemRedColor]
                                                          : [UIColor systemGreenColor];
            [ball addSubview:lb];
            [ball addGestureRecognizer:[[UITapGestureRecognizer alloc]
                                        initWithTarget:gFT action:@selector(ballTapped:)]];
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
                                           initWithTarget:gFT action:@selector(ballDragged:)];
            [ball addGestureRecognizer:pan];
            [host addSubview:ball];
        } else {
            CGFloat w = 250, h = 300;
            CGFloat ox = MIN(MAX(c.x - w / 2, 8), sc.width  - w - 8);
            CGFloat oy = MIN(MAX(c.y - h / 2, 80), sc.height - h - 8);
            gFloatWindow.frame = CGRectMake(ox, oy, w, h);
            UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, h)];
            panel.layer.cornerRadius = 14; panel.layer.masksToBounds = YES;
            panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.86];

            UILabel *ti = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, w - 60, 22)];
            ti.text = [NSString stringWithFormat:@"AgentInject2 %@", kAIVer];
            ti.textColor = [UIColor whiteColor]; ti.font = [UIFont boldSystemFontOfSize:14];
            [panel addSubview:ti];
            UIButton *cx = [UIButton buttonWithType:UIButtonTypeSystem];
            cx.frame = CGRectMake(w - 46, 6, 40, 26);
            [cx setTitle:@"收起" forState:UIControlStateNormal];
            [cx addTarget:gFT action:@selector(collapse:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:cx];

            UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(12, 32, w - 24, 34)];
            st.numberOfLines = 2; st.font = [UIFont systemFontOfSize:11];
            st.textColor = [UIColor lightGrayColor];
            st.text = [NSString stringWithFormat:@"%@  心跳✅%d❌%d 指令%d\n%@",
                       gProcName ?: @"?", gPollOK, gPollErr, gCmdGot,
                       (gLastErrText.length ? [@"最近错误: " stringByAppendingString:gLastErrText]
                                            : @"中继已连接")];
            [panel addSubview:st];

            NSArray *items = @[@"顶端状态条", @"诊断盖屏(全屏)", @"隐藏悬浮球", @"自动检查更新"];
            for (int i = 0; i < (int)items.count; i++) {
                CGFloat y = 78 + i * 40;
                UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(12, y, 150, 30)];
                l.text = items[i]; l.textColor = [UIColor whiteColor];
                l.font = [UIFont systemFontOfSize:13];
                [panel addSubview:l];
                if (i == 2) {
                    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
                    b.frame = CGRectMake(w - 76, y, 64, 30);
                    [b setTitle:@"隐藏" forState:UIControlStateNormal];
                    [b addTarget:gFT action:@selector(hideBall:) forControlEvents:UIControlEventTouchUpInside];
                    [panel addSubview:b];
                } else {
                    UISwitch *s = [[UISwitch alloc] initWithFrame:CGRectMake(w - 66, y, 51, 30)];
                    s.tag = i;
                    s.on = AIFlag([NSString stringWithFormat:@"sw%d", i],
                                  i == 0 ? YES : (i == 3 ? YES : NO));
                    [s addTarget:gFT action:@selector(sw:) forControlEvents:UIControlEventValueChanged];
                    [panel addSubview:s];
                }
            }
            UILabel *ft = [[UILabel alloc] initWithFrame:CGRectMake(12, h - 40, w - 24, 32)];
            ft.numberOfLines = 2; ft.font = [UIFont systemFontOfSize:10];
            ft.textColor = [UIColor darkGrayColor];
            NSString *np = AINewerCorePath();
            ft.text = np ? [NSString stringWithFormat:@"待生效新版: %@", np.lastPathComponent]
                         : @"已是最新（更新会自动下载）";
            [panel addSubview:ft];
            [host addSubview:panel];
        }
        gFloatWindow.hidden = NO;
    } @catch (NSException *e) { AILog(@"悬浮球异常 %@", e); }
}

// 15. 入口：constructor + ObjC +load 双保险
//
//  ★ 重要发现（本机实测）：用 Xcode 26 SDK 编译出来的 dylib 里【没有】
//    传统的 __DATA,__mod_init_func section —— constructor 被编码进了
//    __TEXT,__init_offsets（新的静态初始化偏移机制），只有新版 dyld 认。
//    一旦目标进程/注入器不吃这一套，constructor 就永远不会被调用，
//    表现就是「注入成功、App 正常、但什么都没发生」。
//    → 所以额外加一个 ObjC 类的 +load：它由 libobjc 保证调用，
//      不依赖任何 dyld 新特性，是更可靠的入口。
// ---------------------------------------------------------------------------
static BOOL gInstalled = NO;

static void AIInstall(void) {
    if (gInstalled) return;
    gInstalled = YES;
    if (!gLog) { gLog = [NSMutableString new]; gLogLock = [NSLock new]; }
    if ([gBootSrc isEqualToString:@"?"]) gBootSrc = @"load/constructor";
    AILog(@"install enter pid=%d", getpid());

    // v20：本地有更新的 core 就让它接管，本副本不装 hook、不起网络线程。
    // 这样以后升级不用再 TrollFools 重新注入 —— 重开 App 即可。
    if (AIHandoffToNewer()) return;

    // 落一个「已加载」标记文件，用于判断 dylib 到底有没有被 dyld 装载
    @try {
        NSString *mk = [NSString stringWithFormat:@"AgentInject2 loaded pid=%d at %@\n", getpid(), [NSDate date]];
        [mk writeToFile:@"/var/mobile/agent_inject2_installed.txt" atomically:YES
              encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {}

    // 尽早 hook sendEvent：只要 dylib 装进来了，用户一碰屏幕就一定会启动自检
    AIHookWhenReady();

    // 路线 1：监听 App 启动完成再延迟 6 秒（避开 App 自己做初始化，避免闪退）
    // 注意：这里用字符串字面量而不是 UIApplicationDidFinishLaunchingNotification 常量
    // —— 入口早于 UIKit 完成初始化，直接引用 UIKit 常量有触发过早初始化的风险。
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(),
                                    NULL,
                                    AINotifyCb,
                                    CFSTR("UIApplicationDidFinishLaunchingNotification"),
                                    NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

    // 路线 2：兜底，8 秒后无论如何跑一次（有些 App 不发送通知 / TrollFools 注入时机晚）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!gBooted) gBootSrc = @"定时器(8s)";
        @try { AIBoot(); } @catch (NSException *e) { NSLog(@"[AI2] boot2 ex %@", e); }
    });
}

__attribute__((constructor))
static void AIEntry(void) { AIInstall(); }

@interface AIBootLoader : NSObject
@end
@implementation AIBootLoader
+ (void)load { AIInstall(); }
@end
