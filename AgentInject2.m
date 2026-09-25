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
#include <sys/socket.h>
#include <netinet/in.h>
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

// 盖屏窗口。必须是 static 强引用，否则 ARC 会在函数返回时把它释放掉，
// 表现就是"注入成功但屏幕上什么都没有"（v2 踩过的坑）。
// 同时它必须在文件靠前的位置声明 —— v3 的伪造 Touch 分发代码（约 530 行）
// 会用到它，声明放在 13 节会导致 "use of undeclared identifier"。
static UIWindow *gOverlayWindow = nil;

// 前向声明：sendEvent hook 里要在定义之前调用 AIBoot
static void AIBoot(void);
// AITapInProcess（约 430 行）在 AIHostWindow 定义（约 580 行）之前就要用它
static UIWindow *AIHostWindow(void);
static void AISetOverlayVisible(BOOL vis);   // 盖屏按钮在它的定义之前就要用
static void AIShowOverlay(void);            // 盖屏按钮回调里要刷新报告
static void AITestTapAt(CGPoint pt, NSString *desc);
static void AITestTapButton(void);

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
- (CGPoint)locationInView:(UIView *)v {
    if (!v || v == self.aiView) return self.aiPoint;
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

// 找「App 自己的」窗口：排除我们盖的屏、排除键盘/文本特效窗口
static UIWindow *AIHostWindow(void) {
    UIWindow *fallback = nil;
    for (UIWindow *w in AIAllWindows()) {
        if (w == gOverlayWindow) continue;
        NSString *cn = NSStringFromClass([w class]);
        if ([cn rangeOfString:@"TextEffects"].location != NSNotFound) continue;
        if ([cn rangeOfString:@"RemoteKeyboard"].location != NSNotFound) continue;
        if (w.hidden || w.alpha < 0.01) continue;
        if (!fallback) fallback = w;
        if (w.isKeyWindow) return w;
        if (w.rootViewController && w.rootViewController.view.window == w) return w;
    }
    return fallback ?: gOverlayWindow;
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

// 主线程同步执行（HTTP 服务在后台线程，触摸/截图必须回主线程）
static void AIMainSync(void (^b)(void)) {
    if ([NSThread isMainThread]) b();
    else dispatch_sync(dispatch_get_main_queue(), b);
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
        AIHttpErr([gBase stringByAppendingString:@"/report"], bd, 15.0, &e);
        if (e) AILog(@"  ⚠️ 上报失败(%@): %@", m[@"op"], e.localizedDescription);
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
        if (!ok && gBestTap == 4) { @try { ok = AIFakeTapAtWindowPoint(CGPointMake(x, y)); } @catch (id e) {} }
        if (!ok) { @try { ok = AITapInProcess(CGPointMake(x, y)); } @catch (id e) {} }
        AILog(@"  [cmd] tap (%.0f,%.0f) 通道%d -> %@", x, y, gBestTap, ok ? @"OK" : @"FAIL");
        AIReportDict(@{@"op": @"tap", @"ok": @(ok), @"x": @(x), @"y": @(y), @"chan": @(gBestTap)});
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
        __block NSString *tree = @"(none)";
        AIMainSync(^{
            @try {
                UIWindow *w = AIHostWindow();
                UIView *root = w ? (w.rootViewController.view ?: w) : nil;
                if (root) tree = AITreeOf(root, 0, 12);
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"tree", @"ok": @YES, @"tree": tree});
    } else if ([op isEqualToString:@"overlay"]) {
        id ov = cmd[@"on"];
        BOOL vis = ov ? ([ov intValue] != 0) : NO;
        AISetOverlayVisible(vis);
        AIReportDict(@{@"op": @"overlay", @"ok": @YES, @"visible": @(vis)});
    } else if ([op isEqualToString:@"status"]) {
        AIReportDict(@{@"op": @"status", @"ok": @YES,
                       @"proc": gProcName, @"bundle": gBundleId, @"pid": @(getpid()),
                       @"tap": @(gBestTap), @"shot": @(gBestShot),
                       @"mon": @(gMonHits), @"se": @(gSendEventHits),
                       @"tvhits": @(gTargetHits), @"act": @(gActionHits),
                       @"overlay": (gOverlayWindow && !gOverlayWindow.hidden) ? @"on" : @"off"});
    } else if ([op isEqualToString:@"log"]) {
        NSString *t = AILogSnapshot();
        AIReportDict(@{@"op": @"log", @"ok": @YES, @"text": t});
    }
}

static void AINetLoop(void) {
    AILog(@"==== [6] 控制通道 ====");
    @try { AIStartServer(); AISleep(0.6); } @catch (NSException *e) { AILog(@"  服务启动异常 %@", e); }  // 等端口真正 bind 上再打印
    gBase = AIBase();
    AILog(@"  中继: %@", gBase);
    if ([gBase containsString:@"invalid"]) { AILog(@"  地址无效，轮询不启动"); return; }

    // 上线即报到：我在中继那边 GET /peek 就能看到这台设备的 dev id
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        AIReportDict(@{@"op": @"hello", @"proc": gProcName, @"bundle": gBundleId,
                       @"pid": @(getpid()), @"tap": @(gBestTap), @"shot": @(gBestShot),
                       @"tvhits": @(gTargetHits), @"act": @(gActionHits)});
        AILog(@"  已向中继报到 dev=%@  中继=%@", gDevId, gBase);
    });
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        int round = 0;
        while (1) {
            @autoreleasepool {
                @try {
                    NSString *u = [gBase stringByAppendingFormat:@"/poll?dev=%@", gDevId];
                    NSError *pe = nil;
                    NSData *d = AIHttpErr(u, nil, 8.0, &pe);
                    if (pe) AILog(@"  ⚠️ 轮询失败: %@ (code=%ld)", pe.localizedDescription, (long)pe.code);
                    if (d.length) {
                        id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                        if ([j isKindOfClass:[NSDictionary class]]) AIExecCmd(j);
                        else if ([j isKindOfClass:[NSArray class]])
                            for (NSDictionary *c in (NSArray *)j) AIExecCmd(c);
                    }
                } @catch (NSException *e) {}
            }
            if (++round % 15 == 0) {
                AIReportDict(@{@"op": @"beat", @"tap": @(gBestTap), @"shot": @(gBestShot),
                               @"tvhits": @(gTargetHits), @"act": @(gActionHits)});
            }
            [NSThread sleepForTimeInterval:2.0];
        }
    });
    AILog(@"  轮询已启动 -> %@", gBase);
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

            CGFloat top = 44;
            if (banner) {
                // 结论横幅：放最顶部，大字，一眼能看到，不用滚
                UILabel *bl = [[UILabel alloc] initWithFrame:CGRectMake(6, 2, f.size.width - 12, 40)];
                bl.textColor = [UIColor whiteColor];
                bl.backgroundColor = [UIColor redColor];
                bl.font = [UIFont boldSystemFontOfSize:15];
                bl.textAlignment = NSTextAlignmentCenter;
                bl.numberOfLines = 2;
                bl.text = banner;
                [root addSubview:bl];
                top = 46;
            }

            if (done) {
                if (!gRT) gRT = [AIReportTarget new];
                UIButton *b1 = [UIButton buttonWithType:UIButtonTypeSystem];
                b1.frame = CGRectMake(6, top, 150, 38);
                b1.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b1 setTitle:@"复制结论(短)" forState:UIControlStateNormal];
                [b1 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b1.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b1 addTarget:gRT action:@selector(copyTail:) forControlEvents:UIControlEventTouchUpInside];
                [root addSubview:b1];

                UIButton *b2 = [UIButton buttonWithType:UIButtonTypeSystem];
                b2.frame = CGRectMake(162, top, 150, 38);
                b2.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b2 setTitle:@"复制全文(长)" forState:UIControlStateNormal];
                [b2 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b2.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b2 addTarget:gRT action:@selector(copyReport:) forControlEvents:UIControlEventTouchUpInside];
                UIButton *b3 = [UIButton buttonWithType:UIButtonTypeSystem];
                b3.frame = CGRectMake(162, top, 150, 38);
                b3.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b3 setTitle:@"收起盖屏(露出App)" forState:UIControlStateNormal];
                [b3 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b3.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b3 addTarget:gRT action:@selector(toggleOverlay:) forControlEvents:UIControlEventTouchUpInside];
                UIButton *b4 = [UIButton buttonWithType:UIButtonTypeSystem];
                b4.frame = CGRectMake(162, top, 150, 38);
                b4.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b4 setTitle:@"▶ 实测:点App第一个按钮" forState:UIControlStateNormal];
                [b4 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b4.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b4 addTarget:gRT action:@selector(testTapButton:) forControlEvents:UIControlEventTouchUpInside];
                UIButton *b5 = [UIButton buttonWithType:UIButtonTypeSystem];
                b5.frame = CGRectMake(162, top, 150, 38);
                b5.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b5 setTitle:@"▶ 实测:点屏幕中心" forState:UIControlStateNormal];
                [b5 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b5.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b5 addTarget:gRT action:@selector(testTapCenter:) forControlEvents:UIControlEventTouchUpInside];
                UIButton *b6 = [UIButton buttonWithType:UIButtonTypeSystem];
                b6.frame = CGRectMake(162, top, 150, 38);
                b6.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
                [b6 setTitle:@"▶ 立即上报状态(让我看到你)" forState:UIControlStateNormal];
                [b6 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                b6.titleLabel.font = [UIFont boldSystemFontOfSize:14];
                [b6 addTarget:gRT action:@selector(pingNow:) forControlEvents:UIControlEventTouchUpInside];
                [root addSubview:b2];
                top += 42;
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
            [gOverlayWindow makeKeyAndVisible];
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
    NSString *banner = [NSString stringWithFormat:@"AI2 结论 tap=%d shot=%d se=%d tvhits=%d act=%d",
                        gBestTap, gBestShot, gSendEventHits, gTargetHits, gActionHits];
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
    // 一进来就先盖一层「已加载」，让你立刻能确认 dylib 到底跑没跑；
    // 自检跑完再刷新成完整报告（带复制按钮）。
    AIShowOverlayText(@"AgentInject2 已加载 ✓\n正在自检，请稍候…", NO, nil);

    @try { AIEnv(); }          @catch (NSException *e) { AILog(@"env 异常 %@", e); }
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
            @try { AIShowOverlay(); } @catch (NSException *e) {}
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
