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
    if (!gClientType || !gSetCb || !gSchedule) { AILog(@"  符号不全，跳过 monitor"); return; }
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

static void AIHookSendEvent(void) {
    Class c = NSClassFromString(@"UIApplication");
    if (!c) return;
    Method m = class_getInstanceMethod(c, @selector(sendEvent:));
    if (!m) return;
    gOrigSendEvent = method_getImplementation(m);
    if (!gOrigSendEvent) return;
    SEL sel = @selector(sendEvent:);
    IMP newImp = imp_implementationWithBlock(^(id me, UIEvent *ev) {
        __sync_fetch_and_add(&gSendEventHits, 1);
        ((void (*)(id, SEL, id))gOrigSendEvent)(me, sel, ev);
    });
    method_setImplementation(m, newImp);
    AILog(@"  hook -[UIApplication sendEvent:] -> %@", gOrigSendEvent ? @"OK" : @"FAIL");
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
    UIWindow *w = nil;
    if ([app respondsToSelector:@selector(keyWindow)]) w = app.keyWindow;
    if (!w && app.windows.count) w = app.windows.firstObject;
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
                    AIPump(rl, 0.12);
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
    UIWindow *w = ([app respondsToSelector:@selector(keyWindow)] ? app.keyWindow : nil);
    if (!w && app.windows.count) w = app.windows.firstObject;
    if (!w) return nil;
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
    UIWindow *w = ([app respondsToSelector:@selector(keyWindow)] ? app.keyWindow : nil);
    if (!w && app.windows.count) w = app.windows.firstObject;
    if (!w) return nil;
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
    UIWindow *w = ([app respondsToSelector:@selector(keyWindow)] ? app.keyWindow : nil);
    if (!w && app.windows.count) w = app.windows.firstObject;
    if (!w) { AILog(@"  无 window"); return; }
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
    return @"https://RELAY_NOT_CONFIGURED.invalid";
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
        if (!ok) { @try { ok = AITapInProcess(CGPointMake(x, y)); } @catch (id e) {} }
        AILog(@"  [cmd] tap (%.0f,%.0f) 通道%d -> %@", x, y, gBestTap, ok ? @"OK" : @"FAIL");
    } else if ([op isEqualToString:@"shot"]) {
        UIImage *im = AIShotByBest();
        NSData *png = im ? UIImagePNGRepresentation(im) : nil;
        NSString *b64 = png ? [png base64EncodedStringWithOptions:0] : @"";
        NSDictionary *rep = @{@"dev": gDevId, @"op": @"shot",
                              @"ok": @(b64.length > 0), @"b64": b64};
        NSData *bd = [NSJSONSerialization dataWithJSONObject:rep options:0 error:nil];
        @try { AIHttp([gBase stringByAppendingString:@"/report"], bd, 20.0); } @catch (id e) {}
        AILog(@"  [cmd] shot -> %luB", (unsigned long)b64.length);
    } else if ([op isEqualToString:@"status"]) {
        NSDictionary *rep = @{@"dev": gDevId, @"op": @"status",
                              @"proc": gProcName, @"bundle": gBundleId,
                              @"tap": @(gBestTap), @"shot": @(gBestShot),
                              @"mon": @(gMonHits), @"se": @(gSendEventHits)};
        NSData *bd = [NSJSONSerialization dataWithJSONObject:rep options:0 error:nil];
        @try { AIHttp([gBase stringByAppendingString:@"/report"], bd, 10.0); } @catch (id e) {}
    }
}

static void AINetLoop(void) {
    AILog(@"==== [6] 控制通道 ====");
    gBase = AIBase();
    if ([gBase containsString:@"invalid"]) { AILog(@"  未配置控制服务器，轮询不启动"); return; }
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        while (1) {
            @autoreleasepool {
                @try {
                    NSString *u = [gBase stringByAppendingFormat:@"/poll?dev=%@", gDevId];
                    NSData *d = AIHttp(u, nil, 8.0);
                    if (d.length) {
                        id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                        if ([j isKindOfClass:[NSDictionary class]]) AIExecCmd(j);
                        else if ([j isKindOfClass:[NSArray class]])
                            for (NSDictionary *c in (NSArray *)j) AIExecCmd(c);
                    }
                } @catch (NSException *e) {}
            }
            [NSThread sleepForTimeInterval:3.0];
        }
    });
    AILog(@"  轮询已启动 -> %@", gBase);
}

// ---------------------------------------------------------------------------
// 13. 盖屏报告
// ---------------------------------------------------------------------------
static void AIShowOverlay(void) {
    if (gIsSpringBoard) { AILog(@"SpringBoard 进程，跳过盖屏（避免影响系统 UI）"); return; }
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindow *ow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            ow.windowLevel = UIWindowLevelStatusBar + 100;
            ow.backgroundColor = [UIColor blackColor];
            ow.userInteractionEnabled = YES;

            UIScrollView *sv = [[UIScrollView alloc] initWithFrame:ow.bounds];
            sv.backgroundColor = [UIColor blackColor];

            [gLogLock lock]; NSString *txt = [gLog copy]; [gLogLock unlock];
            UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(8, 8, ow.bounds.size.width - 16, 0)];
            lb.numberOfLines = 0;
            lb.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
            lb.textColor = [UIColor greenColor];
            lb.text = txt;
            [lb sizeToFit];
            sv.contentSize = CGSizeMake(ow.bounds.size.width, lb.bounds.size.height + 40);
            [sv addSubview:lb];

            UIViewController *vc = [UIViewController new];
            vc.view = sv;
            ow.rootViewController = vc;
            [ow makeKeyAndVisible];
            AILog(@"盖屏已显示（%lu 字符）", (unsigned long)txt.length);
        } @catch (NSException *e) { AILog(@"盖屏异常 %@", e); }
    });
}

// ---------------------------------------------------------------------------
// 14. 启动
// ---------------------------------------------------------------------------
static void AIBoot(void) {
    if (gBooted) return;
    gBooted = YES;
    AILog(@"########## AgentInject2 boot ##########");

    @try { AIEnv(); }          @catch (NSException *e) { AILog(@"env 异常 %@", e); }
    @try { AIHookSendEvent(); } @catch (NSException *e) { AILog(@"hook 异常 %@", e); }
    @try { AILoadHID(); }      @catch (NSException *e) { AILog(@"loadHID 异常 %@", e); }

    // HID 测试必须在有 runloop 的线程上（monitor 回调靠它）
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CFRunLoopRef rl = CFRunLoopGetCurrent();
        @try { AISetupMonitor(rl); } @catch (NSException *e) { AILog(@"monitor 异常 %@", e); }
        @try { AIHidMatrix(rl); }    @catch (NSException *e) { AILog(@"matrix 异常 %@", e); }

        dispatch_async(dispatch_get_main_queue(), ^{
            @try { AIControlProbe(); } @catch (NSException *e) { AILog(@"control 异常 %@", e); }
            // 进程内 UIKit 路线补测
            @try {
                AILog(@"==== [3b] 进程内 UIKit 合成 ====");
                int s0 = gSendEventHits;
                CGSize s = [UIScreen mainScreen].bounds.size;
                BOOL ok = AITapInProcess(CGPointMake(s.width * 0.5, s.height * 0.5));
                usleep(200000);
                AILog(@"  AITapInProcess -> %@ sendEvent+%d", ok ? @"已投递" : @"失败", gSendEventHits - s0);
                if (gSendEventHits - s0 > 0 && gBestTap == 0) { gBestTap = 2; AILog(@"  ↑ 选定为进程内 UIKit 通道"); }
            } @catch (NSException *e) { AILog(@"inproc 异常 %@", e); }
            @try { AIShotMatrix(); } @catch (NSException *e) { AILog(@"shot 异常 %@", e); }
            @try { AINetLoop(); }    @catch (NSException *e) { AILog(@"net 异常 %@", e); }

            AILog(@"########## 结论: tap=%d shot=%d mon=%d se=%d ##########",
                  gBestTap, gBestShot, gMonHits, gSendEventHits);
            @try { AIWriteReport(); } @catch (NSException *e) {}
            @try { AIShowOverlay(); } @catch (NSException *e) {}
        });
    });
}

__attribute__((constructor))
static void AIEntry(void) {
    if (!gLog) { gLog = [NSMutableString new]; gLogLock = [NSLock new]; }
    AILog(@"constructor enter pid=%d", getpid());

    // 路线 1：监听 App 启动完成再延迟 6 秒（避开 App 自己做初始化，避免闪退）
    // 注意：这里用字符串字面量而不是 UIApplicationDidFinishLaunchingNotification 常量
    // —— constructor 早于 UIKit 完成初始化，直接引用 UIKit 常量有触发过早初始化的风险。
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(),
                                    NULL,
                                    ^(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef ui) {
                                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                                                       dispatch_get_main_queue(), ^{
                                            @try { AIBoot(); } @catch (NSException *e) { NSLog(@"[AI2] boot ex %@", e); }
                                        });
                                    },
                                    CFSTR("UIApplicationDidFinishLaunchingNotification"),
                                    NULL, CFNotificationSuspensionBehaviorDeliverImmediately);

    // 路线 2：兜底，8 秒后无论如何跑一次（有些 App 不发送通知 / TrollFools 注入时机晚）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try { AIBoot(); } @catch (NSException *e) { NSLog(@"[AI2] boot2 ex %@", e); }
    });
}
