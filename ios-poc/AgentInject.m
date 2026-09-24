// ===========================================================================
//  AgentInject.dylib  ——  进程内自动化执行器（TrollFools 注入版）
//
//  目标：注入到目标 App 进程内，验证「进程内能否合成触摸 / 读视图树 / 截图」，
//        并把结果直接盖在屏幕上（离线自证，不依赖任何网络）。
//
//  装机方式：TrollFools → 选择 App → 注入本 dylib → 打开该 App → 8 秒后自动出结果面板。
//
//  判据设计（全部可闭环自证，不用间接 flag 推断）：
//    基准：hook [UIApplication sendEvent:]，它被调用 = 事件真的进了 App 的事件处理链。
//    正对照：真手指点一下 → 计数器必须增加（证明 hook 本身是好的）。
//    被测：每条合成通路打一下 → 看计数器增量 + 事件里的坐标是否等于合成坐标。
// ===========================================================================
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <QuartzCore/QuartzCore.h>
#import <mach/mach.h>
#import <sys/sysctl.h>

// ---------------------------------------------------------------------------
// 日志（惰性初始化 —— 血的教训：ObjC 向 nil 发消息是静默 no-op，
// 忘了初始化会让所有日志进黑洞，界面看着正常但什么都不显示）
// ---------------------------------------------------------------------------
static NSMutableString *gLog = nil;
static NSDate          *gT0  = nil;

static void AILog(NSString *line) {
    if (!gLog) gLog = [NSMutableString string];
    if (!gT0)  gT0  = [NSDate date];
    NSTimeInterval dt = -[gT0 timeIntervalSinceNow];
    @synchronized (gLog) {
        [gLog appendFormat:@"[+%05.2f] %@\n", dt, line];
    }
    NSLog(@"[AINJECT] %@", line);
}

static void AILogf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void AILogf(NSString *fmt, ...) {
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    AILog(s);
}

static void AIHeader(NSString *t) {
    AILog(@"");
    AILog([NSString stringWithFormat:@"========== %@ ==========", t]);
}

// ---------------------------------------------------------------------------
// 事件探针：hook [UIApplication sendEvent:]
// 这是「事件是否真的进入 App 处理链」的唯一可靠判据
// ---------------------------------------------------------------------------
static IMP          gOrigSendEvent = NULL;
static NSInteger    gHookHits      = 0;      // sendEvent: 被调用次数
static NSInteger    gSyntheticHits = 0;      // 其中坐标 == 我们合成坐标的次数
static CGPoint      gProbePoint    = {0.0, 0.0};
static BOOL         gProbeArmed    = NO;
static NSString    *gLastEventDesc = nil;

static NSString *AIDescribeEvent(UIEvent *ev) {
    if (!ev) return @"(nil event)";
    UITouch *t = [[ev allTouches] anyObject];
    if (!t) return @"(no touches)";
    CGPoint p = [t locationInView:nil];
    NSString *phase = @"?";
    switch (t.phase) {
        case UITouchPhaseBegan:     phase = @"Began"; break;
        case UITouchPhaseMoved:     phase = @"Moved"; break;
        case UITouchPhaseEnded:     phase = @"Ended"; break;
        case UITouchPhaseCancelled: phase = @"Cancelled"; break;
        case UITouchPhaseStationary:phase = @"Stationary"; break;
        default: break;
    }
    UIView *v = t.view;
    return [NSString stringWithFormat:@"%@ (%.0f,%.0f) view=%@ type=%ld",
            phase, p.x, p.y,
            v ? NSStringFromClass([v class]) : @"(nil)",
            (long)ev.type];
}

static void AIHookedSendEvent(id self, SEL _cmd, UIEvent *event) {
    gHookHits++;
    @try {
        gLastEventDesc = AIDescribeEvent(event);
        if (gProbeArmed) {
            UITouch *t = [[event allTouches] anyObject];
            if (t) {
                CGPoint p = [t locationInView:nil];
                if (fabs(p.x - gProbePoint.x) < 2.0 && fabs(p.y - gProbePoint.y) < 2.0) {
                    gSyntheticHits++;
                }
            }
        }
    } @catch (NSException *e) { /* 不能因为描述失败就崩 */ }
    if (gOrigSendEvent) ((void (*)(id, SEL, UIEvent *))gOrigSendEvent)(self, _cmd, event);
}

static void AIInstallHook(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class cls = [UIApplication class];
        Method m = class_getInstanceMethod(cls, @selector(sendEvent:));
        if (!m) { AILog(@"  ❌ 找不到 sendEvent:，无法安装事件探针"); return; }
        gOrigSendEvent = method_getImplementation(m);
        method_setImplementation(m, (IMP)AIHookedSendEvent);
        AILog(@"  ✅ 事件探针已安装（hook UIApplication sendEvent:）");
    });
}

// ---------------------------------------------------------------------------
// 取当前所有 window（兼容 iOS 13+ 多场景）
// ---------------------------------------------------------------------------
static NSArray<UIWindow *> *AIAllWindows(void) {
    NSMutableArray *out = [NSMutableArray array];
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return out;

    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in app.connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) if (!w.hidden) [out addObject:w];
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in app.windows) {
        if (!w.hidden && ![out containsObject:w]) [out addObject:w];
    }
#pragma clang diagnostic pop
    return out;
}

static UIWindow *AIMainWindow(void) {
    NSArray *ws = AIAllWindows();
    if (ws.count) return ws.firstObject;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
}

// ---------------------------------------------------------------------------
// 视图树遍历
// ---------------------------------------------------------------------------
static void AIDumpView(UIView *v, int depth, NSMutableString *out, int *controlCount) {
    if (depth > 8) return;
    CGRect f = v.frame;
    CGRect wf = [v convertRect:v.bounds toView:nil];
    NSString *indent = [@"" stringByPaddingToLength:depth * 2 withString:@" " startingAtIndex:0];
    BOOL isCtl = [v isKindOfClass:[UIControl class]];
    if (isCtl && controlCount) (*controlCount)++;

    NSString *extra = @"";
    if ([v isKindOfClass:[UIButton class]]) {
        extra = [NSString stringWithFormat:@" title='%@'", [(UIButton *)v currentTitle] ?: @""];
    } else if ([v isKindOfClass:[UILabel class]]) {
        NSString *tx = [(UILabel *)v text] ?: @"";
        if (tx.length > 24) tx = [tx substringToIndex:24];
        extra = [NSString stringWithFormat:@" text='%@'", tx];
    }

    [out appendFormat:@"%@%@ f=(%.0f,%.0f,%.0f,%.0f) win=(%.0f,%.0f)%@%@\n",
     indent, NSStringFromClass([v class]),
     f.origin.x, f.origin.y, f.size.width, f.size.height,
     wf.origin.x, wf.origin.y,
     isCtl ? @" ★可点" : @"", extra];

    for (UIView *sub in v.subviews) AIDumpView(sub, depth + 1, out, controlCount);
}

// ---------------------------------------------------------------------------
// 通路 A：UIControl 直接触发 action（对按钮 100% 有效，作为「能操作 UI」的正例）
// ---------------------------------------------------------------------------
static BOOL AITapControl(UIWindow *win, CGPoint pt, NSString **desc) {
    UIView *hit = [win hitTest:pt withEvent:nil];
    if (!hit) { if (desc) *desc = @"hitTest 无结果"; return NO; }
    UIView *ctl = hit;
    while (ctl && ![ctl isKindOfClass:[UIControl class]]) ctl = ctl.superview;
    if (!ctl) { if (desc) *desc = [NSString stringWithFormat:@"命中 %@ 但不是 UIControl", NSStringFromClass([hit class])]; return NO; }
    UIControl *c = (UIControl *)ctl;
    NSArray *targets = [c allTargets];
    [c sendActionsForControlEvents:UIControlEventTouchUpInside];
    if (desc) *desc = [NSString stringWithFormat:@"对 %@ 触发 TouchUpInside（targets=%lu）",
                       NSStringFromClass([c class]), (unsigned long)targets.count];
    return YES;
}

// ---------------------------------------------------------------------------
// 通路 B：构造 UITouch + UIEvent，走 [UIApplication sendEvent:]
//   私有 ivar 用 KVC 直接写（KVC 默认 accessInstanceVariablesDirectly=YES，
//   即使属性是 readonly 也能写 ivar）。每一步都 @try，一个失败不拖垮整体。
// ---------------------------------------------------------------------------
static UITouch *AIMakeTouch(CGPoint pt, UIWindow *win, UITouchPhase phase, UIView *view) {
    Class touchCls = NSClassFromString(@"UITouch");
    if (!touchCls) return nil;
    UITouch *t = nil;

    // 候选 1：私有 initWithPoint:inWindow:
    NSArray *sels = @[@"initWithPoint:inWindow:", @"_initWithPoint:inWindow:"];
    for (NSString *sn in sels) {
        SEL sel = NSSelectorFromString(sn);
        NSMethodSignature *sig = [touchCls instanceMethodSignatureForSelector:sel];
        if (!sig) continue;
        @try {
            id raw = [touchCls alloc];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.selector = sel;
            CGPoint p = pt;
            __unsafe_unretained UIWindow *w = win;
            [inv setArgument:&p atIndex:2];
            [inv setArgument:&w atIndex:3];
            [inv invokeWithTarget:raw];
            __unsafe_unretained id ret = nil;
            [inv getReturnValue:&ret];
            t = ret;
            if (t) { AILogf(@"      UITouch 构造成功：%@", sn); break; }
        } @catch (NSException *e) { AILogf(@"      %@ 抛异常 %@", sn, e.reason); }
    }

    // 候选 2：[[UITouch alloc] init] + KVC 写 ivar
    if (!t) {
        @try {
            t = [[touchCls alloc] init];
            AILog(@"      UITouch 用 alloc/init 构造（KVC 填 ivar）");
        } @catch (NSException *e) { return nil; }
    }
    if (!t) return nil;

    NSTimeInterval ts = [[NSProcessInfo processInfo] systemUptime];
    NSDictionary *kv = @{
        @"phase"                     : @(phase),
        @"tapCount"                  : @(1),
        @"timestamp"                 : @(ts),
        @"window"                    : win ?: (id)[NSNull null],
        @"view"                      : view ?: (id)[NSNull null],
        @"locationInWindow"          : [NSValue valueWithCGPoint:pt],
        @"previousLocationInWindow"  : [NSValue valueWithCGPoint:pt],
        @"_locationInWindow"         : [NSValue valueWithCGPoint:pt],
        @"_previousLocationInWindow" : [NSValue valueWithCGPoint:pt],
        @"isTap"                     : @(YES),
    };
    for (NSString *k in kv) {
        id v = kv[k];
        if (v == [NSNull null]) continue;
        @try { [t setValue:v forKey:k]; }
        @catch (NSException *e) { /* ivar 名不对就跳过，不影响别的 */ }
    }
    return t;
}

static UIEvent *AIMakeEvent(UITouch *touch) {
    Class evtCls = NSClassFromString(@"UITouchesEvent") ?: NSClassFromString(@"UIEvent");
    if (!evtCls) return nil;
    UIEvent *ev = nil;
    @try { ev = [[evtCls alloc] init]; } @catch (NSException *e) { return nil; }
    if (!ev) return nil;

    // 候选 1：私有 _addTouch:
    for (NSString *sn in @[@"_addTouch:", @"_addTouch:forDelayedDelivery:"]) {
        SEL sel = NSSelectorFromString(sn);
        if (![ev respondsToSelector:sel]) continue;
        @try {
            if ([sn isEqualToString:@"_addTouch:"]) {
                ((void (*)(id, SEL, id))objc_msgSend)(ev, sel, touch);
            } else {
                ((void (*)(id, SEL, id, BOOL))objc_msgSend)(ev, sel, touch, NO);
            }
            AILogf(@"      UIEvent 用 %@ 挂载 touch", sn);
            break;
        } @catch (NSException *e) { AILogf(@"      %@ 抛异常 %@", sn, e.reason); }
    }

    // 候选 2：KVC 直写 _touches
    @try {
        NSSet *s = [NSSet setWithObject:touch];
        [ev setValue:s forKey:@"_touches"];
        [ev setValue:@(UIEventTypeTouches) forKey:@"type"];
        [ev setValue:@([[NSProcessInfo processInfo] systemUptime]) forKey:@"timestamp"];
    } @catch (NSException *e) { AILogf(@"      KVC 写 _touches 失败 %@", e.reason); }

    // 自检：touches 是否真的挂上了
    @try {
        NSSet *got = [ev allTouches];
        AILogf(@"      UIEvent.allTouches 数量 = %lu", (unsigned long)got.count);
    } @catch (NSException *e) { }
    return ev;
}

static BOOL AITapViaSendEvent(UIWindow *win, CGPoint pt, NSString **desc) {
    UIView *hitView = [win hitTest:pt withEvent:nil];
    NSInteger before = gHookHits, beforeSyn = gSyntheticHits;
    gProbePoint = pt; gProbeArmed = YES;

    UITouch *down = AIMakeTouch(pt, win, UITouchPhaseBegan, hitView);
    if (!down) { if (desc) *desc = @"UITouch 构造失败"; gProbeArmed = NO; return NO; }
    UIEvent *evDown = AIMakeEvent(down);
    if (!evDown) { if (desc) *desc = @"UIEvent 构造失败"; gProbeArmed = NO; return NO; }

    @try {
        [[UIApplication sharedApplication] sendEvent:evDown];
    } @catch (NSException *e) {
        if (desc) *desc = [NSString stringWithFormat:@"sendEvent 抛异常 %@", e.reason];
        gProbeArmed = NO; return NO;
    }

    // 泵 runloop 让事件被真正处理（不能用 usleep，会堵死主线程）
    NSDate *end = [NSDate dateWithTimeIntervalSinceNow:0.10];
    while ([end timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }

    // Ended：同一个 touch 改 phase 再发一次（真实触摸是同一个 UITouch 对象）
    @try { [down setValue:@(UITouchPhaseEnded) forKey:@"phase"]; }
    @catch (NSException *e) { }
    UIEvent *evUp = AIMakeEvent(down);
    if (evUp) {
        @try { [[UIApplication sharedApplication] sendEvent:evUp]; }
        @catch (NSException *e) { }
    }
    end = [NSDate dateWithTimeIntervalSinceNow:0.10];
    while ([end timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }

    gProbeArmed = NO;
    NSInteger dH = gHookHits - before, dS = gSyntheticHits - beforeSyn;
    if (desc) *desc = [NSString stringWithFormat:@"sendEvent 命中 +%ld，坐标匹配 +%ld（hit=%@）",
                       (long)dH, (long)dS,
                       hitView ? NSStringFromClass([hitView class]) : @"nil"];
    return dS > 0;
}

// ---------------------------------------------------------------------------
// 通路 C：hitTest + 手动沿响应链派发 touchesBegan/Ended（不构造 UIEvent）
// ---------------------------------------------------------------------------
static BOOL AITapViaResponderChain(UIWindow *win, CGPoint pt, NSString **desc) {
    UIView *hit = [win hitTest:pt withEvent:nil];
    if (!hit) { if (desc) *desc = @"hitTest 无结果"; return NO; }

    UITouch *t = AIMakeTouch(pt, win, UITouchPhaseBegan, hit);
    if (!t) { if (desc) *desc = @"UITouch 构造失败"; return NO; }
    NSSet *ts = [NSSet setWithObject:t];

    NSInteger before = gHookHits;
    @try {
        [hit touchesBegan:ts withEvent:nil];
        UIResponder *r = hit;
        while ((r = [r nextResponder])) {
            if ([r respondsToSelector:@selector(touchesBegan:withEvent:)]) {
                @try { [r touchesBegan:ts withEvent:nil]; } @catch (NSException *e) { }
            }
        }
    } @catch (NSException *e) {
        if (desc) *desc = [NSString stringWithFormat:@"touchesBegan 抛异常 %@", e.reason];
        return NO;
    }

    @try { [t setValue:@(UITouchPhaseEnded) forKey:@"phase"]; } @catch (NSException *e) { }
    @try {
        [hit touchesEnded:ts withEvent:nil];
        UIResponder *r = hit;
        while ((r = [r nextResponder])) {
            if ([r respondsToSelector:@selector(touchesEnded:withEvent:)]) {
                @try { [r touchesEnded:ts withEvent:nil]; } @catch (NSException *e) { }
            }
        }
    } @catch (NSException *e) { }

    NSDate *end = [NSDate dateWithTimeIntervalSinceNow:0.10];
    while ([end timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    if (desc) *desc = [NSString stringWithFormat:@"已沿响应链派发（hit=%@，sendEvent +%ld）",
                       NSStringFromClass([hit class]), (long)(gHookHits - before)];
    return YES;
}

// ---------------------------------------------------------------------------
// 通路 D：对照 —— 从进程内再试一次 _enqueueHIDEvent:（已知在 iOS 16 无效，留作对照）
// ---------------------------------------------------------------------------
static BOOL AITapViaEnqueueHID(UIWindow *win, CGPoint pt, NSString **desc) {
    UIApplication *app = [UIApplication sharedApplication];
    SEL sel = NSSelectorFromString(@"_enqueueHIDEvent:");
    if (![app respondsToSelector:sel]) { if (desc) *desc = @"_enqueueHIDEvent: 不存在"; return NO; }
    // 没有 IOHIDEvent 可构造（本版不做），只做存在性检查
    if (desc) *desc = @"_enqueueHIDEvent: 存在但本版未构造 IOHIDEvent（已知 v3 三路全灭）";
    return NO;
}

// ---------------------------------------------------------------------------
// 截图（进程内渲染 keyWindow）
// ---------------------------------------------------------------------------
static UIImage *AIScreenshot(UIWindow *win, NSString **desc) {
    if (!win) { if (desc) *desc = @"无 window"; return nil; }
    @try {
        UIGraphicsImageRenderer *r =
            [[UIGraphicsImageRenderer alloc] initWithSize:win.bounds.size];
        __block BOOL ok = NO;
        UIImage *img = [r imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
            ok = [win drawViewHierarchyInRect:win.bounds afterScreenUpdates:YES];
        }];
        if (img) {
            // 平均亮度，用来判断是不是全黑（全黑通常意味着渲染层次没抓到）
            CGFloat lum = 0;
            @try {
                CGImageRef cg = img.CGImage;
                if (cg) {
                    size_t w = CGImageGetWidth(cg), h = CGImageGetHeight(cg);
                    if (w > 0 && h > 0) {
                        NSUInteger bytesPerRow = 4;
                        unsigned char *buf = calloc(w * 4, 1);
                        CGContextRef c = CGBitmapContextCreate(buf, w, 1, 8, w * bytesPerRow,
                                                               CGColorSpaceCreateDeviceRGB(),
                                                               kCGImageAlphaPremultipliedLast);
                        if (c) {
                            CGContextDrawImage(c, CGRectMake(0, 0, w, h), cg);
                            double s = 0;
                            for (size_t i = 0; i < w; i++) {
                                s += (buf[i*4] + buf[i*4+1] + buf[i*4+2]) / 3.0;
                            }
                            lum = s / (double)w;
                            CGContextRelease(c);
                        }
                        free(buf);
                    }
                }
            } @catch (NSException *e) { }
            if (desc) *desc = [NSString stringWithFormat:@"%.0fx%.0f drawOK=%@ 亮度≈%.0f",
                               img.size.width, img.size.height, ok ? @"YES" : @"NO", lum];
            return img;
        }
    } @catch (NSException *e) {
        if (desc) *desc = [NSString stringWithFormat:@"截图抛异常 %@", e.reason];
    }
    if (desc) *desc = @"截图返回空";
    return nil;
}

// ---------------------------------------------------------------------------
// 结果面板（盖在屏幕上，不抢 keyWindow）
// ---------------------------------------------------------------------------
static UIWindow      *gPanel = nil;
static UITextView    *gPanelText = nil;
static UILabel       *gHud = nil;
static NSTimer       *gHudTimer = nil;

static void AIRefreshPanel(void) {
    if (!gPanelText) return;
    NSString *txt;
    @synchronized (gLog) { txt = [gLog copy]; }
    gPanelText.text = txt;
    if (txt.length) {
        NSRange r = NSMakeRange(txt.length - 1, 1);
        [gPanelText scrollRangeToVisible:r];
    }
}

static void AIShowPanel(void) {
    if (gPanel) { AIRefreshPanel(); return; }
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return;

    CGRect screen = [UIScreen mainScreen].bounds;
    gPanel = [[UIWindow alloc] initWithFrame:screen];
    gPanel.windowLevel = UIWindowLevelStatusBar + 200;   // 不 makeKey，避免抢焦点
    gPanel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.92];
    gPanel.hidden = NO;

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor clearColor];
    gPanel.rootViewController = vc;

    // 顶部实时 HUD（真手指点一下这里会 +1，用来证明 hook 是好的）
    gHud = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, screen.size.width, 34)];
    gHud.backgroundColor = [UIColor systemBlueColor];
    gHud.textColor = [UIColor whiteColor];
    gHud.font = [UIFont boldSystemFontOfSize:13];
    gHud.textAlignment = NSTextAlignmentCenter;
    gHud.numberOfLines = 2;
    [vc.view addSubview:gHud];

    gPanelText = [[UITextView alloc] initWithFrame:
                  CGRectMake(6, 38, screen.size.width - 12, screen.size.height - 44)];
    gPanelText.backgroundColor = [UIColor blackColor];
    gPanelText.textColor = [UIColor greenColor];
    gPanelText.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    gPanelText.editable = NO;
    [vc.view addSubview:gPanelText];

    AIRefreshPanel();

    // 实时刷新 HUD：真手指点击能在这里看到 +1
    gHudTimer = [NSTimer scheduledTimerWithTimeInterval:0.4 repeats:YES block:^(NSTimer *t) {
        gHud.text = [NSString stringWithFormat:@"事件探针 命中=%ld  坐标匹配=%ld  最近: %@\n👉 真手指点一下屏幕，命中数应 +1",
                     (long)gHookHits, (long)gSyntheticHits, gLastEventDesc ?: @"—"];
        AIRefreshPanel();
    }];
    [[NSRunLoop mainRunLoop] addTimer:gHudTimer forMode:NSRunLoopCommonModes];
}

// ---------------------------------------------------------------------------
// 主自检流程
// ---------------------------------------------------------------------------
static void AISelfTest(void) {
    static dispatch_once_t onceTest;
    dispatch_once(&onceTest, ^{
        @autoreleasepool {
            pid_t pid = getpid();
            char nameBuf[64] = {0};
            int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};
            struct kinfo_proc kp; size_t len = sizeof(kp);
            if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0) {
                strncpy(nameBuf, kp.kp_proc.p_comm, sizeof(nameBuf) - 1);
            }

            AILog(@"##################################################");
            AILog(@"   AgentInject 进程内自动化执行器  (TrollFools 注入)");
            AILog(@"##################################################");
            AILogf(@"  宿主进程: %s (pid=%d)   bundle: %@",
                   nameBuf, pid, [[NSBundle mainBundle] bundleIdentifier] ?: @"?");
            AILogf(@"  系统: %@   屏幕: %.0f x %.0f",
                   [[UIDevice currentDevice] systemVersion],
                   [UIScreen mainScreen].bounds.size.width,
                   [UIScreen mainScreen].bounds.size.height);

            AIInstallHook();

            // --- 1. 环境 ---
            AIHeader(@"1. 环境");
            NSArray *ws = AIAllWindows();
            AILogf(@"  可见 window 数量: %lu", (unsigned long)ws.count);
            UIWindow *win = AIMainWindow();
            AILogf(@"  主 window: %@", win ? NSStringFromClass([win class]) : @"(无)");

            // --- 2. 视图树 ---
            AIHeader(@"2. 视图树（★=UIControl 可点）");
            int ctlCount = 0;
            NSMutableString *tree = [NSMutableString string];
            if (win) AIDumpView(win, 0, tree, &ctlCount);
            AILogf(@"  可点控件(UIControl) 数量: %d", ctlCount);
            if (tree.length > 3000) {
                AILog([tree substringToIndex:3000]);
                AILog(@"  ...(已截断)");
            } else {
                AILog(tree);
            }

            // --- 3. 触摸通路 ---
            AIHeader(@"3. 进程内合成触摸（逐条验证）");
            CGSize sc = [UIScreen mainScreen].bounds.size;
            CGPoint pt = CGPointMake(sc.width * 0.5, sc.height * 0.62);
            AILogf(@"  目标坐标 (%.0f, %.0f)", pt.x, pt.y);
            AILog(@"  ※ 判据：hook 到 sendEvent: 且事件坐标 == 合成坐标 = 事件真的进了处理链");

            NSString *d = nil; BOOL ok = NO;

            ok = AITapViaResponderChain(win, pt, &d);
            AILogf(@"  [C 响应链手动派发] %@ → %@", d, ok ? @"✅" : @"—");

            ok = AITapViaSendEvent(win, pt, &d);
            AILogf(@"  [B UIEvent→sendEvent] %@ → %@", d, ok ? @"✅ 合成事件已进处理链" : @"❌ 未进处理链");

            d = nil; ok = AITapControl(win, pt, &d);
            AILogf(@"  [A UIControl 直接触发] %@ → %@", d, ok ? @"✅" : @"—");

            d = nil; ok = AITapViaEnqueueHID(win, pt, &d);
            AILogf(@"  [D _enqueueHIDEvent 对照] %@", d);

            // --- 4. 截图 ---
            AIHeader(@"4. 进程内截图");
            d = nil;
            UIImage *img = AIScreenshot(win, &d);
            AILogf(@"  %@", d);
            if (img) {
                @try {
                    NSData *png = UIImagePNGRepresentation(img);
                    NSString *p = @"/var/mobile/agentinject_shot.png";
                    NSError *err = nil;
                    BOOL wrote = [png writeToFile:p options:NSDataWritingAtomic error:&err];
                    AILogf(@"  写文件 %@ → %@", p, wrote ? @"✅ 成功" :
                           [NSString stringWithFormat:@"❌ %@", err.localizedDescription]);
                } @catch (NSException *e) { AILogf(@"  写文件异常 %@", e.reason); }
            }

            // --- 5. 日志落盘 ---
            NSString *lp = @"/var/mobile/agentinject.log";
            NSString *txt; @synchronized (gLog) { txt = [gLog copy]; }
            @try {
                NSError *e2 = nil;
                BOOL w2 = [txt writeToFile:lp atomically:YES encoding:NSUTF8StringEncoding error:&e2];
                AILogf(@"  日志落盘 %@ → %@", lp, w2 ? @"✅" : @"❌(沙箱限制，不影响结论)");
            } @catch (NSException *e) { }

            AIHeader(@"结论");
            AILog(@"  看第 3 段：");
            AILog(@"   · B 路 ✅ → 进程内能合成真触摸，可执行器直接操作 UI");
            AILog(@"   · 仅 A 路 ✅ → 只能触发 UIControl，得靠响应链/直接调方法");
            AILog(@"   · 全 ❌ → 进程内也合成不了，只能上越狱或硬件方案");
            AILog(@"");
            AILog(@"  👉 请用真手指点一下屏幕：顶部 HUD 的「命中」应 +1。");
            AILog(@"     若真手指也不 +1，说明 hook 没装上，本轮结论作废。");

            AIShowPanel();
        }
    });
}

// ---------------------------------------------------------------------------
// 入口：dylib 被加载时执行
// 注意 constructor 跑在 App 启动很早期，UIKit 还没就绪 —— 必须延迟。
// 三重触发：didFinishLaunching 通知 + 延迟 8s 兜底（通知可能已经错过）。
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void AgentInjectEntry(void) {
    @autoreleasepool {
        AILog(@"[AgentInject] dylib 已加载，等待宿主 App 就绪…");
        [[NSNotificationCenter defaultCenter]
         addObserverForName:UIApplicationDidFinishLaunchingNotification
         object:nil queue:[NSOperationQueue mainQueue]
         usingBlock:^(NSNotification *n) {
             AILog(@"[AgentInject] 收到 didFinishLaunching，6 秒后开始自检");
             dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)),
                            dispatch_get_main_queue(), ^{ AISelfTest(); });
         }];
        // 兜底：无论有没有收到通知，8 秒后一定跑
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ AISelfTest(); });
    }
}
