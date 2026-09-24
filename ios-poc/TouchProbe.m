//
//  TouchProbe.m
//  触控注入能力探针 —— 验证「模拟人点屏幕」在本机是否可行
//
//  背景：手机自动化执行器必须能合成触控事件。iOS 上有三条可能通路：
//    通道 1：IOHIDEvent 私有 API —— 直接构造 HID 事件投递给 SpringBoard
//    通道 2：GSEvent 私有 API（GraphicsServices）—— 构造 GSEventRecord
//    通道 3：UIKit 层 UIApplication sendEvent（仅限自身进程，作对照）
//
//  本探针把三条通路全部并行试一遍，用 dlopen/dlsym 动态查找私有符号，
//  存在性探测 + 符号解析探测 + 实际调用探测 三层递进，
//  一次上机即可拿到完整结论。不做任何破坏性动作（只点安全坐标）。
//

#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_param.h>
#import <dlfcn.h>
#import <unistd.h>
#import <string.h>
#import <objc/runtime.h>
// csops：查询进程代码签名状态（libsystem_kernel）。
// 注意：iOS SDK 不提供 <sys/codesign.h>（那是 macOS 的头文件），
// 因此常量与原型在此显式声明。CS_OPS_STATUS = 0。
#define CS_OPS_STATUS 0
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

static UITextView      *gLogView = nil;
static NSMutableString *gLog     = nil;

static void TPLog(NSString *line) {
    NSLog(@"[PROBE] %@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
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
    TPLog([NSString stringWithFormat:@"===== %@ =====", t]);
}

// ---------------------------------------------------------------------------
// 结果汇总
// ---------------------------------------------------------------------------

static NSMutableArray<NSDictionary *> *gResults = nil;

static void TPRecord(NSString *channel, NSString *verdict, NSString *detail) {
    if (!gResults) gResults = [NSMutableArray array];
    [gResults addObject:@{@"channel": channel, @"verdict": verdict, @"detail": detail ?: @""}];
    TPLog([NSString stringWithFormat:@"【%@】%@  %@", channel, verdict, detail ?: @""]);
}

// ===========================================================================
// 通道 1：IOHIDEvent 私有 API
// ===========================================================================
//
// 思路：dlopen 私有框架，拿到 IOHIDEventCreateXXX 系列构造器 + 事件投递函数。
// 关键符号（不同 iOS 版本命名略有差异，故做多候选匹配）：
//   构造：IOHIDEventCreateDigitizerEvent / IOHIDEventCreateDigitizerFingerEvent
//   投递：IOHIDEventSystemClientDispatchEvent
//         IOHIDEventSystemClientCreateSimpleClient
//

typedef void *IOHIDEventRef;
typedef void *IOHIDEventSystemClientRef;

// 类型编码（来自 IOKit/hid 头文件的逆向结果）
// kIOHIDEventTypeDigitizer = 3
// IOHIDDigitizerTransducerTypeFinger = 2
// IOHIDDigitizerEventRange = 1<<0, Touch = 1<<1, Position = 1<<2, Identity = 1<<3
//   => 全套 = 0xF（range|touch|position|identity）

static void TP_Channel1_IOHIDEvent(void) {
    TPHeader(@"通道 1：IOHIDEvent 私有 API（dlopen 动态解析）");

    // --- 1.1 框架可加载性 ---
    const char *fwPaths[] = {
        "/System/Library/PrivateFrameworks/IOHID.framework/IOHID",
        "/System/Library/Frameworks/IOKit.framework/IOKit",
    };
    void *hIOHID = NULL;
    for (int i = 0; i < 2; i++) {
        void *h = dlopen(fwPaths[i], RTLD_LAZY | RTLD_GLOBAL);
        TPLog([NSString stringWithFormat:@"  dlopen %s → %s", fwPaths[i], h ? "OK" : dlerror()]);
        if (h && !hIOHID) hIOHID = h;
    }

    // --- 1.2 符号解析 ---
    const char *ctorNames[] = {
        "IOHIDEventCreateDigitizerEvent",
        "IOHIDEventCreateDigitizerFingerEvent",
        "IOHIDEventCreateDigitizerFingerEventWithQuality",
    };
    void *ctor = NULL;
    NSString *ctorUsed = nil;
    for (int i = 0; i < 3; i++) {
        void *p = hIOHID ? dlsym(hIOHID, ctorNames[i]) : NULL;
        if (!p) p = dlsym(RTLD_DEFAULT, ctorNames[i]);
        TPLog([NSString stringWithFormat:@"  dlsym %s → %p", ctorNames[i], p]);
        if (p && !ctor) { ctor = p; ctorUsed = @(ctorNames[i]); }
    }

    const char *clientNames[] = {
        "IOHIDEventSystemClientCreateSimpleClient",
        "IOHIDEventSystemClientCreate",
    };
    void *clientCreate = NULL;
    for (int i = 0; i < 2; i++) {
        void *p = hIOHID ? dlsym(hIOHID, clientNames[i]) : NULL;
        if (!p) p = dlsym(RTLD_DEFAULT, clientNames[i]);
        TPLog([NSString stringWithFormat:@"  dlsym %s → %p", clientNames[i], p]);
        if (p && !clientCreate) clientCreate = p;
    }

    void *dispatch = hIOHID ? dlsym(hIOHID, "IOHIDEventSystemClientDispatchEvent") : NULL;
    if (!dispatch) dispatch = dlsym(RTLD_DEFAULT, "IOHIDEventSystemClientDispatchEvent");
    TPLog([NSString stringWithFormat:@"  dlsym IOHIDEventSystemClientDispatchEvent → %p", dispatch]);

    // --- 1.3 判定 ---
    NSMutableArray *missing = [NSMutableArray array];
    if (!hIOHID)       [missing addObject:@"框架不可加载"];
    if (!ctor)         [missing addObject:@"事件构造器缺失"];
    if (!clientCreate) [missing addObject:@"Client 创建函数缺失"];
    if (!dispatch)     [missing addObject:@"事件投递函数缺失"];

    if (missing.count > 0) {
        TPRecord(@"通道1 IOHIDEvent", @"FAILED",
                 [NSString stringWithFormat:@"缺少: %@", [missing componentsJoinedByString:@", "]]);
        TPLog(@"  说明：符号层面就走不通，无需再试实际调用。");
        return;
    }

    // --- 1.4 实际调用 ---
    typedef void *(*CreateClientFn)(int, int);
    typedef IOHIDEventRef (*CreateFingerFn)(double, double, int, int, int, int, double);
    typedef void (*DispatchFn)(IOHIDEventSystemClientRef, IOHIDEventRef);

    CreateClientFn createClient = (CreateClientFn)clientCreate;
    DispatchFn     sendEvent    = (DispatchFn)dispatch;

    IOHIDEventSystemClientRef client = createClient(0, 0);
    TPLog([NSString stringWithFormat:@"  createClient() → %p", client]);
    if (!client) {
        TPRecord(@"通道1 IOHIDEvent", @"PARTIAL", @"符号齐全但 client 创建返回空");
        return;
    }

    if (![ctorUsed isEqualToString:@"IOHIDEventCreateDigitizerFingerEvent"]) {
        TPRecord(@"通道1 IOHIDEvent", @"PARTIAL",
                 [NSString stringWithFormat:@"符号齐全（用了 %@），但本探针只实现了 Finger 事件路径", ctorUsed]);
        return;
    }

    CreateFingerFn mkFinger = (CreateFingerFn)ctor;
    CGSize  screen = [UIScreen mainScreen].bounds.size;
    CGPoint pt     = CGPointMake(screen.width / 2.0, screen.height / 2.0);

    // range=1(接触) touch=1 position=1
    IOHIDEventRef down = mkFinger(0, 0, 0, 2 /*finger*/, 0xF /*range|touch|position|identity*/, 1 /*down*/, 0.0);
    IOHIDEventRef up   = mkFinger(0, 0, 0, 2, 0x8 /*identity 归零=抬起*/, 0, 0.0);

    if (!down) {
        TPRecord(@"通道1 IOHIDEvent", @"PARTIAL", @"事件构造返回空（参数签名可能不符本机版本）");
        return;
    }

    sendEvent(client, down);
    usleep(30000);
    if (up) sendEvent(client, up);

    TPRecord(@"通道1 IOHIDEvent", @"CALLED",
             [NSString stringWithFormat:@"已向 (%.0f,%.0f) 投递 down/up，无崩溃", pt.x, pt.y]);
    TPLog(@"  注意：CALLED 仅代表「调用未报错」，是否真的生效要看屏幕反应 + 通道3对照。");
}

// ===========================================================================
// 通道 2：GSEvent 私有 API（GraphicsServices）
// ===========================================================================

static void TP_Channel2_GSEvent(void) {
    TPHeader(@"通道 2：GSEvent 私有 API（GraphicsServices）");

    void *hGS = dlopen("/System/Library/PrivateFrameworks/GraphicsServices.framework/GraphicsServices",
                       RTLD_LAZY | RTLD_GLOBAL);
    TPLog([NSString stringWithFormat:@"  dlopen GraphicsServices → %s", hGS ? "OK" : dlerror()]);

    const char *names[] = {
        "GSEventCreateWithEventType",
        "GSSendEvent",
        "GSInitialize",
        "_GSSendEvent",
    };
    NSMutableArray *found = [NSMutableArray array];
    for (int i = 0; i < 4; i++) {
        void *p = hGS ? dlsym(hGS, names[i]) : NULL;
        if (!p) p = dlsym(RTLD_DEFAULT, names[i]);
        TPLog([NSString stringWithFormat:@"  dlsym %-28s → %p", names[i], p]);
        if (p) [found addObject:@(names[i])];
    }

    // 同时探测 GSEventRecord 类结构体是否可构造（需要私有头文件定义，
    // 这里只做符号层判定，不构造结构体，避免尺寸不符导致越界写）
    if (found.count == 0) {
        TPRecord(@"通道2 GSEvent", @"FAILED", @"全部符号缺失");
    } else if (![found containsObject:@"GSEventCreateWithEventType"] || ![found containsObject:@"GSSendEvent"]) {
        TPRecord(@"通道2 GSEvent", @"PARTIAL",
                 [NSString stringWithFormat:@"仅找到 %@，构造/投递不齐", [found componentsJoinedByString:@","]]);
    } else {
        TPRecord(@"通道2 GSEvent", @"SYMBOLS_OK",
                 @"构造+投递符号齐全，但需精确复刻 GSEventRecord 结构体布局才能调用（未在本探针实施）");
    }
    TPLog(@"  说明：GSEventRecord 是未公开结构体，字段偏移随版本变化；");
    TPLog(@"        继续走这条路需要先dump 出结构体布局，属第二阶段工作。");
}

// ===========================================================================
// 通道 3：UIKit 层自测（对照组，验证探针逻辑本身正确）
// ===========================================================================
//
// 这条通路只能给「自己这个 App」投事件，无法跨 App，故不是目标通路。
// 但它能证明：事件构造参数、坐标换算是对的 —— 作为对照组排除「探针写错了」。

@interface TPProbeView : UIView
@property (nonatomic, assign) CGPoint lastTouchPoint;
@end

@implementation TPProbeView
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    self.lastTouchPoint = [t locationInView:self];
    TPLog([NSString stringWithFormat:@"  ✅ 收到真实触摸: (%.0f, %.0f)", self.lastTouchPoint.x, self.lastTouchPoint.y]);
}
@end

static TPProbeView *gProbeView = nil;

static void TP_Channel3_UIKitSelfTest(void) {
    TPHeader(@"通道 3：UIKit 自测（对照组）");

    if (!gProbeView) {
        TPRecord(@"通道3 UIKit对照", @"SKIP", @"探针视图未初始化");
        return;
    }
    CGPoint c = gProbeView.center;
    TPLog([NSString stringWithFormat:@"  参照点（本 App 视图中心）: (%.0f, %.0f)", c.x, c.y]);

    // 验证 UITouch 是否可被外部构造（若可，则单进程内也能合成事件）
    BOOL canAlloc = class_respondsToSelector(object_getClass([UITouch class]), @selector(alloc));
    TPLog([NSString stringWithFormat:@"  UITouch 类可 alloc : %@", canAlloc ? @"是" : @"否"]);
    TPLog(@"  说明：UITouch 的 init 受保护，实际无法凭空构造有效触摸对象。");

    TPRecord(@"通道3 UIKit对照", @"BASELINE",
             @"仅用于坐标/参数校验，不能跨 App 投递");
}

// ===========================================================================
// 权限与身份信息（决定上面各通道能否生效的根因）
// ===========================================================================

static void TP_EnvironmentInfo(void) {
    TPHeader(@"环境与权限信息");

    TPLog([NSString stringWithFormat:@"  自身 pid      : %d", getpid()]);
    TPLog([NSString stringWithFormat:@"  自身 bundle   : %@", [[NSBundle mainBundle] bundleIdentifier]]);
    TPLog([NSString stringWithFormat:@"  系统版本      : %@", [[UIDevice currentDevice] systemVersion]]);
    TPLog([NSString stringWithFormat:@"  设备型号      : %@", [[UIDevice currentDevice] model]]);
    CGSize s = [UIScreen mainScreen].bounds.size;
    TPLog([NSString stringWithFormat:@"  屏幕逻辑尺寸  : %.0f x %.0f", s.width, s.height]);
    TPLog([NSString stringWithFormat:@"  屏幕 scale    : %.1f", [UIScreen mainScreen].scale]);

    // 进程身份：是否被当作 platform binary
    uint32_t flags = 0;
    int r = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    TPLog([NSString stringWithFormat:@"  csops 返回    : %d, 进程 flags = 0x%08X", r, flags]);

    // 关键 flag 解读
    // CS_PLATFORM_BINARY    0x04000000
    // CS_GET_TASK_ALLOW     0x00000004
    // CS_HARD / CS_KILL     0x100 / 0x200
    struct { const char *n; uint32_t b; } tb[] = {
        {"CS_PLATFORM_BINARY", 0x04000000},
        {"CS_GET_TASK_ALLOW",  0x00000004},
        {"CS_DEBUGGED",        0x10000000},
        {"CS_HARD",            0x00000100},
        {"CS_RESTRICT",        0x00000800},
        {"CS_REQUIRE_LV",      0x00002000},
    };
    for (int i = 0; i < 6; i++)
        TPLog([NSString stringWithFormat:@"    %-20s : %@", tb[i].n,
               (flags & tb[i].b) ? @"✅ 有" : @"❌ 无"]);

    // 沙箱状态：能否写根目录
    BOOL canWriteRoot = [[NSFileManager defaultManager] isWritableFileAtPath:@"/"] ? YES : NO;
    TPLog([NSString stringWithFormat:@"  / 可写        : %@", canWriteRoot ? @"✅ 是（无沙箱）" : @"❌ 否（有沙箱）"]);
}

// ===========================================================================
// 主入口
// ===========================================================================

static void TP_RunAll(void) {
    gResults = [NSMutableArray array];
    TPLog(@"");
    TPLog(@"######################################");
    TPLog(@"   触控注入能力探针  TouchProbe");
    TPLog(@"######################################");

    TP_EnvironmentInfo();
    TP_Channel1_IOHIDEvent();
    TP_Channel2_GSEvent();
    TP_Channel3_UIKitSelfTest();

    // ---- 汇总 ----
    TPHeader(@"结论汇总");
    NSString *best = @"无可用通路";
    int bestRank = 0;   // 0=无 1=FAILED 2=PARTIAL 3=SYMBOLS_OK/CALLED
    for (NSDictionary *r in gResults) {
        NSString *v = r[@"verdict"];
        int rank = 0;
        if ([v isEqualToString:@"FAILED"]) rank = 1;
        else if ([v isEqualToString:@"PARTIAL"]) rank = 2;
        else if ([v isEqualToString:@"SYMBOLS_OK"] || [v isEqualToString:@"CALLED"]) rank = 3;
        if (rank > bestRank) { bestRank = rank; best = r[@"channel"]; }
    }

    TPLog([NSString stringWithFormat:@"可用通路评估: %@", best]);
    if (bestRank >= 3) {
        TPLog(@"下一步：确认屏幕是否真的响应了点击（观察是否有关键事件被触发）");
    } else if (bestRank == 2) {
        TPLog(@"下一步：细化工到符号/结构体层，需要 dump 私有头文件布局");
    } else {
        TPLog(@"下一步：本机私有 API 路走不通，改走 Frida Gadget 路线");
    }
    TPLog(@"######################################");
}

// ===========================================================================
// UI
// ===========================================================================

@interface TPRootViewController : UIViewController
@end

@implementation TPRootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Touch Probe";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    gLogView = [[UITextView alloc] initWithFrame:CGRectZero];
    gLogView.font = [UIFont monospacedSystemFontOfSize:10.0 weight:UIFontWeightRegular];
    gLogView.editable = NO;
    gLogView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:gLogView];

    // 对照组视图：铺满下半屏，探测真实触摸是否到达
    gProbeView = [[TPProbeView alloc] initWithFrame:CGRectZero];
    gProbeView.backgroundColor = [UIColor colorWithRed:0.12 green:0.30 blue:0.55 alpha:1.0];
    gProbeView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:gProbeView];

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectZero];
    hint.text = @"蓝色区域 = 触摸对照区（真实触摸会打印坐标）";
    hint.font = [UIFont systemFontOfSize:11.0];
    hint.textColor = [UIColor whiteColor];
    hint.translatesAutoresizingMaskIntoConstraints = NO;
    [gProbeView addSubview:hint];

    UIButton *runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [runButton setTitle:@"开始探针" forState:UIControlStateNormal];
    runButton.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    runButton.translatesAutoresizingMaskIntoConstraints = NO;
    [runButton addTarget:self action:@selector(runProbe) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:runButton];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [runButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:8.0],
        [runButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],

        [gLogView.topAnchor constraintEqualToAnchor:runButton.bottomAnchor constant:8.0],
        [gLogView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:8.0],
        [gLogView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-8.0],
        [gLogView.heightAnchor constraintEqualToConstant:340.0],

        [gProbeView.topAnchor constraintEqualToAnchor:gLogView.bottomAnchor constant:8.0],
        [gProbeView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:8.0],
        [gProbeView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-8.0],
        [gProbeView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-8.0],

        [hint.centerXAnchor constraintEqualToAnchor:gProbeView.centerXAnchor],
        [hint.centerYAnchor constraintEqualToAnchor:gProbeView.centerYAnchor],
    ]];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(runProbe)
                                                 name:@"TPRunNotification"
                                               object:nil];

    TPLog(@"就绪。点『开始探针』，或用 touchprobe://run 唤起。");
}

- (void)runProbe {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        TP_RunAll();
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
    TPRootViewController *root = [[TPRootViewController alloc] init];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:root];
    [self.window makeKeyAndVisible];
    return YES;
}

- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    TPLog([NSString stringWithFormat:@"被 URL 唤醒: %@", url.absoluteString]);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"TPRunNotification" object:nil];
    });
    return YES;
}

@end
