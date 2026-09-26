//
//  HLProbe.m —— 老贝贝底座「运行时探针」dylib
//
//  目的：一次注入，把规格书 §2.4 悬而未决的组合（eventMask × Create 参数个数
//        × 字段常量）在真机上一个不漏地试完，并把结果用肉眼可见的方式显示出来。
//
//  为什么不用「改 Makefile 宏重编 9 次」：
//      · 每换一种组合就要 GitHub 编一次 + 重注入一次，9 种 = 9 轮，太慢
//      · 崩溃发生在运行时，编译时看不出来
//      → 这里把 18 种组合（3 事件形态 × 2 字段常量集 × 3 mask）全部编进同一份 dylib，
//        UI 上一个按钮逐个试；崩了重启 App 自动从断点继续（NSUserDefaults 记录）。
//
//  判据（拒绝「看起来对」）：
//      · 触摸：屏幕正中央有一个计数器按钮。手动点 +1 证明按钮本身活着；
//        合成触摸若真的到达 App，同一个按钮 +1。数字涨了才算通过。
//      · 取色：三块纯色 UIView（红/绿/蓝），取色回读 RGB。
//        红读成蓝 = byte order 反了，一眼可见。
//
//  组合编号 k ∈ [0,18)：form = k%3, fieldset = (k/3)%2, mask = (k/6)%3
//
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <dlfcn.h>
#import <mach/mach_time.h>
#import <unistd.h>

#pragma mark - A. IOKit 桥（dlopen + dlsym，与已验证可用的 AgentInject2 同款写法）

static void *gProbeClient = NULL;   // 选中的 HID client（必须定义在使用点之前）

typedef void    *IOHIDEventRef;
typedef void    *IOHIDEventSystemClientRef;
typedef uint64_t IOHIDTime;

// 14 参容器（现状主力）
typedef IOHIDEventRef (*F_CreateDigitizer)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t,
                                           uint32_t, uint32_t, uint32_t,
                                           double, double, double, double, double,
                                           Boolean, Boolean, uint32_t);
// 18 参手指（新签名）
typedef IOHIDEventRef (*F_CreateFingerQ)(CFAllocatorRef, IOHIDTime, uint32_t, uint32_t, uint32_t,
                                         double, double, double, double, double,
                                         double, double, double, double, double,
                                         Boolean, Boolean, uint32_t);
// 11 参手指（老签名，连点器同款）
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

static F_CreateDigitizer gCreate = NULL;
static F_CreateFingerQ   gFingerQ = NULL;
static F_CreateFingerOld gFingerOld = NULL;
static F_Append          gAppend = NULL;
static F_SetInt          gSetInt = NULL;
static F_SetFloat        gSetFloat = NULL;
static F_SetSender       gSetSender = NULL;
static F_ClientCreate    gClientCreate = NULL;
static F_ClientSimple    gClientSimple = NULL;
static F_ClientType      gClientType = NULL;
static F_Dispatch        gDispatch = NULL;

static NSString *gSymReport = @"未加载";

static void HLLoadHID(void) {
    const char *fws[] = {
        "/System/Library/PrivateFrameworks/IOHID.framework/IOHID",
        "/System/Library/Frameworks/IOKit.framework/IOKit",
    };
    for (int i = 0; i < 2; i++) dlopen(fws[i], RTLD_LAZY | RTLD_GLOBAL);

    struct { const char *n; void **s; } tab[] = {
        {"IOHIDEventCreateDigitizerEvent",                  (void **)&gCreate},
        {"IOHIDEventCreateDigitizerFingerEventWithQuality", (void **)&gFingerQ},
        {"IOHIDEventCreateDigitizerFingerEvent",            (void **)&gFingerOld},
        {"IOHIDEventAppendEvent",                           (void **)&gAppend},
        {"IOHIDEventSetIntegerValue",                       (void **)&gSetInt},
        {"IOHIDEventSetFloatValue",                         (void **)&gSetFloat},
        {"IOHIDEventSetSenderID",                           (void **)&gSetSender},
        {"IOHIDEventSystemClientCreate",                    (void **)&gClientCreate},
        {"IOHIDEventSystemClientCreateSimpleClient",        (void **)&gClientSimple},
        {"IOHIDEventSystemClientCreateWithType",            (void **)&gClientType},
        {"IOHIDEventSystemClientDispatchEvent",             (void **)&gDispatch},
    };
    int miss = 0;
    NSMutableString *ms = [NSMutableString string];
    for (int i = 0; i < (int)(sizeof(tab) / sizeof(tab[0])); i++) {
        void *p = dlsym(RTLD_DEFAULT, tab[i].n);
        *(tab[i].s) = p;
        if (!p) { miss++; [ms appendFormat:@"%s ", tab[i].n]; }
    }
    gSymReport = miss ? [NSString stringWithFormat:@"缺 %d 个: %@", miss, ms] : @"11/11 全部命中";
}

#pragma mark - B. 两套字段常量（真机已验证 vs 规格书 §2.4 给的）

#define HL_SET_OURS 0   // AgentInject2 真机跑通用：X=0x0B0000
#define HL_SET_SPEC 1   // 规格书 §2.4 给的：X=0x0B0030
#define HL_SET_BEI  2   // 老贝贝逆向报告 §4.3：X=0x0B0014 / Y=0x0B0015（三套常量之一，别照抄！）

static uint32_t HLFieldX(int set)         { return set==HL_SET_OURS ? 0x0B0000u : (set==HL_SET_SPEC ? 0x0B0030u : 0x0B0014u); }
static uint32_t HLFieldY(int set)         { return set==HL_SET_OURS ? 0x0B0001u : (set==HL_SET_SPEC ? 0x0B0031u : 0x0B0015u); }
static uint32_t HLFieldIsDisplay(int set) { return set==HL_SET_OURS ? 0x0B0019u : (set==HL_SET_SPEC ? 0x0B002Au : 0x0B0019u); }

static NSString *HLSetName(int set) { return set==HL_SET_OURS ? @"OURS" : (set==HL_SET_SPEC ? @"SPEC" : @"BEI"); }

// mask 三候选。ph: 0=down 1=move 2=up
static uint32_t HLMask(int mi, int ph) {
    switch (mi) {
        case 0: return 0x03;                                  // Range|Touch
        case 1: return (ph == 1) ? 0x64 : 0x63;               // +Identity|Attribute
        case 2: return 0x07;                                  // Range|Touch|Position
    }
    return 0x03;
}
static NSString *HLMaskName(int mi) { return @[@"A-0x03", @"B-0x63/64", @"C-0x07"][mi]; }

static NSString *HLFormName(int form) {
    return @[@"复合hand+Q18", @"裸finger-Q18", @"裸finger-Old11"][form];
}

// 构造一个事件。nx/ny 已归一化 0–1。
static IOHIDEventRef HLMakeEvent(int form, int set, int mi, double nx, double ny, int ph) {
    IOHIDTime ts = mach_absolute_time();
    uint32_t mask = HLMask(mi, ph);
    uint32_t touching = (ph == 2) ? 0 : 1;

    if (form == 0) {
        if (!gCreate || !gFingerQ || !gAppend) return NULL;
        IOHIDEventRef hand = gCreate(kCFAllocatorDefault, ts, 3 /*hand*/, 0, 0,
                                     mask, 0, 0, 0, 0, 0, 0, 0, true, 0);
        if (!hand) return NULL;
        if (gSetInt) gSetInt(hand, HLFieldIsDisplay(set), 1);
        IOHIDEventRef f = gFingerQ(kCFAllocatorDefault, ts, 1, 1, mask,
                                   nx, ny, 0.0, 0.0, 0.0,
                                   0.0, 0.0, 0.0, 0.0, 0.0,
                                   touching ? true : false, true, 0);
        if (f) {
            if (gSetFloat) { gSetFloat(f, HLFieldX(set), nx); gSetFloat(f, HLFieldY(set), ny); }
            if (gSetInt)   gSetInt(f, HLFieldIsDisplay(set), 1);
            gAppend(hand, f);
        }
        return hand;
    } else if (form == 1) {
        if (!gFingerQ) return NULL;
        IOHIDEventRef f = gFingerQ(kCFAllocatorDefault, ts, 1, 1, mask,
                                   nx, ny, 0.0, 0.0, 0.0,
                                   0.0, 0.0, 0.0, 0.0, 0.0,
                                   touching ? true : false, true, 0);
        if (f && gSetFloat) { gSetFloat(f, HLFieldX(set), nx); gSetFloat(f, HLFieldY(set), ny); }
        return f;
    } else {
        if (!gFingerOld) return NULL;
        IOHIDEventRef f = gFingerOld(kCFAllocatorDefault, ts, 1, 1, mask,
                                     nx, ny, 0.0, 0.0, 0.0, (uint32_t)touching);
        if (f && gSetFloat) { gSetFloat(f, HLFieldX(set), nx); gSetFloat(f, HLFieldY(set), ny); }
        return f;
    }
}

#pragma mark - C. 取色（规格书 §3：drawViewHierarchy + CoreGraphics 读像素）

static UIImage *HLSnapshot(UIWindow *win) {
    if (!win) return nil;
    UIGraphicsBeginImageContextWithOptions(win.bounds.size, NO, [UIScreen mainScreen].scale);
    @try { [win drawViewHierarchyInRect:win.bounds afterScreenUpdates:NO]; }
    @catch (NSException *e) { UIGraphicsEndImageContext(); return nil; }
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return img;
}

// 返回 "R,G,B (RGBA读) / R,G,B (BGRA读)"
static NSString *HLReadPixel(UIImage *img, CGPoint logicPoint) {
    if (!img) return @"no-img";
    CGImageRef cg = img.CGImage;
    if (!cg) return @"no-cg";
    CGFloat scale = [UIScreen mainScreen].scale;
    size_t w = CGImageGetWidth(cg), h = CGImageGetHeight(cg);
    size_t px = (size_t)(logicPoint.x * scale), py = (size_t)(logicPoint.y * scale);
    if (px >= w || py >= h) return @"out-of-range";

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, w * 4, cs,
        (CGBitmapInfo)(kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big));
    CGColorSpaceRelease(cs);
    if (!ctx) return @"no-ctx";
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
    const uint8_t *d = (const uint8_t *)CGBitmapContextGetData(ctx);
    size_t off = (py * w + px) * 4;
    NSString *s = [NSString stringWithFormat:@"RGBA(%d,%d,%d) BGRA(%d,%d,%d)",
                   d[off], d[off+1], d[off+2], d[off+2], d[off+1], d[off]];
    CGContextRelease(ctx);
    return s;
}

#pragma mark - D. 探针 UI

#define HL_TOTAL 27   // 3 事件形态 × 3 字段常量集(OURS/SPEC/BEI) × 3 mask
#define K_IDX   @"hlprobe_idx"
#define K_TRY   @"hlprobe_trying"
#define K_RES   @"hlprobe_results"

@interface HLProbeVC : UIViewController
@property (nonatomic, strong) UILabel     *head;
@property (nonatomic, strong) UILabel     *resultList;
@property (nonatomic, strong) UIButton    *target;
@property (nonatomic, strong) NSArray     *swatches;   // ARC 下不能用 C 数组属性
@property (nonatomic, strong) UILabel     *colorOut;
@property (nonatomic, assign) int          manualN;
@property (nonatomic, assign) int          synthN;
@property (nonatomic, assign) int          idx;
@property (nonatomic, assign) BOOL         autoRunning;
@property (nonatomic, strong) NSString    *clientName;
@end

@implementation HLProbeVC

- (void)viewDidLoad {
    [super viewDidLoad];
    CGRect b = [UIScreen mainScreen].bounds;
    self.view.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];

    self.head = [[UILabel alloc] initWithFrame:CGRectMake(8, 44, b.size.width - 16, 56)];
    self.head.numberOfLines = 0;
    self.head.font = [UIFont systemFontOfSize:11];
    self.head.textColor = [UIColor whiteColor];
    [self.view addSubview:self.head];

    // ★ 必须在屏幕正中央：合成触摸固定打中心点
    self.target = [UIButton buttonWithType:UIButtonTypeSystem];
    self.target.frame = CGRectMake(0, 0, 240, 130);
    self.target.center = CGPointMake(b.size.width / 2, b.size.height / 2);
    self.target.backgroundColor = [UIColor colorWithRed:0.13 green:0.35 blue:0.55 alpha:1];
    self.target.layer.cornerRadius = 12;
    self.target.titleLabel.numberOfLines = 0;
    self.target.titleLabel.font = [UIFont systemFontOfSize:15];
    [self.target setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self.target addTarget:self action:@selector(onManual:)
          forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.target];

    // 三块纯色
    NSArray *cols = @[[UIColor redColor], [UIColor greenColor], [UIColor blueColor]];
    CGFloat y = b.size.height - 320;
    NSMutableArray *sw = [NSMutableArray array];
    for (int i = 0; i < 3; i++) {
        UIView *v = [[UIView alloc] initWithFrame:CGRectMake(20 + i * 90, y, 80, 60)];
        v.backgroundColor = cols[i];
        v.tag = 100 + i;
        [self.view addSubview:v];
        [sw addObject:v];
    }
    self.swatches = sw;

    self.colorOut = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 64, b.size.width - 24, 60)];
    self.colorOut.numberOfLines = 0;
    self.colorOut.font = [UIFont systemFontOfSize:10];
    self.colorOut.textColor = [UIColor yellowColor];
    self.colorOut.text = @"点「取色」后这里显示 期望 vs 实测";
    [self.view addSubview:self.colorOut];

    self.resultList = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 128, b.size.width - 24, 100)];
    self.resultList.numberOfLines = 0;
    self.resultList.font = [UIFont systemFontOfSize:9];
    self.resultList.textColor = [UIColor colorWithWhite:0.8 alpha:1];
    [self.view addSubview:self.resultList];

    NSArray *titles = @[@"试下一个", @"自动遍历", @"取色", @"重置", @"隐藏/显示"];
    SEL sels[5] = {@selector(onNext:), @selector(onAuto:), @selector(onColor:),
                   @selector(onReset:), @selector(onHide:)};
    CGFloat bw = (b.size.width - 24) / 5.0;
    for (int i = 0; i < 5; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(12 + i * bw, b.size.height - 70, bw - 4, 44);
        btn.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
        btn.titleLabel.font = [UIFont systemFontOfSize:11];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn setTitle:titles[i] forState:UIControlStateNormal];
        [btn addTarget:self action:sels[i] forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:btn];
    }

    // 崩溃断点续跑
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    self.idx = (int)[ud integerForKey:K_IDX];
    NSInteger trying = [ud integerForKey:K_TRY];
    if (trying > 0) {
        // 上次写到 trying 却没清掉 = 崩在这个组合上
        NSMutableArray *r = [[ud arrayForKey:K_RES] mutableCopy] ?: [NSMutableArray array];
        while ((int)r.count <= (int)trying - 1) [r addObject:@"?"];
        [r replaceObjectAtIndex:(NSUInteger)(trying - 1) withObject:@"CRASH"];
        [ud setObject:r forKey:K_RES];
        [ud removeObjectForKey:K_TRY];
        [ud synchronize];
    }
    [self refresh];
}

- (void)refresh {
    int form = self.idx % 3, set = (self.idx / 3) % 3, mi = (self.idx / 6) % 3;
    self.head.text = [NSString stringWithFormat:
        @"HLProbe %s\n符号:%@\nclient:%@\n下一个 #%d/%d  form=%@ field=%@ mask=%@",
        __DATE__, gSymReport, self.clientName ?: @"未选",
        self.idx, HL_TOTAL, HLFormName(form), HLSetName(set), HLMaskName(mi)];
    [self.target setTitle:[NSString stringWithFormat:@"TARGET\n手动点=%d\n合成到=%d",
                           self.manualN, self.synthN]
                 forState:UIControlStateNormal];
    NSArray *r = [[NSUserDefaults standardUserDefaults] arrayForKey:K_RES] ?: @[];
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < (int)r.count; i++) {
        [s appendFormat:@"#%d(%@/%@/%@)=%@  ", i, HLFormName(i % 3),
         HLSetName((i / 3) % 3), HLMaskName((i / 6) % 3), r[i]];
    }
    self.resultList.text = r.count ? s : @"（还没试过任何组合）";
}

- (void)onManual:(id)sender { self.manualN++; [self refresh]; }

- (void)onNext:(id)sender {
    if (self.idx >= HL_TOTAL) { self.head.text = @"18 种已试完，见下方列表"; return; }
    [self runCombo:self.idx];
}

- (void)onAuto:(id)sender {
    if (self.autoRunning) { self.autoRunning = NO; return; }
    self.autoRunning = YES;
    [self autoStep];
}

- (void)autoStep {
    if (!self.autoRunning || self.idx >= HL_TOTAL) { self.autoRunning = NO; [self refresh]; return; }
    [self runCombo:self.idx];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self autoStep]; });
}

- (void)runCombo:(int)k {
    int form = k % 3, set = (k / 3) % 3, mi = (k / 6) % 3;
    int before = self.synthN;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setInteger:k + 1 forKey:K_TRY];   // 崩在这里 → 下次启动判定为 CRASH
    [ud synchronize];

    @try {
        IOHIDEventRef ev = NULL;
        for (int ph = 0; ph < 3; ph++) {
            ev = HLMakeEvent(form, set, mi, 0.5, 0.5, ph);
            if (!ev) continue;
            if (gSetSender) gSetSender(ev, 0x4001ULL);
            if (gDispatch && gProbeClient) gDispatch(gProbeClient, ev);
            usleep(120 * 1000);
        }
    } @catch (NSException *e) { /* 崩在 HID 层的话 ObjC 异常也兜不住，靠 K_TRY 断点 */ }

    // 等事件路由回来再判定
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSMutableArray *r = [[ud arrayForKey:K_RES] mutableCopy] ?: [NSMutableArray array];
        while ((int)r.count <= k) [r addObject:@"?"];
        [r replaceObjectAtIndex:(NSUInteger)k
                     withObject:(self.synthN > before ? @"OK" : @"NO-EFFECT")];
        [ud setObject:r forKey:K_RES];
        [ud setInteger:k + 1 forKey:K_IDX];
        [ud removeObjectForKey:K_TRY];   // 正常走完，清掉崩溃标记
        [ud synchronize];
        self.idx = k + 1;
        [self refresh];
    });
}

- (void)onColor:(id)sender {
    UIImage *img = HLSnapshot(self.view.window ?: [UIApplication sharedApplication].keyWindow);
    NSArray *expect = @[@"(255,0,0)", @"(0,255,0)", @"(0,0,255)"];
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 3; i++) {
        UIView *v = self.swatches[i];
        CGPoint c = [self.view convertPoint:CGPointMake(v.bounds.size.width / 2,
                                                        v.bounds.size.height / 2)
                                   fromView:v];
        [s appendFormat:@"#%d 期望%@ 实测%@\n", i, expect[i], HLReadPixel(img, c)];
    }
    self.colorOut.text = s;
}

- (void)onReset:(id)sender {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:K_RES]; [ud removeObjectForKey:K_IDX]; [ud removeObjectForKey:K_TRY];
    [ud synchronize];
    self.idx = 0; self.manualN = 0; self.synthN = 0;
    [self refresh];
}

- (void)onHide:(id)sender {
    UIWindow *w = self.view.window;
    w.hidden = !w.hidden;
}

// 合成触摸到达时，UIKit 会正常路由 → 命中中心按钮 → 这里 +1
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesBegan:touches withEvent:event];
}

@end

#pragma mark - E. 注入入口

// ★ 关键修复：窗口必须被全局强引用。原版用 block 内局部变量 UIWindow *w，
//   block 跑完即被 ARC 回收 → 注入后界面「不显示」。改用 static 全局攥住，
//   与 AgentInject2 的 gFloatWindow（static UIWindow *）同一套路。
static UIWindow *gProbeWin = nil;

__attribute__((constructor))
static void HLProbeEntry(void) {
    HLLoadHID();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            if (gClientCreate)      { gProbeClient = gClientCreate(kCFAllocatorDefault); }
            if (!gProbeClient && gClientSimple) { gProbeClient = gClientSimple(kCFAllocatorDefault, 0); }
            if (!gProbeClient && gClientType)   { gProbeClient = gClientType(kCFAllocatorDefault, 0, NULL); }

            // iOS 13+ 必须用 initWithWindowScene: 关联到场景，否则窗口挂不上、不显示。
            UIWindowScene *scn = nil;
            if (@available(iOS 13.0, *)) {
                scn = [UIApplication sharedApplication].keyWindow.windowScene;
            }
            gProbeWin = scn ? [[UIWindow alloc] initWithWindowScene:scn]
                            : [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            HLProbeVC *vc = [HLProbeVC new];
            vc.clientName = gProbeClient ? @"已取得" : @"❌全部失败";
            gProbeWin.rootViewController = vc;
            gProbeWin.windowLevel = UIWindowLevelAlert + 1000;
            gProbeWin.backgroundColor = [UIColor clearColor];
            gProbeWin.hidden = NO;
            NSLog(@"[HLProbe] UI 已建立 client=%p sym=%@ win=%p", gProbeClient, gSymReport, gProbeWin);
        } @catch (NSException *e) {
            NSLog(@"[HLProbe] 建 UI 失败 %@", e);
        }
    });
}
