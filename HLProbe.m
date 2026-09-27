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
//  组合编号 k ∈ [0,27)：form = k%3, fieldset = (k/3)%3, mask = (k/9)%3
//
//  v7 新增（验证「老贝贝识字」链路能否搬过来）：
//      · 识字：截目标 App 主窗口 → Vision VNRecognizeTextRequest → 条数/耗时/前 3 条文本+坐标
//      · 坐标自检：截探针自己的窗口，OCR 找已知位置的 "手动点=N" 文本，
//        用「不翻转 y」和「y=1-y-h 翻转」两种公式分别回算 UIKit 坐标，
//        与按钮真实 frame 比误差 —— 一次注入就把 Vision 坐标换算钉死。
//      · 黑图判定：截图后算平均亮度与非黑像素占比，直接回答「截图是不是息屏黑图」。
//
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <Vision/Vision.h>
#import <dlfcn.h>
#import <mach/mach_time.h>
#import <unistd.h>

#pragma mark - A. IOKit 桥（dlopen + dlsym，与已验证可用的 AgentInject2 同款写法）

static void *gProbeClient = NULL;   // 选中的 HID client（必须定义在使用点之前）

// ★ 探针窗口：必须全局强引用 + iOS13+ initWithWindowScene:，否则注入后不显示（v6 修的坑）
static UIWindow *gProbeWin = nil;

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

#pragma mark - F. Vision OCR（老贝贝识字链路复现 + 坐标换算验证）

static NSString *gLangSupport = @"未查询";
static NSString *gOCRVerdict = @"待跑";

// 平均亮度 + 非黑像素占比：一眼分辨「截图正常」还是「息屏黑图」。
// 这是本项目当前的头号悬案（我们回传的 PNG 经常是黑的），必须当场可判。
static NSString *HLImageStats(UIImage *img) {
    if (!img) return @"no-img";
    CGImageRef cg = img.CGImage;
    if (!cg)   return @"no-cg";
    const size_t S = 16;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, S, S, 8, S * 4, cs,
        (CGBitmapInfo)(kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big));
    CGColorSpaceRelease(cs);
    if (!ctx) return @"no-ctx";
    CGContextSetInterpolationQuality(ctx, kCGInterpolationLow);
    CGContextDrawImage(ctx, CGRectMake(0, 0, S, S), cg);
    const uint8_t *d = (const uint8_t *)CGBitmapContextGetData(ctx);
    long sum = 0, nonBlack = 0;
    for (size_t i = 0; i < S * S; i++) {
        long lum = (d[i*4] * 299 + d[i*4+1] * 587 + d[i*4+2] * 114) / 1000;
        sum += lum;
        if (lum > 8) nonBlack++;
    }
    CGContextRelease(ctx);
    CGFloat avg = (CGFloat)sum / (CGFloat)(S * S);
    CGFloat pct = (CGFloat)nonBlack * 100.f / (CGFloat)(S * S);
    return [NSString stringWithFormat:@"亮度%.0f/255 非黑%.0f%%%@",
            avg, pct, (avg < 6.f ? @" ⚠️黑图(疑似息屏)" : @"")];
}

// 返回 @{text, x, y, w, h} 数组。x/y/w/h 是 Vision 归一化坐标（原点左下）。
static NSArray<NSDictionary *> *HLRecognize(UIImage *img, double *costMs) {
    NSMutableArray *out = [NSMutableArray array];
    if (!img || !img.CGImage) return out;
    if (@available(iOS 13.0, *)) {
        // 运行时问系统：这台机器上 accurate 档到底支持哪些语言（中文在不在里面）
        NSError *le = nil;
        NSArray<NSString *> *langs =
            [VNRecognizeTextRequest supportedRecognitionLanguagesForTextRecognitionLevel:
                VNRequestTextRecognitionLevelAccurate
                revision:VNRecognizeTextRequestRevision1 error:&le];
        gLangSupport = langs
            ? [NSString stringWithFormat:@"%lu种%@ · %@",
                (unsigned long)langs.count,
                ([langs containsObject:@"zh-Hans"] ? @" ✅含zh-Hans" : @" ❌无zh-Hans"),
                [[langs subarrayWithRange:NSMakeRange(0, MIN((NSUInteger)6, langs.count))]
                    componentsJoinedByString:@","]]
            : [NSString stringWithFormat:@"查询失败 %@", le.localizedDescription];

        VNImageRequestHandler *hd =
            [[VNImageRequestHandler alloc] initWithCGImage:img.CGImage options:@{}];
        VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
        req.recognitionLevel      = VNRequestTextRecognitionLevelAccurate;  // 中文只有 accurate 支持
        req.recognitionLanguages  = @[@"zh-Hans", @"en-US"];
        req.usesLanguageCorrection = NO;   // 官方明示中文不支持 correction，开了反而改错字

        NSDate *t0 = [NSDate date];
        NSError *err = nil;
        BOOL ok = [hd performRequests:@[req] error:&err];
        if (costMs) *costMs = -[t0 timeIntervalSinceNow] * 1000.0;
        if (!ok) { gOCRVerdict = [NSString stringWithFormat:@"OCR 失败: %@", err.localizedDescription]; return out; }

        for (VNObservation *o in req.results) {
            if (![o isKindOfClass:[VNRecognizedTextObservation class]]) continue;
            VNRecognizedTextObservation *ob = (VNRecognizedTextObservation *)o;
            VNRecognizedText *top = [[ob topCandidates:1] firstObject];
            if (!top) continue;
            CGRect bb = ob.boundingBox;   // 归一化，原点左下
            [out addObject:@{@"text": top.string,
                             @"x": @(bb.origin.x), @"y": @(bb.origin.y),
                             @"w": @(bb.size.width), @"h": @(bb.size.height)}];
        }
        // 视觉顺序：从上到下、从左到右（Vision 的 y 原点在左下，所以按 y 降序）
        [out sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"y" ascending:NO],
                                    [NSSortDescriptor sortDescriptorWithKey:@"x" ascending:YES]]];
    } else {
        gOCRVerdict = @"iOS<13 无 Vision OCR";
    }
    return out;
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
@property (nonatomic, strong) UILabel     *ocrOut;
@property (nonatomic, strong) UILabel     *ocrHead;
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

    CGFloat W = b.size.width;

    self.head = [[UILabel alloc] initWithFrame:CGRectMake(8, 44, W - 16, 60)];
    self.head.numberOfLines = 0;
    self.head.font = [UIFont systemFontOfSize:11];
    self.head.textColor = [UIColor whiteColor];
    [self.view addSubview:self.head];

    self.ocrHead = [[UILabel alloc] initWithFrame:CGRectMake(8, 106, W - 16, 46)];
    self.ocrHead.numberOfLines = 0;
    self.ocrHead.font = [UIFont systemFontOfSize:9.5];
    self.ocrHead.textColor = [UIColor cyanColor];
    self.ocrHead.text = @"点「识字」跑 Vision OCR（端侧，不联网）";
    [self.view addSubview:self.ocrHead];

    // ★ 必须在屏幕正中央：合成触摸固定打中心点
    self.target = [UIButton buttonWithType:UIButtonTypeSystem];
    self.target.frame = CGRectMake(0, 0, 240, 120);
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
    CGFloat y = b.size.height / 2 + 70;      // 紧贴 TARGET 按钮下方，按钮本身绝不能挪
    NSMutableArray *sw = [NSMutableArray array];
    for (int i = 0; i < 3; i++) {
        UIView *v = [[UIView alloc] initWithFrame:CGRectMake(20 + i * 90, y, 80, 42)];
        v.backgroundColor = cols[i];
        v.tag = 100 + i;
        [self.view addSubview:v];
        [sw addObject:v];
    }
    self.swatches = sw;

    self.colorOut = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 44, W - 24, 36)];
    self.colorOut.numberOfLines = 0;
    self.colorOut.font = [UIFont systemFontOfSize:9.5];
    self.colorOut.textColor = [UIColor yellowColor];
    self.colorOut.text = @"点「取色」后这里显示 期望 vs 实测";
    [self.view addSubview:self.colorOut];

    self.resultList = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 82, W - 24, 64)];
    self.resultList.numberOfLines = 0;
    self.resultList.font = [UIFont systemFontOfSize:9];
    self.resultList.textColor = [UIColor colorWithWhite:0.8 alpha:1];
    [self.view addSubview:self.resultList];

    self.ocrOut = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 148, W - 24, 84)];
    self.ocrOut.numberOfLines = 0;
    self.ocrOut.font = [UIFont systemFontOfSize:8.5];
    self.ocrOut.textColor = [UIColor greenColor];
    self.ocrOut.text = @"识字结果会显示在这里：条数 / 耗时 / 前 3 条文本与归一化坐标。";
    [self.view addSubview:self.ocrOut];

    NSArray *t1 = @[@"识字", @"坐标自检", @"取色", @"试下一个"];
    SEL s1[4] = {@selector(onOCR:), @selector(onOCRSelf:), @selector(onColor:), @selector(onNext:)};
    NSArray *t2 = @[@"自动遍历", @"重置", @"隐藏/显示"];
    SEL s2[3] = {@selector(onAuto:), @selector(onReset:), @selector(onHide:)};
    CGFloat bw1 = (W - 24) / 4.0, bw2 = (W - 24) / 3.0;
    for (int i = 0; i < 4; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(12 + i * bw1, y + 240, bw1 - 4, 36);
        btn.backgroundColor = (i == 0) ? [UIColor colorWithRed:0.1 green:0.45 blue:0.3 alpha:1]
                                       : [UIColor colorWithWhite:0.25 alpha:1];
        btn.titleLabel.font = [UIFont systemFontOfSize:11];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn setTitle:t1[i] forState:UIControlStateNormal];
        [btn addTarget:self action:s1[i] forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:btn];
    }
    for (int i = 0; i < 3; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(12 + i * bw2, y + 282, bw2 - 4, 36);
        btn.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
        btn.titleLabel.font = [UIFont systemFontOfSize:11];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn setTitle:t2[i] forState:UIControlStateNormal];
        [btn addTarget:self action:s2[i] forControlEvents:UIControlEventTouchUpInside];
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
    int form = self.idx % 3, set = (self.idx / 3) % 3, mi = (self.idx / 9) % 3;
    self.head.text = [NSString stringWithFormat:
        @"HLProbe v7 %s\n符号:%@\nclient:%@\n下一个 #%d/%d  form=%@ field=%@ mask=%@",
        __DATE__, gSymReport, self.clientName ?: @"未选",
        self.idx, HL_TOTAL, HLFormName(form), HLSetName(set), HLMaskName(mi)];
    [self.target setTitle:[NSString stringWithFormat:@"TARGET\n手动点=%d\n合成到=%d",
                           self.manualN, self.synthN]
                 forState:UIControlStateNormal];
    NSArray *r = [[NSUserDefaults standardUserDefaults] arrayForKey:K_RES] ?: @[];
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < (int)r.count; i++) {
        [s appendFormat:@"#%d(%@/%@/%@)=%@  ", i, HLFormName(i % 3),
         HLSetName((i / 3) % 3), HLMaskName((i / 9) % 3), r[i]];
    }
    self.resultList.text = r.count ? s : @"（还没试过任何组合）";
}

- (void)onManual:(id)sender { self.manualN++; [self refresh]; }

- (void)onNext:(id)sender {
    if (self.idx >= HL_TOTAL) { self.head.text = @"27 种已试完，见下方列表"; return; }
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
    // v7 修正：v6 用 (k/6)%3 取 mask，与 (k/3)%3 不独立，27 个编号只覆盖 18 个组合、
    // 漏掉 9 个（set0/mi2、set1/mi1、set2/mi0 全没试到）。改成 /9 才是完整 3×3×3。
    int form = k % 3, set = (k / 3) % 3, mi = (k / 9) % 3;
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

#pragma mark - OCR 动作

// 找「目标 App 的主窗口」：探针自己的窗口是 UIWindowLevelAlert+1000，必须排除，
// 否则截下来全是探针自己的黑底，OCR 出来只有我们自己的字（假成功）。
static UIWindow *HLAppWindow(void) {
    UIWindow *best = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w == gProbeWin || w.hidden) continue;
        if (w.windowLevel >= UIWindowLevelAlert) continue;
        if (w.rootViewController) { best = w; break; }
    }
    return best ?: [UIApplication sharedApplication].keyWindow;
}

- (void)onOCR:(id)sender {
    self.ocrOut.text = @"识字中…";
    UIWindow *appWin = HLAppWindow();
    UIImage *img = HLSnapshot(appWin);          // 截图必须在主线程做
    NSString *stats = HLImageStats(img);        // 先判是不是黑图，黑图 OCR 必然空
    __block NSString *winDesc = [NSString stringWithFormat:@"win=%@ %@",
        NSStringFromClass([appWin.rootViewController class]),
        NSStringFromCGSize(appWin.bounds.size)];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        double cost = 0;
        NSArray *res = HLRecognize(img, &cost);
        NSString *lang = gLangSupport, *verdict = gOCRVerdict;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSMutableString *s = [NSMutableString string];
            [s appendFormat:@"条数=%lu 耗时=%.0fms  %@\n", (unsigned long)res.count, cost, stats];
            for (int i = 0; i < (int)MIN((NSUInteger)3, res.count); i++) {
                NSDictionary *d = res[i];
                [s appendFormat:@"%d「%@」n(%.2f,%.2f %.2fx%.2f)\n", i, d[@"text"],
                 [d[@"x"] doubleValue], [d[@"y"] doubleValue],
                 [d[@"w"] doubleValue], [d[@"h"] doubleValue]];
            }
            if (!res.count) [s appendFormat:@"0 条 — %@", verdict];
            self.ocrOut.text = s;
            self.ocrHead.text = [NSString stringWithFormat:@"支持语言: %@\n截图: %@  %@",
                                 lang, stats, winDesc];
        });
    });
}

// 坐标自检：拿「已知位置的文字」反过来验证 Vision → UIKit 的 y 换算到底哪个对。
// 锚点：head 里的 "HLProbe"（实际 y=44）与 TARGET 按钮里的"手动点"（实际 y=按钮顶）。
- (void)onOCRSelf:(id)sender {
    self.ocrOut.text = @"坐标自检中…（截的是探针自己的窗口）";
    UIImage *img = HLSnapshot(gProbeWin ?: self.view.window);
    CGRect tf = self.target.frame, hf = self.head.frame;
    CGFloat H = [UIScreen mainScreen].bounds.size.height;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        double cost = 0;
        NSArray *res = HLRecognize(img, &cost);
        NSArray *anchors = @[
            @{@"key": @"HLProbe", @"y": @(hf.origin.y)},
            @{@"key": @"手动点",  @"y": @(tf.origin.y)},
        ];
        NSMutableString *s = [NSMutableString string];
        [s appendFormat:@"自检 命中%lu条 耗时%.0fms\n", (unsigned long)res.count, cost];
        for (NSDictionary *a in anchors) {
            NSString *key = a[@"key"];
            CGFloat expect = [a[@"y"] doubleValue];
            NSDictionary *hit = nil;
            for (NSDictionary *d in res) {
                if ([[d[@"text"] description] rangeOfString:key].location != NSNotFound) { hit = d; break; }
            }
            if (!hit) { [s appendFormat:@"锚点「%@」未命中\n", key]; continue; }
            double vy = [hit[@"y"] doubleValue], vh = [hit[@"h"] doubleValue];
            CGFloat yA = (CGFloat)(vy * H);                 // 公式A：不翻转
            CGFloat yB = (CGFloat)((1.0 - vy - vh) * H);    // 公式B：y_ui = 1 - y_vn - h
            CGFloat dA = fabs(yA - expect), dB = fabs(yB - expect);
            [s appendFormat:@"「%@」实际顶=%.0f | A不翻转=%.0f(Δ%.0f) B翻转=%.0f(Δ%.0f) → %@\n",
             key, expect, yA, dA, yB, dB, (dB < dA ? @"B✅(y=1-y-h)" : @"A✅(不翻转)")];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ self.ocrOut.text = s; });
    });
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
