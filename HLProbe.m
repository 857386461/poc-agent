//
//  HLProbe.m —— 老贝贝底座「运行时探针」dylib
//
//  v9 主题：一键「写日志」。
//    用户看不懂屏上那些数字没关系 —— 点一下「写日志」，探针把所有能测到的东西
//    自动跑一遍（截图统计 / 取色 / Vision 支持语言矩阵 / 3 组 OCR 实测 /
//    坐标换算自检 / 27 组触摸合成），写成**一份自包含的日志**：
//      (1) 写进 App 沙盒多个候选路径（供 Filza 之类手动取）
//      (2) 直接 POST 回项目公网中继（云端可立即读回，用户零操作）
//    云端只用看这份日志就能下结论，不再需要用户读屏 / 截图。
//
//  同时修掉 v6/v7/v8 的**真 bug**（这条最要紧）：
//    v6/v7 判定合成触摸是否到达，比的是 self.synthN ——
//    但 synthN 除了 onReset 清零外**从不自增**，于是 27 组永远判 NO-EFFECT。
//    真正被合成触摸顶到的按钮走的是 onManual: → 累加的是 manualN。
//    → 「27 组合全部 NO-EFFECT」是**假结论**，v9 改成比对 manualN 的增量。
//
//  组合编号 k ∈ [0,27)：form = k%3, fieldset = (k/3)%3, mask = (k/9)%3
//    （v6 曾用 (k/6)%3，与 (k/3)%3 不独立，27 个编号只覆盖 18 组，v7 已修）
//
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <Vision/Vision.h>
#import <dlfcn.h>
#import <mach/mach_time.h>
#import <unistd.h>
#import <stdarg.h>

#pragma mark - A. IOKit 桥（dlopen + dlsym，与已验证可用的 AgentInject2 同款写法）

static void *gProbeClient = NULL;   // 选中的 HID client

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

#pragma mark - B. 三套字段常量（真机已验证 vs 规格书 §2.4 vs 老贝贝报告）

#define HL_SET_OURS 0   // AgentInject2 真机跑通用：X=0x0B0000
#define HL_SET_SPEC 1   // 规格书 §2.4 给的：X=0x0B0030
#define HL_SET_BEI  2   // 老贝贝逆向报告 §4.3：X=0x0B0014（三套常量之一，别照抄！）

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

#pragma mark - 日志基础设施（v9）

static NSMutableString *gLog = nil;          // 当前正在攒的日志
static NSString *gBuildTag = @"v9";

static void HLLogAdd(NSString *fmt, ...) {
    if (!gLog) gLog = [NSMutableString string];
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gLog appendString:s];
    [gLog appendString:@"\n"];
    NSLog(@"[HLProbe] %@", s);
}

static NSString *HLEnvLine(void) {
    UIDevice *d = [UIDevice currentDevice];
    UIScreen *sc = [UIScreen mainScreen];
    return [NSString stringWithFormat:
            @"设备=%@ iOS=%@ 屏幕=%.0fx%.0f @%.0fx 首选语言=%@",
            d.model, d.systemVersion,
            sc.bounds.size.width, sc.bounds.size.height, sc.scale,
            [[NSLocale preferredLanguages] firstObject] ?: @"?"];
}

#pragma mark - C. 截图 / 取色（规格书 §3：drawViewHierarchy + CoreGraphics 读像素）

static UIImage *HLSnapshot(UIWindow *win) {
    if (!win) return nil;
    UIGraphicsBeginImageContextWithOptions(win.bounds.size, NO, [UIScreen mainScreen].scale);
    @try { [win drawViewHierarchyInRect:win.bounds afterScreenUpdates:NO]; }
    @catch (NSException *e) { UIGraphicsEndImageContext(); return nil; }
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return img;
}

// 返回 "RGBA(r,g,b) BGRA(r,g,b)"
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

// 平均亮度 + 非黑像素占比：一眼分辨「截图正常」还是「息屏黑图」。
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

// 逐 revision × level 问系统：这台机器上到底支持哪些语言（中文在不在）。
// v7 只用 Revision1 问、却用默认 revision 跑 —— 问的和用的不是同一个，结论不可信。
static NSString *HLLangMatrix(void) {
    if (@available(iOS 13.0, *)) {
        NSMutableString *s = [NSMutableString string];
        NSArray *levels = @[@(VNRequestTextRecognitionLevelFast), @(VNRequestTextRecognitionLevelAccurate)];
        NSArray *names  = @[@"fast    ", @"accurate"];
        for (int li = 0; li < 2; li++) {
            for (int rev = 1; rev <= 4; rev++) {
                NSError *e = nil;
                NSArray<NSString *> *l =
                    [VNRecognizeTextRequest supportedRecognitionLanguagesForTextRecognitionLevel:[levels[li] integerValue]
                                                                                        revision:rev
                                                                                           error:&e];
                if (l) {
                    [s appendFormat:@"  %@ rev%d: %lu种 zh-Hans=%@ | %@\n",
                     names[li], rev, (unsigned long)l.count,
                     ([l containsObject:@"zh-Hans"] ? @"YES" : @"no"),
                     [l componentsJoinedByString:@","]];
                } else {
                    [s appendFormat:@"  %@ rev%d: 查询失败(%@)\n", names[li], rev, e.localizedDescription ?: @"?"];
                }
            }
        }
        return s;
    }
    return @"  iOS<13 无 Vision\n";
}

// 跑一次 OCR。返回 @{count,cost,items,err,rev,level}
static NSDictionary *HLRecognizeEx(UIImage *img, NSInteger level, NSArray *langs,
                                   BOOL correction, NSInteger revision) {
    if (!img || !img.CGImage) return @{@"err": @"no-img", @"count": @0, @"items": @[]};
    if (@available(iOS 13.0, *)) {
        VNImageRequestHandler *hd =
            [[VNImageRequestHandler alloc] initWithCGImage:img.CGImage options:@{}];
        VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
        req.recognitionLevel = level;
        if (langs) req.recognitionLanguages = langs;
        req.usesLanguageCorrection = correction;
        if (revision > 0) req.revision = revision;

        NSDate *t0 = [NSDate date];
        NSError *err = nil;
        BOOL ok = [hd performRequests:@[req] error:&err];
        double cost = -[t0 timeIntervalSinceNow] * 1000.0;
        if (!ok) {
            return @{@"err": err.localizedDescription ?: @"?",
                     @"cost": @(cost), @"rev": @(req.revision), @"count": @0, @"items": @[]};
        }
        NSMutableArray *items = [NSMutableArray array];
        for (VNObservation *o in req.results) {
            if (![o isKindOfClass:[VNRecognizedTextObservation class]]) continue;
            VNRecognizedTextObservation *ob = (VNRecognizedTextObservation *)o;
            VNRecognizedText *top = [[ob topCandidates:1] firstObject];
            if (!top) continue;
            CGRect bb = ob.boundingBox;   // 归一化，原点左下
            [items addObject:@{@"text": top.string, @"conf": @(top.confidence),
                               @"x": @(bb.origin.x), @"y": @(bb.origin.y),
                               @"w": @(bb.size.width), @"h": @(bb.size.height)}];
        }
        [items sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"y" ascending:NO],
                                      [NSSortDescriptor sortDescriptorWithKey:@"x" ascending:YES]]];
        return @{@"count": @(items.count), @"cost": @(cost), @"items": items,
                 @"rev": @(req.revision), @"level": @(level)};
    }
    return @{@"err": @"iOS<13", @"count": @0, @"items": @[]};
}

#pragma mark - 落盘 / 上传（v9）

// 往多个候选路径写同一份日志；返回 @{ok:[成功路径], tries:[每行结果]}
static NSDictionary *HLWriteLogFile(NSString *content) {
    NSMutableArray *paths = [NSMutableArray array];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs.length) [paths addObject:[docs stringByAppendingPathComponent:@"HLProbe.log"]];
    [paths addObject:[NSTemporaryDirectory() stringByAppendingPathComponent:@"HLProbe.log"]];
    [paths addObject:@"/var/mobile/Documents/HLProbe.log"];   // 若越狱/有权限则最好找
    [paths addObject:@"/var/mobile/Media/HLProbe.log"];
    NSMutableArray *ok = [NSMutableArray array], *tries = [NSMutableArray array];
    for (NSString *p in paths) {
        NSError *e = nil;
        BOOL w = [content writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&e];
        if (w) { [ok addObject:p]; [tries addObject:[@"✅ " stringByAppendingString:p]]; }
        else   { [tries addObject:[NSString stringWithFormat:@"❌ %@ (%@)", p, e.localizedDescription ?: @"?"]]; }
    }
    return @{@"ok": ok, @"tries": tries};
}

// 把日志 POST 回项目公网中继（AgentInject2 用的同一台）。
// 成功后云端 GET /report?dev=hlprobe 就能直接读到，用户无需下载任何文件。
static void HLUploadLog(NSString *content, void (^done)(NSString *)) {
    NSURL *u = [NSURL URLWithString:@"https://aa0c466b5cdb559bb.app.workbuddy.host/report"];
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    r.HTTPMethod = @"POST";
    [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    r.timeoutInterval = 25;
    NSDictionary *body = @{@"dev": @"hlprobe", @"op": @"log",
                           @"ts": @([[NSDate date] timeIntervalSince1970]),
                           @"len": @(content.length),
                           @"data": @{@"log": content}};
    r.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSURLSessionDataTask *t =
        [[NSURLSession sharedSession] dataTaskWithRequest:r
            completionHandler:^(NSData *d, NSURLResponse *resp, NSError *e) {
                NSString *res;
                if (e) {
                    res = [NSString stringWithFormat:@"FAIL %@", e.localizedDescription];
                } else {
                    NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
                    res = [NSString stringWithFormat:@"HTTP %ld %@", (long)code,
                           [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @""];
                }
                dispatch_async(dispatch_get_main_queue(), ^{ if (done) done(res); });
            }];
    [t resume];
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
@property (nonatomic, strong) UITextView  *ocrOut;      // v9 改可滚动，便于截图备份
@property (nonatomic, strong) UILabel     *ocrHead;
@property (nonatomic, assign) int          manualN;     // 手动/任意 UIKit 触摸命中 TARGET 的次数
@property (nonatomic, assign) int          synthN;      // 「遍历期间」命中次数（合成触摸的判据）
@property (nonatomic, assign) int          idx;
@property (nonatomic, assign) BOOL         autoRunning;
@property (nonatomic, assign) BOOL         logBusy;
@property (nonatomic, strong) NSString    *clientName;
@end

@implementation HLProbeVC

- (void)viewDidLoad {
    [super viewDidLoad];
    CGRect b = [UIScreen mainScreen].bounds;
    self.view.backgroundColor = [UIColor colorWithWhite:0.06 alpha:0.94];

    CGFloat W = b.size.width, H = b.size.height;

    self.head = [[UILabel alloc] initWithFrame:CGRectMake(8, 44, W - 16, 62)];
    self.head.numberOfLines = 0;
    self.head.font = [UIFont systemFontOfSize:11];
    self.head.textColor = [UIColor whiteColor];
    [self.view addSubview:self.head];

    self.ocrHead = [[UILabel alloc] initWithFrame:CGRectMake(8, 108, W - 16, 48)];
    self.ocrHead.numberOfLines = 0;
    self.ocrHead.font = [UIFont systemFontOfSize:9.5];
    self.ocrHead.textColor = [UIColor cyanColor];
    self.ocrHead.text = @"点「写日志」→ 自动跑完并写文件+上传，云端直接读";
    [self.view addSubview:self.ocrHead];

    // ★ 必须在屏幕正中央：合成触摸固定打中心点
    self.target = [UIButton buttonWithType:UIButtonTypeSystem];
    self.target.frame = CGRectMake(0, 0, 240, 120);
    self.target.center = CGPointMake(W / 2, H / 2);
    self.target.backgroundColor = [UIColor colorWithRed:0.13 green:0.35 blue:0.55 alpha:1];
    self.target.layer.cornerRadius = 12;
    self.target.titleLabel.numberOfLines = 0;
    self.target.titleLabel.font = [UIFont systemFontOfSize:15];
    [self.target setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self.target addTarget:self action:@selector(onManual:)
          forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.target];

    // 三块纯色（紧贴 TARGET 下方，TARGET 本身绝不能挪）
    NSArray *cols = @[[UIColor redColor], [UIColor greenColor], [UIColor blueColor]];
    CGFloat y = H / 2 + 70;
    NSMutableArray *sw = [NSMutableArray array];
    for (int i = 0; i < 3; i++) {
        UIView *v = [[UIView alloc] initWithFrame:CGRectMake(20 + i * 90, y, 80, 42)];
        v.backgroundColor = cols[i];
        v.tag = 100 + i;
        [self.view addSubview:v];
        [sw addObject:v];
    }
    self.swatches = sw;

    self.colorOut = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 44, W - 24, 34)];
    self.colorOut.numberOfLines = 0;
    self.colorOut.font = [UIFont systemFontOfSize:9.5];
    self.colorOut.textColor = [UIColor yellowColor];
    self.colorOut.text = @"点「取色」后这里显示 期望 vs 实测";
    [self.view addSubview:self.colorOut];

    self.resultList = [[UILabel alloc] initWithFrame:CGRectMake(12, y + 78, W - 24, 56)];
    self.resultList.numberOfLines = 0;
    self.resultList.font = [UIFont systemFontOfSize:9];
    self.resultList.textColor = [UIColor colorWithWhite:0.8 alpha:1];
    [self.view addSubview:self.resultList];

    self.ocrOut = [[UITextView alloc] initWithFrame:CGRectMake(12, y + 136, W - 24, 96)];
    self.ocrOut.editable = NO;
    self.ocrOut.scrollEnabled = YES;
    self.ocrOut.backgroundColor = [UIColor clearColor];
    self.ocrOut.font = [UIFont systemFontOfSize:8.5];
    self.ocrOut.textColor = [UIColor greenColor];
    self.ocrOut.text = @"日志 / OCR 结果会显示在这里（可上下滚动）。";
    [self.view addSubview:self.ocrOut];

    NSArray *t1 = @[@"写日志", @"识字", @"坐标自检", @"取色"];
    SEL s1[4] = {@selector(onWriteLog:), @selector(onOCR:), @selector(onOCRSelf:), @selector(onColor:)};
    NSArray *t2 = @[@"自动遍历", @"试下一个", @"重置", @"隐藏/显示"];
    SEL s2[4] = {@selector(onAuto:), @selector(onNext:), @selector(onReset:), @selector(onHide:)};
    CGFloat bw1 = (W - 24) / 4.0, bw2 = (W - 24) / 4.0;
    for (int i = 0; i < 4; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(12 + i * bw1, y + 238, bw1 - 4, 36);
        btn.backgroundColor = (i == 0) ? [UIColor colorWithRed:0.10 green:0.50 blue:0.32 alpha:1]
                                       : [UIColor colorWithWhite:0.25 alpha:1];
        btn.titleLabel.font = [UIFont systemFontOfSize:11];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn setTitle:t1[i] forState:UIControlStateNormal];
        [btn addTarget:self action:s1[i] forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:btn];
    }
    for (int i = 0; i < 4; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(12 + i * bw2, y + 278, bw2 - 4, 36);
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
        @"HLProbe %@ %s\n符号:%@  client:%@\n下一个 #%d/%d  form=%@ field=%@ mask=%@",
        gBuildTag, __DATE__, gSymReport, self.clientName ?: @"未选",
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

// 合成一组触摸。判据改为 manualN 的增量（v6/v7 用 never-increasing 的 synthN，结论无效）
- (void)runCombo:(int)k {
    int form = k % 3, set = (k / 3) % 3, mi = (k / 9) % 3;
    int before = self.manualN;
    int created = 0;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setInteger:k + 1 forKey:K_TRY];   // 崩在这里 → 下次启动判定为 CRASH
    [ud synchronize];

    @try {
        for (int ph = 0; ph < 3; ph++) {
            IOHIDEventRef ev = HLMakeEvent(form, set, mi, 0.5, 0.5, ph);
            if (!ev) continue;
            created++;
            if (gSetSender) gSetSender(ev, 0x4001ULL);
            if (gDispatch && gProbeClient) gDispatch(gProbeClient, ev);
            usleep(120 * 1000);
        }
    } @catch (NSException *e) { /* HID 层崩溃靠 K_TRY 断点兜 */ }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.9 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        int after = self.manualN;
        BOOL ok = (after > before);
        if (ok) self.synthN++;
        NSMutableArray *r = [[ud arrayForKey:K_RES] mutableCopy] ?: [NSMutableArray array];
        while ((int)r.count <= k) [r addObject:@"?"];
        [r replaceObjectAtIndex:(NSUInteger)k withObject:(ok ? @"OK" : @"NO-EFFECT")];
        [ud setObject:r forKey:K_RES];
        [ud setInteger:k + 1 forKey:K_IDX];
        [ud removeObjectForKey:K_TRY];   // 正常走完，清掉崩溃标记
        [ud synchronize];
        self.idx = k + 1;
        [self refresh];
        if (self.logBusy) {
            HLLogAdd(@"#%02d %@ / %@ / %@ : 事件%d个 命中%d次 → %@",
                     k, HLFormName(form), HLSetName(set), HLMaskName(mi),
                     created, after - before, ok ? @"✅OK" : @"NO-EFFECT");
            [self logSweepStep:k + 1];
        }
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

#pragma mark - 找目标 App 主窗口

// 探针自己的窗口是 UIWindowLevelAlert+1000，必须排除，
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

#pragma mark - 原有「识字」按钮（单跑一次）

- (void)onOCR:(id)sender {
    self.ocrOut.text = @"识字中…";
    UIWindow *appWin = HLAppWindow();
    UIImage *img = HLSnapshot(appWin);
    NSString *stats = HLImageStats(img);
    NSString *winDesc = [NSString stringWithFormat:@"win=%@ %@",
        NSStringFromClass([appWin.rootViewController class]), NSStringFromCGRect(appWin.bounds)];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *r = HLRecognizeEx(img, VNRequestTextRecognitionLevelAccurate,
                                        @[@"zh-Hans", @"en-US"], NO, 0);
        NSArray *items = r[@"items"] ?: @[];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSMutableString *s = [NSMutableString string];
            [s appendFormat:@"条数=%@ 耗时=%.0fms  %@\n", r[@"count"], [r[@"cost"] doubleValue], stats];
            for (int i = 0; i < (int)MIN((NSUInteger)5, items.count); i++) {
                NSDictionary *d = items[i];
                [s appendFormat:@"%d「%@」n(%.2f,%.2f %.2fx%.2f)\n", i, d[@"text"],
                 [d[@"x"] doubleValue], [d[@"y"] doubleValue], [d[@"w"] doubleValue], [d[@"h"] doubleValue]];
            }
            if (!items.count) [s appendFormat:@"0 条 — %@", r[@"err"] ?: @""];
            self.ocrOut.text = s;
            self.ocrHead.text = [NSString stringWithFormat:@"支持语言: %@\n截图: %@  %@",
                                 [HLLangMatrix() stringByReplacingOccurrencesOfString:@"\n" withString:@" "],
                                 stats, winDesc];
        });
    });
}

// 坐标自检：拿「已知位置的文字」反过来验证 Vision → UIKit 的 y 换算。
- (void)onOCRSelf:(id)sender {
    self.ocrOut.text = @"坐标自检中…（截的是探针自己的窗口）";
    UIImage *img = HLSnapshot(gProbeWin ?: self.view.window);
    CGRect tf = self.target.frame, hf = self.head.frame;
    CGFloat H = [UIScreen mainScreen].bounds.size.height;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *r = HLRecognizeEx(img, VNRequestTextRecognitionLevelAccurate,
                                        @[@"zh-Hans", @"en-US"], NO, 0);
        NSArray *items = r[@"items"] ?: @[];
        NSArray *anchors = @[
            @{@"key": @"HLProbe", @"y": @(hf.origin.y)},
            @{@"key": @"手动点",  @"y": @(tf.origin.y)},
        ];
        NSMutableString *s = [NSMutableString string];
        [s appendFormat:@"自检 命中%@条 耗时%.0fms\n", r[@"count"], [r[@"cost"] doubleValue]];
        for (NSDictionary *a in anchors) {
            NSString *key = a[@"key"];
            CGFloat expect = [a[@"y"] doubleValue];
            NSDictionary *hit = nil;
            for (NSDictionary *d in items) {
                if ([[d[@"text"] description] rangeOfString:key].location != NSNotFound) { hit = d; break; }
            }
            if (!hit) { [s appendFormat:@"锚点「%@」未命中\n", key]; continue; }
            double vy = [hit[@"y"] doubleValue], vh = [hit[@"h"] doubleValue];
            CGFloat yA = (CGFloat)(vy * H);
            CGFloat yB = (CGFloat)((1.0 - vy - vh) * H);
            CGFloat dA = fabs(yA - expect), dB = fabs(yB - expect);
            [s appendFormat:@"「%@」实际顶=%.0f | A不翻转=%.0f(Δ%.0f) B翻转=%.0f(Δ%.0f) → %@\n",
             key, expect, yA, dA, yB, dB, (dB < dA ? @"B✅(y=1-y-h)" : @"A✅(不翻转)")];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ self.ocrOut.text = s; });
    });
}

#pragma mark - v9 一键写日志

- (void)onWriteLog:(id)sender {
    if (self.logBusy) return;
    self.logBusy = YES;
    self.autoRunning = NO;
    gLog = [NSMutableString string];
    self.ocrHead.text = @"写日志：采集中…（约 40s，别关屏、别切 App）";
    self.ocrOut.text = @"写日志中，请稍候…";

    HLLogAdd(@"================ HLProbe %@ 真机诊断日志 ================", gBuildTag);
    HLLogAdd(@"构建: %s %s", __DATE__, __TIME__);
    HLLogAdd(@"时间: %@", [NSDate date]);
    HLLogAdd(@"%@", HLEnvLine());
    HLLogAdd(@"bundle: %@", [[NSBundle mainBundle] bundleIdentifier] ?: @"?");
    HLLogAdd(@"HID 符号: %@", gSymReport);
    HLLogAdd(@"HID client: %@ (%p)", gProbeClient ? @"已取得" : @"❌失败", gProbeClient);
    HLLogAdd(@"TARGET 初始 manualN=%d synthN=%d（建议先手点 TARGET 三次再写日志，可作基线）",
             self.manualN, self.synthN);

    UIWindow *aw = HLAppWindow();
    UIImage *appImg = HLSnapshot(aw);
    UIImage *probeImg = HLSnapshot(gProbeWin ?: self.view.window);
    NSString *stats = HLImageStats(appImg);

    HLLogAdd(@"");
    HLLogAdd(@"-- [1] 目标窗口 / 截图 --");
    HLLogAdd(@"目标窗口: %@ %@", NSStringFromClass([aw.rootViewController class]), NSStringFromCGRect(aw.bounds));
    HLLogAdd(@"截图统计: %@", stats);
    HLLogAdd(@"截图方法: drawViewHierarchyInRect:afterScreenUpdates:NO");

    HLLogAdd(@"");
    HLLogAdd(@"-- [2] 取色（探针窗口三纯色块，判 byte order） --");
    NSArray *expect = @[@"(255,0,0)", @"(0,255,0)", @"(0,0,255)"];
    for (int i = 0; i < 3; i++) {
        UIView *v = self.swatches[i];
        CGPoint c = [self.view convertPoint:CGPointMake(v.bounds.size.width / 2, v.bounds.size.height / 2)
                                   fromView:v];
        HLLogAdd(@"  #%d 期望%@ 实测 %@", i, expect[i], HLReadPixel(probeImg, c));
    }

    HLLogAdd(@"");
    HLLogAdd(@"-- [3] Vision 支持语言矩阵（逐 revision × level，问系统） --");
    HLLogAdd(@"%@", HLLangMatrix());

    HLLogAdd(@"");
    HLLogAdd(@"-- [4] OCR 实测（3 种配置，判中文能不能识） --");
    [self logOCRMatrix:appImg];

    HLLogAdd(@"");
    HLLogAdd(@"-- [5] 坐标自检（探针窗口已知位置文字反推 A/B） --");
    [self logSelfCheck:probeImg];

    HLLogAdd(@"");
    HLLogAdd(@"-- [6] 触摸 27 组合（合成触摸是否到达 App） --");
    // 复位触摸计数再遍历
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:K_RES];
    [ud removeObjectForKey:K_TRY];
    [ud setInteger:0 forKey:K_IDX];
    [ud synchronize];
    self.idx = 0;
    self.synthN = 0;
    int base = self.manualN;
    [self refresh];
    HLLogAdd(@"遍历前 manualN=%d（基线；若为 0 说明还没人手动点过 TARGET）", base);
    [self logSweepStep:0];
}

- (void)logOCRMatrix:(UIImage *)img {
    if (@available(iOS 13.0, *)) {
        VNRecognizeTextRequest *d = [[VNRecognizeTextRequest alloc] init];
        HLLogAdd(@"  默认 revision=%ld（不显式设置时用的就是它）", (long)d.revision);
    }
    NSArray *cfgs = @[
        @{@"name": @"accurate/[zh-Hans,en-US]/corr=NO", @"level": @(VNRequestTextRecognitionLevelAccurate),
          @"langs": @[@"zh-Hans", @"en-US"], @"corr": @NO},
        @{@"name": @"accurate/auto-langs/corr=YES", @"level": @(VNRequestTextRecognitionLevelAccurate),
          @"langs": [NSNull null], @"corr": @YES},
        @{@"name": @"fast/auto-langs/corr=NO", @"level": @(VNRequestTextRecognitionLevelFast),
          @"langs": [NSNull null], @"corr": @NO},
    ];
    for (NSDictionary *c in cfgs) {
        NSArray *langs = [c[@"langs"] isKindOfClass:[NSArray class]] ? c[@"langs"] : nil;
        NSDictionary *r = HLRecognizeEx(img, [c[@"level"] integerValue], langs, [c[@"corr"] boolValue], 0);
        HLLogAdd(@"  ● %@ → 条数=%@ 耗时=%.0fms rev=%@ %@",
                 c[@"name"], r[@"count"], [r[@"cost"] doubleValue], r[@"rev"], r[@"err"] ?: @"");
        NSArray *items = r[@"items"] ?: @[];
        for (int i = 0; i < (int)MIN((NSUInteger)8, items.count); i++) {
            NSDictionary *it = items[i];
            HLLogAdd(@"      %d 「%@」conf=%.2f n(%.3f,%.3f %.3fx%.3f)",
                     i, it[@"text"], [it[@"conf"] doubleValue],
                     [it[@"x"] doubleValue], [it[@"y"] doubleValue],
                     [it[@"w"] doubleValue], [it[@"h"] doubleValue]);
        }
    }
}

- (void)logSelfCheck:(UIImage *)img {
    NSDictionary *r = HLRecognizeEx(img, VNRequestTextRecognitionLevelAccurate,
                                    @[@"zh-Hans", @"en-US"], NO, 0);
    NSArray *items = r[@"items"] ?: @[];
    CGFloat H = [UIScreen mainScreen].bounds.size.height;
    HLLogAdd(@"  自检 OCR 命中 %@ 条 耗时 %.0fms", r[@"count"], [r[@"cost"] doubleValue]);
    NSArray *anchors = @[@{@"key": @"HLProbe", @"y": @(self.head.frame.origin.y)},
                         @{@"key": @"手动点",  @"y": @(self.target.frame.origin.y)}];
    for (NSDictionary *a in anchors) {
        NSString *key = a[@"key"];
        CGFloat expect = [a[@"y"] doubleValue];
        NSDictionary *hit = nil;
        for (NSDictionary *it in items) {
            if ([it[@"text"] rangeOfString:key].location != NSNotFound) { hit = it; break; }
        }
        if (!hit) { HLLogAdd(@"  锚点「%@」未命中", key); continue; }
        double vy = [hit[@"y"] doubleValue], vh = [hit[@"h"] doubleValue];
        CGFloat yA = (CGFloat)(vy * H), yB = (CGFloat)((1.0 - vy - vh) * H);
        HLLogAdd(@"  锚点「%@」实际顶=%.0f | A不翻转=%.0f(Δ%.0f) B翻转=%.0f(Δ%.0f) → %@",
                 key, expect, yA, fabs(yA - expect), yB, fabs(yB - expect),
                 (fabs(yB - expect) < fabs(yA - expect) ? @"B✅(y=1-y-h)" : @"A✅(不翻转)"));
    }
}

- (void)logSweepStep:(int)k {
    if (k >= HL_TOTAL) {
        HLLogAdd(@"遍历完：合成命中 %d / %d 次", self.synthN, HL_TOTAL);
        if (self.synthN == 0) {
            HLLogAdd(@"⚠️ 27 组全部 NO-EFFECT —— 若遍历前 manualN>0（按钮本身活着），");
            HLLogAdd(@"   则说明合成触摸事件根本没到达 App 的 UIKit 层。");
        } else {
            HLLogAdd(@"✅ 存在能生效的组合，见上面标 OK 的那几行。");
        }
        [self finalizeLog];
        return;
    }
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setInteger:k forKey:K_IDX];
    [ud synchronize];
    self.idx = k;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self runCombo:k]; });
}

- (void)finalizeLog {
    NSDictionary *w = HLWriteLogFile(gLog);
    NSMutableString *m = [gLog mutableCopy];
    [m appendString:@"\n-- [7] 落盘 / 上传 --\n"];
    [m appendFormat:@"本地写入:\n%@\n", [w[@"tries"] componentsJoinedByString:@"\n"]];
    NSString *payload = [m copy];
    self.ocrOut.text = payload;
    self.ocrHead.text = [NSString stringWithFormat:@"日志 %lu B，上传中…", (unsigned long)payload.length];
    __weak typeof(self) ws = self;
    HLUploadLog(payload, ^(NSString *res) {
        NSString *all = [payload stringByAppendingFormat:@"上传: %@\n", res];
        HLWriteLogFile(all);
        ws.ocrHead.text = [NSString stringWithFormat:@"✅日志 %lu B\n上传: %@\n文件: %@",
                           (unsigned long)all.length, res,
                           [w[@"ok"] count] ? [w[@"ok"] firstObject] : @"(见下方列表)"];
        ws.logBusy = NO;
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

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesBegan:touches withEvent:event];
}

@end

#pragma mark - E. 注入入口

// ★ 窗口必须被全局强引用。原版用 block 内局部变量 UIWindow *w，ARC 跑完即回收 → 不显示。
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
