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
#import <Vision/Vision.h>          // v38：屏幕识字（OCR）—— 通用能力，不针对任何 App
#import <ImageIO/ImageIO.h>
#import <objc/runtime.h>
#import <UIKit/UIGestureRecognizerSubclass.h>   // v25：允许直接调 gr 的 touchesBegan/Ended
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
static NSString * const kAIVer = @"v62";   // v62 = 「KSN1-1 能力层加固 + 设备侧签名自给自足」。三件事：
   //       ① `http` op 加 `maxlen`：回执体积上限从硬编码 20000 改为可由 `cmd.maxlen` 覆盖（0 = 不截断）。
   //          为什么必须：`/homepage/tasks` 回执 20005B，正好被 20000 砍掉最后一个字符 → json 解析报
   //          `Unterminated string`，看起来像「接口坏了」，实为回执被截。★ 截断必须**显式**且**可关**。
   //       ② `call` op 加 `maxlen`：单个字符串返回上限从硬编码 8000 改为可覆盖（0 = 不截断）。
   //          为什么必须：`_methodDescription`（一次性 dump 某类全部方法名+地址）长 8005 字符，
   //          被砍在 8005-5 处；且中继层单条回执 ~4000 上限（G105），双重截断下 json 必坏。
   //       ③ body 参与签名：确认 `http` op 的 `cmd[@"body"]` → HTTPBody 通路**早已完整**，
   //          写接口签名所需原料（URL 参 + body 参）在设备侧**取得到**，无需再改 dylib。属脚本层组装。
   //       ★ 安全边界：① ② 都只是「回执截断阈值」这一个数字可配，**不新增任何动作能力**，
   //         不放开任何白名单；`maxlen` 只影响「给你看多少」，不影响「能做什么」。零风险。
   //       ▼ v61 前情：v61 = 「call 设备侧就地抽取」。给 `call` 加 pick: 参数 —— 在**设备内**从大返回值里
   //       挑出要的子集再回传，解决「返回值太大撑爆回执」。★ 为什么必须：v60 的 inst 白名单已能取到
   //       单例实例，但 `NSHTTPCookieStorage.cookies` 返回 **744 个 Cookie**，description 展开数百 KB，
   //       AIReportDict 的 POST 超限直接丢包 → 调用方看到的是**彻底无回执**（不是报错！），极易误判成
   //       "设备掉线/op 不存在"。实测：probe/processName/count 都正常，唯独 cookies 无回执 → 定位到体积。
   //       ★ 做法：pick 支持 dict 取字段 / array 取下标+字段投影 + 截断，全在设备侧完成，回执只带结果。
   //       ★ 安全边界：只读、只做取值/投影/截断，不改任何状态；pick 是与 call 同级的**只读后处理**。
   //       ▼ v60 前情：只读单例实例方法（inst: 白名单）。v60 = 给 `call` 加 inst: 参数 —— 传白名单内的单例方法名
   //       （如 inst=sharedHTTPCookieStorage），插件先取到**实例**，再按真实签名调**实例方法**。
   //       ★ 为什么必须有：`NSHTTPCookieStorage.sharedHTTPCookieStorage.cookies` 是最典型的
   //       「单例 + 实例方法」，但 v57 的 call 只认类方法（+），够不着。实证：设备 http op
   //       发出的请求回执 `nCookie: 0`（一个 Cookie 都没带）→ 服务端 result:40「服务器繁忙」
   //       （实为认不出身份）。要从进程里读真实 Cookie/鉴权头，就必须能调实例方法。
   //       ★ 安全边界：只认**白名单单例**（NSHTTPCookieStorage/NSUserDefaults/NSFileManager/
   //       NSNotificationCenter/NSURLCache/NSProcessInfo），全部是只读容器或只读偏好，
   //       不含任何业务对象；白名单外的 inst 一律拒绝；单例方法必须无参。
   // v59 = 「输出参数支持」：给 `call` 加**可变容器包装**语法 —— 参数写成 {"$mstr":"初值"} / {"$marr":[...]} / {"$mdict":{...}} 即自动构造 NSMutableString/Array/Dictionary，调用后把容器的**最终内容**回传到 out[]。★ 为什么必须有：真机实测调 KSMWPassportSecurityTools +sig3OnURLPath:method:requestParams:sig3PlainText: 时，第 4 个参数 sig3PlainText: 报 `Attempt to mutate immutable object with setString:` —— 它是**输出参数**（函数把算出的明文 setString: 写回给你），传不可变 NSString 必炸。这是 Cocoa 惯用法：形如 `xxxPlainText:` / `result:` 的参数是 by-reference 输出，必须传**可变**容器。有了 out[]，就能把这类函数「算出来的中间明文」捞出来，这是反推签名算法最关键的原料。▼ v58 前情：给 `call` 加 probe=1（只读方法签名，回 want/argTypes/retType）+ 参数个数判据 `>` 改 `!=`（少一个就是拿未初始化内存当参数 → UB）。▼ v57 前情：路线 A 落地，新增通用 `call` op。★ v56 的 mm=1（按方法名扫）真机挖出签名函数 —— v58 上机复扫又挖出**最关键的统一入口**：KSMWPassportSecurityTools +sig3OnURLPath:method:requestParams:（路径+方法+参数 → 64hex）、+sig3OnURLPath:method:requestParams:sig3PlainText:（多一个**输出**明文参数）、+checkOnSig3UrlPathWhiteList:，以及 KSLASecurityHandler +customSig3WithPath:parameters:（前 6 hex 与前者相同 → 共享 sig3 前缀逻辑）、KSExtensionNetwork +_sig3WithPath:sig:did:、KWAppSignatureBuilder +createTokenSigWithSig:salt:（__NStokensig）、KSGPolicyParser +handleSig3Policy:。这些类**类名里根本没有 sig**，只有按方法名才扫得到。▼ v55/v56 前情：已把「抄+原样重放」跑通（clock/r result=1；签名绑 URL 参数+body、不绑 X-REQUESTID；T+12min 仍有效）。
//   ---------------------------------------------------------------------------
//   v49（路线一 · 通用网络监听）的结论留痕 —— 写在版本号旁边，避免后人再走一遍：
//
//   【做了什么】用 NSURLProtocol 注册式 hook 旁路记录 App 的 HTTP 往返，
//     想让 AI 直接读接口 JSON 而不是靠 OCR 猜数字。三道闸隔离做得很干净
//     （中继 host 在 canInitWithRequest: 就 return NO、总开关默认关且限时、
//      propertyForKey: 防递归），真机实测中继全程稳定、零误抓。
//
//   【为什么撤掉】2026-09-30 真机实测判定 —— **快手不走 NSURLSession**。
//     证据（[FACT]，同一 300s 监听窗口内）：
//       · 监听层确实工作：抓到 https://www.apple.com/library/test/success.html
//         -> 200 84ms 69 text（与 diag 的「①苹果 ✅ 200」互证，cnt 精确 =1）
//       · 快手确实有网络活动：滑 8 条视频后 feed 内容变化、luma 37→137
//       · 同一窗口内快手零记录：cnt 恒为 1（就是苹果那条）
//     机理：快手这类大厂用自研 HTTP 客户端（基于 CFNetwork/自封装 socket+TLS），
//     绕过 NSURLSession —— 而 NSURLProtocol 只对 NSURLSession 生效。
//     业界做 App 网络观测之所以普遍用抓包（VPN/代理）而非 NSURLProtocol，就是这个原因。
//
//   【v54 更正 —— 上面这段结论只对了一半，务必读这段再动手】
//   2026-10-02 用 sigprobe 的「旁路 hook NSMutableURLRequest」实测 overturn：
//     滑 8 条视频，315 条记录里 **167 条是 az4-api.ksapisrv.com、70 条是 ulogjs.ksapisrv.com**。
//     —— **快手确实用 NSMutableURLRequest 构造请求**！
//   正确的机理是：
//     · NSURLProtocol **只对 NSURLSession 生效** → 抓不到快手 ✅（这段没错）
//     · 但 NSMutableURLRequest 是 **URL Loading System 的请求对象**，
//       NSURLConnection / 自研基于它的栈**照样会用它**，所以 hook 它的头 setter **能抓到**。
//     · 结论修正为：**快手不走 NSURLSession，但走 NSMutableURLRequest。**
//       所以「不能用 NSURLProtocol」≠「不能用 ObjC 层 hook」。
//   【快手鉴权载体（v53 真机实测，见 侦察结论-快手鉴权机制.md）】
//     头：Cookie(region_ticket+__NSWJ) / kas(32hex,会话固定) / kaw(base64,会话固定)
//         / qr-xx-kv(did,ud,egid,rdid) / X-REQUESTID(每请求变) / User-Agent:kwai-ios
//         / x-aegon-* 系列
//     URL 查询参数 51 个，其中签名类：__NS_sig3 / __NStokensig / sig / __NS_xfalcon
//     业务域真机实为 **az4-api.ksapisrv.com**（不是 HAR 里的 az3-api-js.gifshow.com）。
//   【适用边界】像=<想覆盖 App 网络>，优先 hook NSMutableURLRequest 的头 setter（ObjC，简单、
//     进程内、零依赖）；NSURLProtocol 那条留给「确认走 NSURLSession 的 App」。抓包仍需用户
//     装描述文件，违背本项目「注入即用」的第一性目标，继续不采用。
//
//   【反例/边界】限于「快手极速版 com.kwai.nebula，2026-09-30 / 2026-10-02 两次观测」。
//   ---------------------------------------------------------------------------
// v48 = v47 + G55 拖动起步阈值修复（会话主 · 用户报障「v47 拖球没偏了，但按住中心点要拖到边缘球才动」）：v47 用 [pan requireGestureRecognizerToFail:tap] 区分点击/拖动，但 tap 的失败判定要求手指位移超过其自身容差（约 10pt），于是 pan 必须等手指走够这段才 recognize —— 用户按住球心（半径 28pt 的球）往外拖，要拖到接近球边缘才开始跟手，手感就是「拖不动 / 只有边上能动」。修法：① 去掉 requireGestureRecognizerToFail，tap/pan 由 AIFloatTarget 作为 delegate 允许并存识别（shouldRecognizeSimultaneously 返回 YES）；② 在 ballDragged: 内按**累计位移**自行分流：translation 每次被清零，故用 gFloatDragAcc 自攒，<6pt 不动（判定权留给 tap，保证轻点能展开），≥6pt 才真正拖窗口，并主动把 tap 置失败（enabled 翻转一次强制重置）避免拖完抬指又触发一次展开/收起；③ 加 gFloatDragOn 状态标记本次触摸是否已进入拖动，拖动确认时把 tap 的 enabled 翻转一次强制其失败（比 gestureRecognizerShouldBegin 可靠 —— 后者对 tap 的判定发生在触摸落下时，那时还没有位移信息，判不出拖动）。v47 = v46 + 悬浮球拖动交互两处修复（会话主 · 用户报障「拖球有偏差 + 拖完再点没反应」）：① [G53] ballDragged 坐标系混算——原代码拖的是 gFloatWindow 内的 ball 子视图，ball.center 是**窗口内**坐标（收起态恒为 30,30），却在同一行里用**屏幕**尺寸 sc.width/sc.height 做 clamp，两套坐标混算 → 球被推到 60×60 窗口之外，表现为「手指拖了球却偏移/跑飞/看着没动」。修法：直接拖**窗口本身**（窗口原点即屏幕坐标，与 sc 同系），球作为窗口内固定子视图跟随；同时把 fpx/fpy 的存储与还原公式改为严格互逆（px=(cx-30)/(W-60)，与 AIFloatApply 的 c.x=30+px*(W-60) 对偶），实测 6 个落点往返一致到 0.6px 内。② [G54] tap 与 pan 挂在同一 view 上却没声明优先级——iOS 默认 pan 一旦开始就取消 tap，而 pan 识别阈值仅约 10pt，轻点时的微小位移会被 pan 抢走，于是「拖过一次之后点球没反应」。修法：显式 [pan requireGestureRecognizerToFail:tap]（v48 已被 G55 取代），并限制 minimum/maximumNumberOfTouches=1。③ 附带：拖动期间置 gFloatLast=now 抑制心跳自愈把窗口按旧值拽回；拖动结束强制 AIFloatApply 一次，消除「存的是新值、显示是旧值」的漂移窗口。   // v47 = v46 + 悬浮球拖动交互两处修复（会话主 · 用户报障「拖球有偏差 + 拖完再点没反应」）：① [G53] ballDragged 坐标系混算——原代码拖的是 gFloatWindow 内的 ball 子视图，ball.center 是**窗口内**坐标（收起态恒为 30,30），却在同一行里用**屏幕**尺寸 sc.width/sc.height 做 clamp，两套坐标混算 → 球被推到 60×60 窗口之外，表现为「手指拖了球却偏移/跑飞/看着没动」。修法：直接拖**窗口本身**（窗口原点即屏幕坐标，与 sc 同系），球作为窗口内固定子视图跟随；同时把 fpx/fpy 的存储与还原公式改为严格互逆（px=(cx-30)/(W-60)，与 AIFloatApply 的 c.x=30+px*(W-60) 对偶），实测 6 个落点往返一致到 0.6px 内。② [G54] tap 与 pan 挂在同一 view 上却没声明优先级——iOS 默认 pan 一旦开始就取消 tap，而 pan 识别阈值仅约 10pt，轻点时的微小位移会被 pan 抢走，于是「拖过一次之后点球没反应」。修法：显式 [pan requireGestureRecognizerToFail:tap]，并限制 minimum/maximumNumberOfTouches=1。③ 附带：拖动期间置 gFloatLast=now 抑制心跳自愈把窗口按旧值拽回；拖动结束强制 AIFloatApply 一次，消除「存的是新值、显示是旧值」的漂移窗口。v46 = v45 + 最后一批「抄错 token」修正（会话主 · 用 prototype-html 技能把 v45 做成可交互原型并与 v8 原型逐项对照时又抓出的 3 处）：① .p-hd h3 字号 13→**14**（原型写 var(--fz-3)，而 --fz-3=14px，--fz-2 才是 13 —— 我上一版注释里抄错了 token 名，属于 G47「以为差不多」的具体形态）；② L3 面板按钮 .pbtn 14→**13**（原型 var(--fz-2)=13px，上一版我以「安全入口可读性」为由主动放大到 14，但既然原型就给了 13 且 44pt 高度已满足触摸下限，应忠于原型）；③ .g-meta 透明度 .72→**.85**（原型 .g-meta{opacity:.85}）。—— 结论：**UI 落地只要还有一处「我按感觉给的」，就还能再抓出差异**；本轮把 v8 的每一条 CSS 声明都映射到了源码常量。v45 = v44 + 原型头部/回顾卡精修（会话主 · 最后一批回选择器原文核对）：① L3 面板头部补「3/7」步数（原型 .p-hd .stepno{11px;--txt-2}）——原型的头部是「形状 标题 步数 ✕」四段，上一版把步数塞到第二行副标题，把「一眼看到第几步」降级成「读一行小字」；② 面板关闭按钮「收起」文字 44×26 → 原型 .p-close 的 **✕ 图标 30×30 圆角8 描边 --line**（文字按钮占宽且与暂停/结束语义混淆，✕ 才是通用关闭语汇）；③ 回顾卡标题 h4 14→**16px**；④ 回顾卡三数字 .nums b 13→**14px**。v44 = v43 + 原型剩余 4 处结构补齐（会话主 · 继续回选择器原文核对，把「原型有、真机没有」的全部补上）：① L3 面板「本轮回顾」行（原型 .recap）—— v42 漏做；回顾卡是任务结束的**一次性**强提示，点掉即失，这行是面板里**随时可查**的常驻战绩摘要（N/M 成功 · 结论），缺了它错过弹卡就再也看不到本轮结果；底部预留 152→174 腾位，实测各分区 62..206 / 206..222 / 234..262 / 268..300 / 326..370 无重叠；② L2 罩层标题（原型 .g-title）—— 上一版是「彩色形状+彩色大字 22px」挤一个 label，原型是**8px 脉动圆点 + 纯白 16px 稳字**（gap 7，圆点 1.4s 呼吸、文字不动）；③ 罩层副标题 15px 白 → 13px/alpha.88（原型 .g-brief --txt-2=rgba(255,255,255,.88)）；④ 罩层三按钮（原型 .gbtn）52→46 高、12→10 圆角、14→13 字号，「结束」改用 .gbtn.stop 红色语义（红边 .7 + 红底 .16 + 浅红字）——破坏性动作必须与另两个可区分，是安全设计不是装饰。v43 = v42 + 原型数值/结构精修（会话主 · 对照原型选择器原文逐项核对，共 7 处）：① .step .sy 形状字号 13→**12**（上一版误取 .p-hd .sy 的 15px，改回 .step 继承值 --fz-1=12；同一 class 名在不同作用域取值不同，必须回选择器原文核）、列宽 14→**12**（原型 .step .sy{width:12px}）；② 动作文字 X 33→**31**（.step padding-left 12 + .sy 宽 12 + .l1 gap 7）；③ 步骤行高 48→**51**（有证据行重算：7+18.6+2+15.5+7+0.5，无证据行仍 34）；④ .ev 证据行缩进 33→**31**（.step padding-left 12 + .ev padding-left 19），颜色 .72→**.88**（原型 .ev 用 --txt-2=rgba(255,255,255,.88)）；⑤ L1 球内部拆两元素：原来形状+词塞进一个 11px 双行 label → 形状独立 **19px**（原型 .ball .shape{font-size:19px}）+ 词独立 **9px**、色 .88（原型 .ball .word{font-size:9px;max-width:52px}），脉动动画改挂形状层（原型 .shape.pulse）；⑥ L3 面板头部拆两元素：原来形状+任务名同 label 同色 14px → 形状独立 **15px** 状态色（原型 .p-hd .sy{font-size:15px}）+ 标题恒白 **13px**（原型 .p-hd h3{font-size:13px}，不随状态着色），间距 8（.p-hd gap:8px）；⑦ 版本号自证。v42 = v41 + UI 结构实现（会话主 · 补齐原型 v8 缺失的结构，共 12 处）。v41 只做了 5 处数值微调（颜色/alpha/形状/宽高），用户对比原型后指出「真机还是老界面，只有悬浮球变了」——因为 v41 没新增任何结构，而原型最核心的两块结构真机上根本不存在。本版补齐：① L3 步骤列表：一整块 9px Menlo 灰字 UITextView → UIScrollView + 逐行 AIStepRowView（图标 14 + 动作 12px #e9eef3 + 目标 + Menlo 10px 证据 + 0.5px 分隔线，按状态着色；行高 有证据 48/无 34）；② 结束回顾卡（规划 §8.1 收尾闭环）：原来只有一行 ▶ 拼在文本末尾 → 罩层中央 246×214 大卡（✓/■ + 任务完成·原因 + 用时·动作·失败 三数字 + 知道了 44pt）；③ L2 罩层进度条：「共 N 步 · 当前第 M 步」+ 196×6 进度条（填充 idx/total，与状态同色）；④ L1 球动效：脉动（exec/wait 1.8s 呼吸）+ done 徽标脉冲 + 吸边半隐（edge 开关，alpha .55 右移 18）；⑤ 减少动效：跟随 UIAccessibilityIsReduceMotionEnabled + reduce 开关强制；⑥ L3 副标题加「成功 ✓N」计数；⑦ L3 新增「⧉ 复制步骤全文」按钮（行视图后文字不可选，需显式出口）；⑧ 回顾卡状态机：gRecapShown/gRecapDismissed 双闸。⑨ 结构可观测化（这一条是被否掉的 v41 最该有的东西）：ui{} 新增 panel.steps.n（步骤行数）/ panel.okcnt（成功步数）/ guard.recap（回顾卡在不在）/ guard.recaptext / guard.pct（进度条百分比）/ float.edge / float.reduce —— v41 的 ui{} 里一个结构字段都没有，脚本想测「步骤列表有没有每步一行」也无从下手，只能退化成测 dot 颜色，于是「15/15 全绿但用户不认」；⑩ 新增命令 recapknow（等价点「知道了」）/ copysteps（复制全文，回传剪贴板长度）/ flag（读写 edge·reduce 等开关），让上述结构量全部可被脚本远程断言。—— 关键坑：AIGuardShouldShow 加 gRecapShown（任务收尾 gBusy 归零，否则罩在同帧落下，卡无容器）；task op 里显式 AIGuardRender（AIGuardSync 在罩已显示时不重绘，卡状态变了屏上还是旧的）；AITaskSet 清空分支仅在 gRecapDismissed 时清 gTaskResult（否则云端补发的 task{0,0} 会把刚弹的卡提前干掉）。v41 = v40 + UI 落地（会话主 · 原型 v8 → 真机源码，共 5 处）：① 失败形状 ✕→■（与原型 v4/v8 对齐，规划 §2 与 §9.2 自相矛盾取 ■；形状是语义载体，原型与源码不一致落地必错）；② L1 悬浮球可辨识性：黑 0.62 半透明无描边 → 不透明 #14161a + 2px 亮描边 rgba(255,255,255,.92)，双对比元素取最大值（原型实测 深色宿主旧值仅 1.13:1 近乎隐形，新值 深色 16.29/浅白 6.74/中性灰 12.48/高饱和 14.62 全 ≥3）；③ L1 球词优先读 task.brief（原实现忽略 brief，球上只有干巴巴的 3/7）；④ L2 罩层暗化 0.55→0.65（0.55 在浅色宿主上次级文字仅 3.33:1 不达 WCAG，0.65 是四种宿主全达标的最小可用值 6.57~15.64）；⑤ L3 面板暂停/结束按钮 32→44 高 + 面板 360→380（原注释写着「≥44pt 原则」实际只做 32，而这是唯一能叫停 AI 的安全入口）。v40 = v39 + G30 根治（G30：回执通道单边瘫死——飞行模式令域名 poll 连败 4 次后 gActiveBase 切 IP 兜底，轮询带 AITrustDelegate 活着，回执/心跳 POST（AIReportDict）却没带 → IP 直连证书 CN 不匹配 → -1202「证书无效」一切回执单边全灭；看门狗只看轮询 tick（命令还在执行）永不换代，IP 态又无自动回切路径 → 死锁到杀 App。修法：回执与轮询同待遇，IP 态同样 trustAny+Host 覆盖）。v39 = v38 + G28 看门狗三件套（会话B 合流）：① hang 阈值 45→150s（text/tree 全量 25~90s，45s 对慢命令必然误判换代）；② rst 每 60s 冷却回收 1（原 rst=8 永久放弃换代，13:12 事故通道瘫死实锤）；③ 积压 >3 只执行最后 1 条（换代后新代拉积压慢命令循环换代是耗尽主因）；④ 换代即落盘日志（取证）。v38 = v37 + 屏幕识字（会话A）：op=ocr 读整屏文字 / op=vfind 按文字找并点，参数 accurate + zh-Hans,en-US + correction=NO、坐标 y=(1-y_vn-h)*H。v37 = v36 + G25 竞态修复（task/status 的 gTask* 读写统一挪主线程，.ips 实锤 AITaskDict 竞态 → SIGSEGV）
static volatile int32_t gPollOK = 0, gPollErr = 0;
static volatile int32_t gRepOK  = 0, gRepErr  = 0;
static volatile int32_t gCmdGot = 0;
// ---- v35：G13 轮询看门狗 ----
// 坑：轮询线程偶尔 hang 死（卡在 NSURLSession 里不回），从此命令全不回执、
// 心跳也停，唯一恢复办法是杀进程重开 —— 用户在外面根本不知道发生了什么。
// 做法：轮询线程每完成一趟就打一个 tick；看门狗发现 tick 超过 WD_HANG_SEC 没动，
// 就起一条「新一代」轮询线程接管，旧线程若哪天醒过来发现代次变了自行退出。
#define AI_WD_HANG_SEC 150.0     // v39（G28）：45→150。事实：text/tree 全量实测 25~90s，v36 只在命令
                                 //      开头打一次 tick，45s 阈值对 >45s 的慢命令必然误判换代
                                 //      → 新代再拉积压慢命令又超时 → 循环换代 → rst 耗尽 → 通道瘫死
                                 //      （13:12 事故实证：App 活着、主线程活着、命令通道 10 分钟无响应）
#define AI_WD_MAX_RETRY 8        // 自愈重启上限，防止线程泄漏式暴涨
static volatile double gPollTick  = 0;    // 轮询线程最后一次「走完一趟」的时刻
static volatile int32_t gPollGen  = 0;    // 轮询线程代次（只有最新一代继续跑）
static volatile int32_t gPollRst  = 0;    // 看门狗已重启过几次
static volatile double gMainTick  = 0;    // 主线程最后一次响应看门狗 ping 的时刻
static volatile double gMainLag   = 0;    // 主线程卡了多久（秒），0 = 正常
static long             gLastErrCode = 0;
static NSString        *gLastErrText = nil;
static NSString        *gToastText   = nil;   // 我从中继下发的一句话
static NSString        *gDiagText    = nil;   // 网络自检结果
static UIWindow        *gHudWindow   = nil;   // 顶端常驻状态条（独立于盖屏，收起盖屏也还在）
static UILabel         *gHudLabel    = nil;
static BOOL             gHudWanted   = NO;    // v30：默认完全隐藏（诊断计数走云端 log/status，屏幕只留悬浮球）
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

// v30：任务态 —— 云端 task op 下发，悬浮球显示「任务名 进度 / 当前动作」。
// 屏幕上用户只需要看这个；其余诊断信息全部走云端（status 自报 / log 拉取），不再上屏。
static NSString *gTaskName = nil;        // 任务名，如「刷视频」
static NSString *gTaskStep = nil;        // 当前动作，如「上滑切下一个」
static int      gTaskIdx   = 0;          // 第几步（1-based）
static int      gTaskTotal = 0;          // 共几步；0 = 无任务（悬浮球回落显示版本/心跳）
static int      gTaskOk    = -1;         // -1 执行中 / 1 最近一步成功 / 0 最近一步失败
static BOOL      gFloatForce    = NO;    // 交互操作要立刻重绘，跳过节流
static CFTimeInterval gFloatLast = 0;
// v48 · G55：拖动起步阈值状态。
//   v47 用 [pan requireGestureRecognizerToFail:tap] 区分「点击 / 拖动」，但 tap 的失败判定
//   要求手指位移超过其自身容差（约 10pt），于是 pan 必须等手指走够这段才 recognize ——
//   用户按住球心往外拖，得拖到接近球边缘（半径 28pt）球才开始跟手，手感是「拖不动」。
//   正确做法：两者并存识别，由代码按**累计位移**决定是拖动还是点击。
static BOOL      gFloatDragOn   = NO;    // 本次触摸是否已判定为拖动
static CGPoint   gFloatDragAcc  = {0, 0};   // 拖动累计位移（translation 被清零后由此累加）
//   注意：不能用 CGPointZero —— 它是 CGPointMake() 的函数调用，不是编译期常量，
//   文件作用域初始化会报 "initializer element is not a compile-time constant"（CI #80 实测）。

// ---- v30 UI 三层任务态（单一状态源：/status 的 task{}+ui{} 驱动 L1/L2/L3）----
// 状态取值沿用规划 §5：idle | exec | wait | ok | fail（形状优先，颜色只做加强，色盲可用）
static NSString *gTaskState  = @"idle";   // 当前状态
static NSString *gTaskBrief  = nil;       // 一句话（给悬浮球/防护罩），如「正在刷第 3 个视频」
static NSString *gGuardMode  = @"privacy";// privacy（毛玻璃+暗化）| verify（露出 App，仍吃触摸）
static BOOL      gGuardPinned = NO;       // 手动 pin：任务结束也不落下
static volatile int32_t gOpBusy = 0;      // v34：AI 操作期标志（不只是有任务才遮挡）
static CFTimeInterval   gLastOpTs = 0;    // v34：最后一次真实操作的时刻，用于空闲自动落下
static volatile int32_t gBusy = 0;        // 任务期标志：1 = 有任务在跑 → 防护罩自动升起
static NSMutableArray *gSteps = nil;      // L3 步骤列表：@{@"s":状态,@"act":动作,@"obj":目标,@"ev":证据}
static BOOL      gPanelDiag  = NO;        // L3 面板「诊断」区是否展开（默认折叠）
static NSString *gTaskResult = nil;       // 结束回顾卡文案（任务结束时一句话结论）
// ---- v42 回顾卡状态机 + 动效开关 ----
// 回顾卡为什么需要两个标志：云端在任务结束时可能还会补发 task{step:0,total:0} 清空信号，
// 而 AITaskSet 的清空分支会重置 gTaskResult。若不加闸，刚弹出的卡会被紧随其后的清空信号干掉。
// 故：gRecapShown=卡在显示；gRecapDismissed=用户已点「知道了」（唯一放行清空的钥匙）。
static BOOL      gRecapShown     = NO;
static BOOL      gRecapDismissed = NO;
static int       gTaskStartTs    = 0;    // 任务起点（unix 秒），用于回顾卡「用时 1:24」
static int       gTaskActCount   = 0;    // 动作次数（每 AIStepAdd 一次 +1）
static BOOL      gReduceMotion   = NO;   // v42：减少动效（跟随系统 + reduce 开关）

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
static void AIGuardSync(void);               // v32：罩层状态自愈（tick 每秒收敛一次）
static void AIGuardRender(void);             // v32：guardVerify(4392) 在定义(4411)之前要用
static void AIFloatSync(void);               // v33：悬浮球自愈（tick 每秒收敛一次）
static void AIOpMark(void);                  // v34：操作类命令点亮罩层（AIExecCmd 在定义之前要用）
static void AIOpIdleCheck(void);             // v34：操作停下 8s 后罩层自动落下
static void AIShowOverlay(void);            // 盖屏按钮回调里要刷新报告
// v30 UI 三层任务态（定义见 AIFloatApply 之前）
static void AITaskSet(NSString *name, int step, int total, NSString *state, int ok, NSString *brief);
static void AIStepAdd(NSString *state, NSString *act, NSString *obj, NSString *ev);
static NSString *AIShapeFor(NSString *st);
static UIColor  *AIColorFor(NSString *st);
static NSString *AITaskLine(void);          // AIGuardRender(4452) 在定义(4779)之前要用
static NSString *AITaskStateNow(void);      // v30：当前有效状态（含 fail 优先）
static NSString *AITaskStateNorm(NSString *s);  // v44：状态归一（AIGuardRender 在定义之前要用）
//                                           ↑ 忘加这行 = CI #75 的 4 个 error（bad receiver type 'int'）。
//                                           G42 同类：定义在后面、调用在前面，就必须有声明，
//                                           哪怕只差几百行 —— 编译器不猜。
static NSDictionary *AITaskDict(void);      // /status 的 task{} —— AIExecCmd 在定义之前要用
static NSDictionary *AIUiDict(void);        // /status 的 ui{}
// v42 UI 结构实现：这几个函数定义在文件后段，被 AIGuardRender / AIFloatApply 提前调用。
// C99 不允许隐式声明，必须在头部补声明（此坑项目里栽过 4 次）。
static void      AIDismissRecap(void);                    // 回顾卡「知道了」出口
static UIView   *AIStepRowView(NSDictionary *step, CGFloat w);   // L3 单行步骤视图
static UIView   *AIRecapCardView(CGFloat screenW);        // 结束回顾卡
static NSString *AITaskElapsedText(void);                 // 「用时 1:24」
// v42：copysteps 命令要复用真实按钮的 AIFloatTarget。这里必须给**完整 @interface**（含
// copySteps: 声明），只写 @class 前向声明没用 —— 前向声明只允许指针用法，
// [[... alloc] init] 和发消息都会报 "receiver ... is a forward declaration"（CI #71 实测）。
// 实现仍在文件后段，接口提上来即可。
@interface AIFloatTarget : NSObject <UIGestureRecognizerDelegate>
- (void)ballTapped:(id)sender;
- (void)ballDragged:(UIPanGestureRecognizer *)g;
- (void)sw:(UISwitch *)s;
- (void)collapse:(id)sender;
- (void)hideBall:(id)sender;
- (void)toggleDiag:(id)sender;
- (void)pauseTask:(id)sender;
- (void)endTask:(id)sender;
- (void)copySteps:(id)sender;
@end
static AIFloatTarget *gFT;                                // 球面板的目标对象（常驻单例）
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
static BOOL AIMemSafe(void);                         // v24：内存水位阀，定义在 ~2436 行
static int  AIMemMB(void);                           // v24：当前常驻内存 MB
static id   AISafeObjGet(id v, SEL g);               // v24：只接受对象返回值的 selector 调用
static NSString *AIRuntimeTextOf(id v);              // v27：AIFindViewsAt 要用，定义在 ~2684 行
static BOOL AITapUIControlAt(CGPoint pt, NSString **outDesc);  // v28：AIDismiss 要用，定义在 ~1137 行
static NSArray   *AIFindViewsAt(CGPoint pt, int maxN);   // v27：按坐标精确命中（躲开 hitTest）
static NSDictionary *AIPickTextViaGesture(NSString *kw);  // v23：按文字触发手势，定义在 ~1339 行
static NSDictionary *AIScrollAt(CGPoint pt, double dy, double dx, BOOL anim, int fire);  // v17（v29 定义加 fire，声明同步，治 conflicting types）
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
    // v25：v==nil 的语义是「要 window 坐标」。原来直接返回 aiPoint，
    // 但 aiPoint 是相对 aiView 的 —— RN 的 RCTTouchHandler 正是用
    // locationInView:nil 取 window 坐标做 hit-test 的，会算错整个点击位置。
    if (!v) {
        if (self.aiView) return [self.aiView convertPoint:self.aiPoint toView:nil];
        return self.aiPoint;
    }
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
// v26：UIKit 的手势分发是真从 event 里取「与本手势关联的那组触摸」的
//      （UIWindow.sendEvent: → _gestureRecognizersForEvent → touchesForGestureRecognizer:）。
//      少了这条，伪造事件在 window 层分发时手势拿不到任何 touch，页面自然没反应。
- (NSSet *)touchesForGestureRecognizer:(UIGestureRecognizer *)g { return self.aiTouches; }
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
// v25：gdtap —— 把触摸【直接喂给手势识别器】
//
//   为什么需要它：快手任务中心是 React Native 渲染的。
//   chain 显示整条父链上只有 RCTRootContentView 挂着 RCTTouchHandler，
//   而「立即签到」按钮本身是 RCTView / RCTTextView，既不是 UIControl，
//   也不自带手势 —— 点击全靠 RCTTouchHandler 收到触摸后转发给 JS。
//
//   两条老路都进不了它的门：
//     · sendEvent（tap）      —— UIKit 分发伪造事件实测不路由（微信上早已判死）
//     · 喂给 hitTest 命中的子 view —— 手势挂在 9 层之上的祖先，子 view 收不到
//
//   所以：沿父链找到第一个挂着手势的 view，用 AIFakeTouch 直接调
//   `-[UIGestureRecognizer touchesBegan/Moved/Ended:]`。
//   UIGestureRecognizerSubclass.h 里这几个方法是公开的，子类化时本来就要重写。
// ---------------------------------------------------------------------------
// 参数：
//   tvMode  触摸点的「归属 view」怎么选（RN 会拿 touch.view 去找 reactTag）
//           0 = 手势所在的祖先 view（v25 行为）
//           1 = 父链上第一个 RCT* 类 view（RN 页面推荐）★默认
//           2 = hitTest 命中的那个 view
//   mv     是否在 began / ended 之间插一拍 moved（默认 0，RN 的 Pressability
//          见到 move 可能判定为滑动而取消点击）
//   delayMs began 与 ended 之间的真实间隔（默认 60ms，让时间戳像真点击）
static NSDictionary *AIGestureDirectTap(CGPoint pt, int tvMode, int mv, int delayMs) {
    UIWindow *w = AIHostWindow();
    if (!w) return @{@"ok": @NO, @"err": @"无 window"};
    UIView *hit = nil;
    @try { hit = [w hitTest:pt withEvent:nil]; } @catch (id e) {}
    if (!hit) return @{@"ok": @NO, @"err": @"hitTest 未命中"};

    UIView *gv = hit; int up = 0; NSArray *grs = nil;
    while (gv && up < 22) {
        @try {
            if (gv.gestureRecognizers.count) { grs = gv.gestureRecognizers; break; }
        } @catch (id e) {}
        gv = gv.superview; up++;
    }
    if (!gv || !grs.count)
        return @{@"ok": @NO, @"err": @"父链 22 层内无手势",
                 @"hit": NSStringFromClass(hit.class)};

    // —— 选「触摸归属 view」——
    UIView *tv = nil; int tvUp = -1;
    if (tvMode == 2) { tv = hit; tvUp = 0; }
    else if (tvMode == 1) {
        UIView *c = hit; int i = 0;
        while (c && i <= up) {
            @try { if ([NSStringFromClass(c.class) hasPrefix:@"RCT"]) { tv = c; tvUp = i; break; } } @catch (id e) {}
            c = c.superview; i++;
        }
    }
    if (!tv) { tv = gv; tvUp = up; }

    AIFakeTouch *t = [AIFakeTouch new];
    t.aiView = tv; t.aiWindow = w;
    // 坐标统一存【相对 tv】；locationInView:nil 会自动换算回 window 坐标（v25 修的那条）
    t.aiPoint = [w convertPoint:pt toView:tv];
    t.aiTime  = [[NSDate date] timeIntervalSince1970];

    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one; ev.aiTime = t.aiTime;

    NSMutableArray *fired = [NSMutableArray array];
    NSMutableArray *errs  = [NSMutableArray array];
    @try {
        t.aiPhase = UITouchPhaseBegan;
        for (UIGestureRecognizer *gr in grs) {
            @try { [gr touchesBegan:one withEvent:ev]; }
            @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"began:%@", e.reason ?: @"?"]]; }
        }
        if (delayMs > 0) usleep((useconds_t)(delayMs * 1000));
        if (mv) {
            t.aiPhase = UITouchPhaseMoved;
            for (UIGestureRecognizer *gr in grs) {
                @try { [gr touchesMoved:one withEvent:ev]; }
                @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"moved:%@", e.reason ?: @"?"]]; }
            }
        }
        t.aiTime = [[NSDate date] timeIntervalSince1970];   // ended 要有更晚的时间戳
        ev.aiTime = t.aiTime;
        t.aiPhase = UITouchPhaseEnded;
        for (UIGestureRecognizer *gr in grs) {
            @try {
                [gr touchesEnded:one withEvent:ev];
                [fired addObject:[NSString stringWithFormat:@"%@|state=%ld",
                                  NSStringFromClass(gr.class), (long)gr.state]];
            }
            @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"ended:%@", e.reason ?: @"?"]]; }
        }
    } @catch (NSException *ex) {
        return @{@"ok": @NO, @"err": ex.reason ?: @"手势分发异常"};
    }
    // 兜底：有些控件自己在 touchesEnded: 里处理，把手势所在 view 也喂一遍
    @try {
        t.aiPhase = UITouchPhaseBegan; [gv touchesBegan:one withEvent:ev];
        t.aiPhase = UITouchPhaseEnded; [gv touchesEnded:one withEvent:ev];
    } @catch (id e) {}

    NSMutableDictionary *d = [@{@"ok": @YES,
                                @"gv": NSStringFromClass(gv.class), @"up": @(up),
                                @"tv": NSStringFromClass(tv.class), @"tvUp": @(tvUp),
                                @"hit": NSStringFromClass(hit.class), @"grs": fired,
                                @"n": @(grs.count), @"pt": NSStringFromCGPoint([w convertPoint:pt toView:tv])} mutableCopy];
    if (errs.count) d[@"errs"] = errs;
    return d;
}

// ---------------------------------------------------------------------------
// v27：find / rntap —— 不问 hitTest，按坐标在整棵树里「精确命中」
//
//   卡了好几版的真实原因：任务中心是 RN 页，(341,293) 的 hitTest 命中的是
//   0,0,390,844 的【全屏 RCTView】（RN 根节点），而真正的按钮「立即签到」
//   是 RCTTextView（reactTag=599…），它压根不在 hitTest 的返回链上。
//
//   RN 的点击派发拿的是 touch.view 的 reactTag（就是 view.tag）：
//   tag 传成了根节点，JS 侧从根开始找 responder，找不到挂 Pressability 的
//   按钮 —— 所以手势 state 都变成 3（recognized）了，业务纹丝不动。
//
//   v27 换个找法：整棵树扫一遍，把所有「框里包含这个点」的 view 都捞出来，
//   按面积从小到大排，最小的那个就是按钮本体，用它的 tag 去喂手势。
// ---------------------------------------------------------------------------
static NSArray *AIFindViewsAt(CGPoint pt, int maxN) {
    UIWindow *w = AIHostWindow();
    if (!w) return @[];
    CGFloat scr = w.bounds.size.width * w.bounds.size.height;
    if (scr <= 0) scr = 390 * 844;
    NSMutableArray *out = [NSMutableArray array];
    NSMutableArray *stack = [NSMutableArray arrayWithObject:w];
    int budget = 6000;                       // 快手树很大，扫太多会卡主线程
    while (stack.count && budget > 0) {
        UIView *v = stack.lastObject; [stack removeLastObject]; budget--;
        if (![v isKindOfClass:[UIView class]]) continue;
        CGRect r = CGRectZero; BOOL ok = NO;
        @try { r = [v convertRect:v.bounds toView:nil]; ok = YES; } @catch (id e) {}
        if (!ok || CGRectIsNull(r) || r.size.width <= 0 || r.size.height <= 0) continue;
        CGFloat area = r.size.width * r.size.height;
        if (area >= scr * 0.6) {             // 全屏的不算「精确目标」
            @try { for (UIView *c in v.subviews) [stack addObject:c]; } @catch (id e) {}
            continue;
        }
        if (CGRectContainsPoint(r, pt)) {
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"cls"]  = NSStringFromClass(v.class);
            d[@"f"]    = [NSString stringWithFormat:@"%.0f,%.0f %.0fx%.0f",
                          r.origin.x, r.origin.y, r.size.width, r.size.height];
            d[@"area"] = @((int)area);
            @try {
                NSNumber *tg = AISafeObjGet(v, @selector(reactTag));
                if (![tg isKindOfClass:[NSNumber class]]) tg = @(v.tag);
                d[@"tag"] = [tg description];
            } @catch (id e) { d[@"tag"] = @(v.tag).description; }
            @try {
                NSString *tx = AIRuntimeTextOf(v);
                if (tx.length) d[@"txt"] = tx.length > 40 ? [tx substringToIndex:40] : tx;
            } @catch (id e) {}
            d[@"v"] = v;                     // 只在进程内用，绝不进 JSON
            [out addObject:d];
        }
        @try { for (UIView *c in v.subviews) [stack addObject:c]; } @catch (id e) {}
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"area"] compare:b[@"area"]];
    }];
    if (maxN > 0 && (int)out.count > maxN) return [out subarrayWithRange:NSMakeRange(0, (NSUInteger)maxN)];
    return out;
}

// 三拍喂手势（began → [moved] → ended），时间戳递增
static void AIFireGRs(NSArray *grs, NSSet *one, AIFakeTouch *t, AIFakeEvent *ev,
                      int mv, int delayMs, NSMutableArray *fired, NSMutableArray *errs) {
    @try {
        t.aiPhase = UITouchPhaseBegan;
        for (UIGestureRecognizer *gr in grs) {
            @try { [gr touchesBegan:one withEvent:ev]; }
            @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"began:%@", e.reason ?: @"?"]]; }
        }
        if (delayMs > 0) usleep((useconds_t)(delayMs * 1000));
        if (mv) {
            t.aiPhase = UITouchPhaseMoved;
            for (UIGestureRecognizer *gr in grs) {
                @try { [gr touchesMoved:one withEvent:ev]; }
                @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"moved:%@", e.reason ?: @"?"]]; }
            }
        }
        t.aiTime  = [[NSDate date] timeIntervalSince1970];   // ended 必须有更晚的时间戳
        ev.aiTime = t.aiTime;
        t.aiPhase = UITouchPhaseEnded;
        for (UIGestureRecognizer *gr in grs) {
            @try {
                [gr touchesEnded:one withEvent:ev];
                [fired addObject:[NSString stringWithFormat:@"%@|state=%ld",
                                  NSStringFromClass(gr.class), (long)gr.state]];
            }
            @catch (NSException *e) { [errs addObject:[NSString stringWithFormat:@"ended:%@", e.reason ?: @"?"]]; }
        }
    } @catch (NSException *ex) { [errs addObject:ex.reason ?: @"?"]; }
}

// v27：rntap —— 用「精确命中的那个 view」的 tag 去喂手势
//   up    从最小候选往上走几层（RN 的 Pressability 常常挂在父容器上）
//   rank  用第几个候选（0=面积最小；同一坐标叠了好几层时可以换）
static NSDictionary *AIRNTap(CGPoint pt, int up, int rank, int delayMs) {
    UIWindow *w = AIHostWindow();
    if (!w) return @{@"ok": @NO, @"err": @"无 window"};
    NSArray *cands = AIFindViewsAt(pt, 24);
    if (!cands.count) return @{@"ok": @NO, @"err": @"该点没有任何非全屏 view 的框包含它"};
    if (rank >= (int)cands.count) rank = (int)cands.count - 1;
    UIView *tv = cands[rank][@"v"];
    if (![tv isKindOfClass:[UIView class]]) return @{@"ok": @NO, @"err": @"候选无效"};
    for (int i = 0; i < up && tv.superview; i++) tv = tv.superview;

    // 找手势：★优先 RCTTouchHandler（RN 的点击只认它）
    //   v27 踩的坑：按钮在 RN 的滚动容器里，沿父链第一个碰到的永远是
    //   UIScrollViewPanGestureRecognizer 那几个滚动手势（实测 state=5 全 failed），
    //   真正管点击的 RCTTouchHandler 挂在更上面的 RCTRootContentView 上。
    //   所以这里先一路扫到顶专门找 RCTTouchHandler，找不到再退回「第一个有手势的」。
    UIView *gv = tv; int up2 = 0; NSArray *grs = nil;
    UIView *scan = tv; int sc = 0;
    while (scan && sc < 26) {
        @try {
            for (UIGestureRecognizer *gr in scan.gestureRecognizers) {
                if ([NSStringFromClass(gr.class) rangeOfString:@"RCTTouchHandler"].length) {
                    gv = scan; grs = scan.gestureRecognizers; up2 = sc; break;
                }
            }
            if (grs) break;
        } @catch (id e) {}
        scan = scan.superview; sc++;
    }
    if (!grs) {
        gv = tv; up2 = 0;
        while (gv && up2 < 24) {
            @try { if (gv.gestureRecognizers.count) { grs = gv.gestureRecognizers; break; } } @catch (id e) {}
            gv = gv.superview; up2++;
        }
    }
    if (!gv || !grs.count)
        return @{@"ok": @NO, @"err": @"父链 26 层内无手势",
                 @"tv": NSStringFromClass(tv.class), @"tag": cands[rank][@"tag"] ?: @"-"};

    AIFakeTouch *t = [AIFakeTouch new];
    t.aiView = tv; t.aiWindow = w;
    t.aiPoint = [w convertPoint:pt toView:tv];
    t.aiTime  = [[NSDate date] timeIntervalSince1970];
    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one; ev.aiTime = t.aiTime;

    NSMutableArray *fired = [NSMutableArray array], *errs = [NSMutableArray array];
    AIFireGRs(grs, one, t, ev, 0, delayMs, fired, errs);
    // 兜底：手势所在 view 自己也喂一遍（有些控件在 touchesEnded: 里收尾）
    @try {
        t.aiPhase = UITouchPhaseBegan; [gv touchesBegan:one withEvent:ev];
        t.aiPhase = UITouchPhaseEnded; [gv touchesEnded:one withEvent:ev];
    } @catch (id e) {}

    NSMutableDictionary *d = [@{@"ok": @YES,
                                @"tv": NSStringFromClass(tv.class),
                                @"tag": cands[rank][@"tag"] ?: @"-",
                                @"f":   cands[rank][@"f"] ?: @"-",
                                @"rank": @(rank), @"up": @(up),
                                @"gv": NSStringFromClass(gv.class), @"gup": @(up2),
                                @"grs": fired, @"ncand": @(cands.count)} mutableCopy];
    if (errs.count) d[@"errs"] = errs;
    return d;
}

// ---------------------------------------------------------------------------
// v28：dismiss —— 一键关掉随机弹窗
//
//   快手这类 App 每走一步都可能蹦出个没见过的弹窗（邀请好友 / 领现金 /
//   开通会员 …），把原本要点的按钮盖住，而且【每次长得都不一样】。
//   靠猜坐标回头再补一个版本，来回注入成本太高。
//
//   所以做成自动的：扫一遍界面文字，按「关掉我」的优先级（关闭 > ✕ >
//   稍后再看 > 取消 > 拒绝 > 返回）挑一个，依次用三条通路点：
//     ① 是 UIControl 就直接 sendActionsForControlEvents（最干净）
//     ② 不是就 rntap（拿它自己的 reactTag 喂 RCTTouchHandler）
//   点了就返回，让云端看界面变化判断成没成。
// ---------------------------------------------------------------------------
static NSDictionary *AIDismiss(void) {
    UIWindow *w = AIHostWindow();
    if (!w) return @{@"ok": @NO, @"err": @"无 window"};
    NSArray *kws = @[@"关闭", @"✕", @"×", @"X", @"稍后再看", @"残忍拒绝", @"下次再说",
                     @"知道了", @"我知道了", @"取消", @"暂不", @"不了", @"跳过", @"返回"];
    CGFloat scr = w.bounds.size.width * w.bounds.size.height;
    if (scr <= 0) scr = 390 * 844;

    NSMutableArray *stack = [NSMutableArray arrayWithObject:w];
    NSMutableArray *hits  = [NSMutableArray array];
    int budget = 6000;
    while (stack.count && budget > 0) {
        UIView *v = stack.lastObject; [stack removeLastObject]; budget--;
        if (![v isKindOfClass:[UIView class]]) continue;
        @try {
            NSString *tx = AIRuntimeTextOf(v);
            if (tx.length && tx.length <= 8) {
                NSString *tt = [tx stringByTrimmingCharactersInSet:
                                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
                for (int i = 0; i < (int)kws.count; i++) {
                    NSString *kw = kws[i];
                    BOOL m = (tt.length <= 2) ? [tt isEqualToString:kw] : [tt containsString:kw];
                    if (!m) continue;
                    CGRect r = [v convertRect:v.bounds toView:nil];
                    CGFloat a = r.size.width * r.size.height;
                    if (r.size.width > 0 && r.size.height > 0 && a < scr * 0.9) {
                        [hits addObject:@{@"kw": kw, @"pri": @(i), @"txt": tt,
                                          @"area": @((int)a),
                                          @"cx": @(r.origin.x + r.size.width  / 2.0),
                                          @"cy": @(r.origin.y + r.size.height / 2.0)}];
                    }
                    break;
                }
            }
        } @catch (id e) {}
        @try { for (UIView *c in v.subviews) [stack addObject:c]; } @catch (id e) {}
    }
    if (!hits.count) return @{@"ok": @NO, @"err": @"界面上没有常见的关闭/取消类文字", @"n": @0};
    [hits sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        if (![a[@"pri"] isEqual:b[@"pri"]]) return [a[@"pri"] compare:b[@"pri"]];
        return [a[@"area"] compare:b[@"area"]];
    }];

    for (int i = 0; i < (int)hits.count && i < 3; i++) {
        NSDictionary *h = hits[i];
        CGPoint pt = CGPointMake([h[@"cx"] floatValue], [h[@"cy"] floatValue]);
        NSString *desc = nil;
        @try {
            if (AITapUIControlAt(pt, &desc))
                return @{@"ok": @YES, @"how": @"tapui", @"kw": h[@"kw"], @"txt": h[@"txt"],
                         @"pt": NSStringFromCGPoint(pt), @"desc": desc ?: @"", @"n": @(hits.count)};
        } @catch (id e) {}
        @try {
            NSDictionary *r2 = AIRNTap(pt, 0, 0, 60);
            if ([r2[@"ok"] boolValue])
                return @{@"ok": @YES, @"how": @"rntap", @"kw": h[@"kw"], @"txt": h[@"txt"],
                         @"pt": NSStringFromCGPoint(pt), @"tag": r2[@"tag"] ?: @"-",
                         @"grs": r2[@"grs"] ?: @[], @"n": @(hits.count)};
        } @catch (id e) {}
    }
    return @{@"ok": @NO, @"err": @"找到关闭类文字但点不动", @"n": @(hits.count),
             @"first": hits[0][@"txt"] ?: @"-"};
}

// ---------------------------------------------------------------------------
// v26：wintap —— 让 UIWindow 自己做一次完整分发
//
//   gdtap 是把触摸直接怼进某个手势，绕过了 UIKit 的整套分发（hitTest →
//   收集链上所有手势 → 逐个喂）。wintap 反过来：伪造一个 event 交给
//   UIWindow.sendEvent:，让 UIKit 按它自己的规矩走一遍。
//
//   能不能成全看 UIWindow 认不认我们这个假 UIEvent —— 它内部读的是
//   touchesForWindow:/touchesForGestureRecognizer:/allTouches 这几个 getter，
//   我们全都重写了（v26 补上了 touchesForGestureRecognizer:）。
//   这条路 v13 在微信上被判死（走的是 UIApplication 层），
//   但 window 层 + 完整 getter 值得再试一次，尤其对付 RN / 自绘 UI。
// ---------------------------------------------------------------------------
static NSDictionary *AIWindowTap(CGPoint pt) {
    UIWindow *w = AIHostWindow();
    if (!w) return @{@"ok": @NO, @"err": @"无 window"};

    AIFakeTouch *t = [AIFakeTouch new];
    t.aiWindow = w; t.aiView = nil;
    t.aiPoint  = pt;                       // 已是 window 坐标
    t.aiTime   = [[NSDate date] timeIntervalSince1970];
    t.aiPhase  = UITouchPhaseBegan;

    AIFakeEvent *ev = [AIFakeEvent new];
    NSSet *one = [NSSet setWithObject:t];
    ev.aiTouches = one; ev.aiTime = t.aiTime;

    int seBefore = gSendEventHits, actBefore = gActionHits;
    NSMutableArray *errs = [NSMutableArray array];

    @try { [w sendEvent:ev]; } @catch (NSException *e) { [errs addObject:[@"began:" stringByAppendingString:e.reason ?: @"?"]]; }
    usleep(60000);
    @try {
        t.aiPhase = UITouchPhaseEnded;
        t.aiTime  = [[NSDate date] timeIntervalSince1970]; ev.aiTime = t.aiTime;
        [w sendEvent:ev];
    } @catch (NSException *e) { [errs addObject:[@"ended:" stringByAppendingString:e.reason ?: @"?"]]; }

    NSMutableDictionary *d = [@{@"ok": @YES,
                                @"pt": NSStringFromCGPoint(pt),
                                @"dse": @(gSendEventHits - seBefore),
                                @"dact": @(gActionHits - actBefore)} mutableCopy];
    if (errs.count) d[@"errs"] = errs;
    return d;
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
    if (!AIBudgetTake() || !AIMemSafe()) return;   // v24：额度 + 内存双阀
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
    if (!v || out.count > 200 || !AIBudgetTake() || !AIMemSafe()) return;   // v24：双阀
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
                                                 [s[@"dy"] doubleValue], [s[@"dx"] doubleValue], YES,
                                                 [s[@"fire"] respondsToSelector:@selector(intValue)] ? [s[@"fire"] intValue] : 0);
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
// v29：安全调用 delegate 的 void 回调（用 NSInvocation，避免 performSelector 的标量/结构体坑）
static BOOL AICallVoid(id target, SEL sel, void *arg1, const char *sig) {
    if (!target || ![target respondsToSelector:sel]) return NO;
    @try {
        NSMethodSignature *ms = [target methodSignatureForSelector:sel];
        if (!ms) return NO;
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:ms];
        inv.selector = sel;
        if (arg1) [inv setArgument:arg1 atIndex:2];
        [inv invokeWithTarget:target];
        return YES;
    } @catch (NSException *e) { return NO; }
}

// v29：改完 contentOffset 后，手动把「分页回调」喂给 delegate。
// 关键：setContentOffset:animated: 只触发 scrollViewDidEndScrollingAnimation:，
//       不触发 scrollViewDidEndDecelerating: —— 而快手的分页/切播放器逻辑就在 decelerating 里。
//       所以只改 offset 会出现「列表 cell 数据换了、画面还是原来那条」的鬼现象。
static NSArray *AIFirePaging(UIScrollView *sv, int mode) {
    if (!sv) return @[];
    id del = nil;
    @try { del = sv.delegate; } @catch (NSException *e) {}
    if (!del) return @[@"no-delegate"];
    NSMutableArray *fired = [NSMutableArray array];

    SEL s_begin = @selector(scrollViewWillBeginDragging:);
    SEL s_scroll = @selector(scrollViewDidScroll:);
    SEL s_enddrag = @selector(scrollViewDidEndDragging:willDecelerate:);
    SEL s_decel  = @selector(scrollViewDidEndDecelerating:);

    if (mode == 2) {  // 只补最后一拍
        if (AICallVoid(del, s_decel, &sv, NULL)) [fired addObject:@"decel"];
        return fired;
    }
    // mode 1：完整减速序列 —— 模拟一根真实手指的减速滑行
    if (AICallVoid(del, s_begin, &sv, NULL)) [fired addObject:@"begin"];
    for (int i = 0; i < 6; i++) {          // 中途若干次 didScroll，App 才有"正在滑"的观感
        if (AICallVoid(del, s_scroll, &sv, NULL)) { if (i == 0) [fired addObject:@"didScroll"]; }
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.016]];
    }
    if ([del respondsToSelector:s_enddrag]) {
        @try {
            NSMethodSignature *ms = [del methodSignatureForSelector:s_enddrag];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:ms];
            inv.selector = s_enddrag;
            [inv setArgument:&sv atIndex:2];
            BOOL yes = YES;
            [inv setArgument:&yes atIndex:3];
            [inv invokeWithTarget:del];
            [fired addObject:@"endDrag"];
        } @catch (NSException *e) {}
    }
    if (AICallVoid(del, s_decel, &sv, NULL)) [fired addObject:@"decel"];
    return fired;
}

static NSDictionary *AIScrollAt(CGPoint pt, double dy, double dx, BOOL anim, int fire) {
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
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithDictionary:
        @{@"ok": @YES, @"sv": NSStringFromClass(sv.class), @"up": @(up),
          @"hit": hit ? NSStringFromClass(hit.class) : @"nil",
          @"before": NSStringFromCGPoint(before),
          @"after":  NSStringFromCGPoint(after),
          @"moved":  @(after.y - before.y),
          @"contentSize": NSStringFromCGSize(sv.contentSize),
          @"frame":  NSStringFromCGRect(sv.bounds)}];
    // v29：诊断信息 —— 分页到底有没有被 App 接管
    id del = nil; @try { del = sv.delegate; } @catch (NSException *e) {}
    out[@"delegate"] = del ? NSStringFromClass([del class]) : @"nil";
    out[@"paging"]   = @(sv.pagingEnabled);
    if ([sv isKindOfClass:[UITableView class]]) {
        UITableView *tv = (UITableView *)sv;
        out[@"visRows"] = @([tv indexPathsForVisibleRows].count);
    }
    if (fire > 0) {
        NSArray *fired = AIFirePaging(sv, fire);
        out[@"fired"] = fired;
        // 再等一拍，让 App 有时间换播放器
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
        CGPoint now = sv.contentOffset;
        out[@"offsetAfterFire"] = NSStringFromCGPoint(now);
        if ([sv isKindOfClass:[UITableView class]])
            out[@"visRowsAfter"] = @([(UITableView *)sv indexPathsForVisibleRows].count);
    }
    return out;
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
// 9b. 屏幕识字（Vision OCR）—— v38，会话A
// ---------------------------------------------------------------------------
// 为什么加它：视图树（tree）对自绘控件 / RN / Flutter / 游戏 UI 基本读不到字，
// 但**人眼看到的字**一定能被 Vision 读到。这是「对话即操作手机」最缺的一块通用能力。
//
// 参数不是猜的，是 HLProbe 在真机（iPhone / iOS 16.1.2）逐项实测出来的，别改：
//   • recognitionLevel = Accurate
//   • recognitionLanguages = @[@"zh-Hans", @"en-US"]   ★必须显式写★
//     用「自动语言包」时「微信」被认成「EXtE」，中文全废。
//   • usesLanguageCorrection = NO                      ★必须关★
//     开了语言纠正，中文会被"纠正"成乱码。
//   • revision 用默认（真机实测 = 3；accurate+rev3 支持 14 种语言含 zh-Hans）
// 同一屏实测：正确参数 28 条/777ms，「微信」「微信支付」conf=1.00；
//            fast 档「微信支付」变「,41-*lt」；自动语言包「微信」变「EXtE」。
//
// 坐标换算（★坑★）：Vision 的 boundingBox 是【归一化、原点左下】，UIKit 原点左上。
//   y_ui = (1 - y_vn - h) * H
// 真机锚点实测：屏顶文字实际 y=44 → 不翻转算 777(Δ733)，翻转算 56(Δ12)。
// 注意别拿屏幕中部的文字当锚点：y≈H/2 时翻转前后只差 1~2pt，完全没区分力
// （v7 就是被中部锚点的「Δ51 vs Δ54」骗得差点判反）。

// 图像平均亮度（0-255，-1=取不到）：判断截图是不是黑图
static int AIImageLuma(UIImage *im) {
    if (!im) return -1;
    CGImageRef cg = im.CGImage;
    if (!cg) return -1;
    static const int N = 16;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    if (!cs) return -1;
    uint8_t *buf = (uint8_t *)calloc((size_t)N * N * 4, 1);
    if (!buf) { CGColorSpaceRelease(cs); return -1; }
    CGContextRef ctx = CGBitmapContextCreate(buf, N, N, 8, N * 4, cs,
                                             kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(cs);
    if (!ctx) { free(buf); return -1; }
    CGContextSetInterpolationQuality(ctx, kCGInterpolationLow);
    CGContextDrawImage(ctx, CGRectMake(0, 0, N, N), cg);
    CGContextRelease(ctx);
    long sum = 0;
    for (int i = 0; i < N * N; i++) {
        int r = buf[i*4], g = buf[i*4+1], b = buf[i*4+2];
        sum += (r * 299 + g * 587 + b * 114) / 1000;
    }
    free(buf);
    return (int)(sum / (N * N));
}

// 挑一张「不是黑图」的截图：黑图是老毛病（多半截到我们自己那层 alert 窗口），
// 这里按策略顺序试，第一个亮够的就用，顺便把用的是哪条通道回报上去。
static NSDictionary *AIOCRShot(void) {
    static const int order[] = {3, 4, 2, 1};
    static const char *nm[] = {"hierarchy", "layer", "UICreateScreen", "UIGetScreen"};
    for (int i = 0; i < 4; i++) {
        UIImage *im = nil;
        @try {
            switch (order[i]) {
                case 3: im = AIShot_Hierarchy(); break;
                case 4: im = AIShot_Layer();     break;
                case 2: im = AIShot_Private2();  break;
                case 1: im = AIShot_Private1();  break;
            }
        } @catch (id e) { im = nil; }
        if (!im || im.size.width < 2) continue;
        int luma = AIImageLuma(im);
        AILog(@"  [ocr] 截图[%s] %.0fx%.0f luma=%d", nm[i], im.size.width, im.size.height, luma);
        if (luma >= 6) {
            return @{@"im": im, @"how": [NSString stringWithUTF8String:nm[i]], @"luma": @(luma)};
        }
    }
    return nil;
}

// 跑一次 OCR。kw 为空=全量；非空=只留包含 kw 的（不区分大小写）。
// 返回 items 已按「从上到下、从左到右」排好，坐标是 UIKit 点坐标（左上原点）。
static NSDictionary *AIOCRRun(NSString *kw, int limit) {
    double t0 = [[NSDate date] timeIntervalSince1970];
    NSDictionary *sh = AIOCRShot();
    if (!sh) return @{@"ok": @NO, @"err": @"no-shot（四种截图通道全黑或全空）"};
    UIImage *im = sh[@"im"];
    CGImageRef cg = im.CGImage;
    if (!cg) return @{@"ok": @NO, @"err": @"no-cgimage", @"luma": sh[@"luma"]};

    VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
    req.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
    req.recognitionLanguages = @[@"zh-Hans", @"en-US"];
    req.usesLanguageCorrection = NO;
    NSError *err = nil;
    VNImageRequestHandler *h = [[VNImageRequestHandler alloc] initWithCGImage:cg options:@{}];
    BOOL done = NO;
    @try { done = [h performRequests:@[req] error:&err]; } @catch (id e) { done = NO; }
    double cost = ([[NSDate date] timeIntervalSince1970] - t0) * 1000.0;
    if (!done) {
        return @{@"ok": @NO, @"err": err.localizedDescription ?: @"performRequests 失败",
                 @"luma": sh[@"luma"], @"how": sh[@"how"], @"cost": @((int)cost)};
    }

    CGSize scr = [UIScreen mainScreen].bounds.size;
    NSMutableArray *arr = [NSMutableArray array];
    NSArray *obs = req.results ?: @[];
    for (VNRecognizedTextObservation *o in obs) {
        VNRecognizedText *top = [[o topCandidates:1] firstObject];
        if (!top) continue;
        NSString *s = top.string ?: @"";
        if (!s.length) continue;
        if (kw.length && [s rangeOfString:kw options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
        CGRect bb = o.boundingBox;                       // 归一化，原点【左下】
        CGFloat w = bb.size.width  * scr.width;
        CGFloat hh = bb.size.height * scr.height;
        CGFloat x  = bb.origin.x   * scr.width;
        CGFloat y  = (1 - bb.origin.y - bb.size.height) * scr.height;   // ★翻转★
        [arr addObject:@{@"t": s, @"c": @((int)(top.confidence * 100)),
                         @"x": @((int)x), @"y": @((int)y),
                         @"w": @((int)w), @"h": @((int)hh),
                         @"cx": @((int)(x + w / 2)), @"cy": @((int)(y + hh / 2))}];
    }
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        double ay = [a[@"y"] doubleValue], by = [b[@"y"] doubleValue];
        if (fabs(ay - by) > 10) return ay < by ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"x"] doubleValue] < [b[@"x"] doubleValue] ? NSOrderedAscending : NSOrderedDescending;
    }];
    if (limit > 0 && (int)arr.count > limit) [arr removeObjectsInRange:NSMakeRange((NSUInteger)limit, arr.count - (NSUInteger)limit)];

    // 摘要行：一条命令就能看懂屏上有什么，不用在云端拼 JSON
    NSMutableString *sum = [NSMutableString string];
    for (NSDictionary *d in arr) [sum appendFormat:@"%@@(%@,%@) ", d[@"t"], d[@"cx"], d[@"cy"]];
    return @{@"ok": @YES, @"n": @(arr.count), @"cost": @((int)cost),
             @"luma": sh[@"luma"], @"how": sh[@"how"], @"items": arr,
             @"sum": sum.length ? sum : @"(屏上没识别到文字)"};
}

// 按文字找并（可选）点它：这是「说人话就能操作」的落点。
// 点用 tapui（UIControl 路线，真机验证有效）；tapui 没命中再退 sendEvent，
// 但 sendEvent 成功不代表生效（合成触摸常被自绘层吞），所以 how 要如实回报。
static NSDictionary *AIOCRFindTap(NSString *kw, int idx, BOOL doTap) {
    if (!kw.length) return @{@"ok": @NO, @"err": @"缺 s=关键词"};
    NSDictionary *r = AIOCRRun(kw, 0);
    NSArray *items = r[@"items"] ?: @[];
    if (!items.count) {
        return @{@"ok": @NO, @"err": @"没找到这个文字", @"kw": kw,
                 @"luma": r[@"luma"] ?: @(-1), @"how": r[@"how"] ?: @""};
    }
    NSUInteger i = (idx >= 0 && (NSUInteger)idx < items.count) ? (NSUInteger)idx : 0;
    NSDictionary *it = items[i];
    NSMutableDictionary *out = [it mutableCopy];
    out[@"ok"]  = @YES;
    out[@"kw"]  = kw;
    out[@"idx"] = @(i);
    out[@"hit"] = @(items.count);
    out[@"all"] = [items valueForKey:@"t"];
    if (doTap) {
        CGPoint p = CGPointMake([it[@"cx"] doubleValue], [it[@"cy"] doubleValue]);
        NSString *desc = nil;
        BOOL ok = NO; NSString *how = @"none";
        @try { ok = AITapUIControlAt(p, &desc); if (ok) how = @"tapui"; } @catch (id e) {}
        if (!ok) { @try { ok = AIFakeTapAtWindowPoint(p); if (ok) how = @"sendEvent"; } @catch (id e) {} }
        out[@"tapok"] = @(ok);
        out[@"how"]   = how;
        out[@"desc"]  = desc ?: @"";
        AILog(@"  [ocr] vfind 「%@」-> #%lu (%@,%@) tap=%d via %@ %@",
              kw, (unsigned long)i, it[@"cx"], it[@"cy"], ok, how, desc ?: @"");
    }
    return out;
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
// headers 不为空时逐项写入请求头（v51 新增：通用 HTTP 能力的核心）。
//   —— 为什么必须加这个：此前只能设 Host 一个头，发任何第三方接口都缺 Cookie / UA，
//      等于「有网络层但没有头部入口」。快手/哈啰这类需要 Cookie + 设备指纹的接口全废。
//      加字典参数后，旧调用点传 nil 即可，完全向后兼容。
// 返回 YES 表示拿到了响应体；响应体本身通过 *out 返回。
static BOOL AIHttpEx(NSString *urlStr, NSData *body, NSTimeInterval tmo,
                     BOOL trustAny, NSString *host, NSData **out, NSError **errOut,
                     NSInteger *httpCode, NSTimeInterval *ms,
                     NSDictionary *headers) {
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) { if (errOut) *errOut = [NSError errorWithDomain:@"AI" code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"URL 非法"}]; return NO; }
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u
                                                     cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                 timeoutInterval:tmo];
    if (body) { rq.HTTPMethod = @"POST"; rq.HTTPBody = body;
                [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"]; }
    if (host.length) [rq setValue:host forHTTPHeaderField:@"Host"];
    // v51：自定义头。放在 Host 之后，允许调用方覆盖上面设的默认值。
    if ([headers isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in headers) {
            if (![k isKindOfClass:[NSString class]]) continue;
            id v = headers[k];
            if (![v isKindOfClass:[NSString class]]) v = [v description];
            @try { [rq setValue:(NSString *)v forHTTPHeaderField:k]; } @catch (id e) {}
        }
    }

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

// ---------------------------------------------------------------------------
// v24：内存水位阀。
//   闪退还有一种成因是 OOM —— 快手本身是视频流 App，内存水位本来就高，
//   我们再叠一层深度遍历很容易把它顶过 Jetsam 阈值，系统直接杀进程，
//   用户看到的就是「闪退」。所以遍历过程中定期看一眼自己吃了多少内存，
//   超过上限立刻收手。宁可少报几条文字，也不把宿主 App 搞死。
// ---------------------------------------------------------------------------
static int AIMemMB(void) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t n = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t k = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                (task_info_t)&info, &n);
    if (k != KERN_SUCCESS) return 0;
    return (int)(info.resident_size / (1024 * 1024));
}
static BOOL AIMemSafe(void) {
    static int peak = 0;                 // 记录本次命令期间见到的最高水位
    if ((gTextBudget & 0x3F) != 0) return YES;   // 每 64 个 view 才查一次，别自己拖慢
    int m = AIMemMB();
    if (m <= 0) return YES;
    if (m > peak) peak = m;
    return m < 1100;                     // 1.1GB 以上就停手
}
static int AIMemPeak(void) { return AIMemMB(); }

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

// ---------------------------------------------------------------------------
// v24：闪退的真正元凶 —— performSelector 遇上【返回标量】的 getter
//
//   快手 _TKLabel 的属性里混着 isRichText(BOOL)、textLineCount(NSInteger)、
//   labelWidth(CGFloat) 这类返回值不是对象的 getter。
//   `id r = [v performSelector:g]` 拿到的就是一个垃圾整数值当指针用，
//   紧接着的 [r isKindOfClass:] 直接 EXC_BAD_ACCESS。
//   这是 Mach 异常，@try/@catch 抓不住 —— 表现就是 App 当场闪退。
//
//   修法：调用前先问 methodSignature 的返回类型，只接受对象（'@'），
//   并用 NSInvocation 取回返回值。标量 getter 一律跳过，永不调用。
// ---------------------------------------------------------------------------
static id AISafeObjGet(id v, SEL g) {
    if (!v || !g) return nil;
    NSMethodSignature *sig = nil;
    @try { sig = [v methodSignatureForSelector:g]; } @catch (id e) { return nil; }
    if (!sig) return nil;
    const char *rt = sig.methodReturnType;
    if (!rt || !*rt) return nil;
    // 跳过类型修饰符：r(const) n(in) N(inout) o(out) O(bycopy) R(byref) V(oneway)
    const char *p = rt;
    while (*p && strchr("rnNoORV", *p)) p++;
    if (*p != '@') return nil;            // 只接受对象返回；B/i/f/d/{struct}/^v 全部拒绝
    @try {
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.selector = g;
        [inv invokeWithTarget:v];
        __unsafe_unretained id r = nil;
        [inv getReturnValue:&r];
        return r;
    } @catch (id e) { return nil; }
}

// v21：自绘控件（快手 _TKLabel）既不继承 UILabel，也没有 accessibilityLabel，
//      文字藏在自定义属性里。用 runtime 枚举类的属性名，挑名字像「文字」的
//      逐个试探 —— 拿不到就 nil，绝不硬猜。
// v23：属性名单改为按类缓存，不再每个实例重复枚举。
// v24：改用 AISafeObjGet，杜绝标量返回值导致的闪退。
static NSString *AIRuntimeTextOf(id v) {
    if (!v) return nil;
    for (NSString *name in AITextPropNames([v class])) {
        SEL g = NSSelectorFromString(name);
        if (!g || ![v respondsToSelector:g]) continue;
        id r = AISafeObjGet(v, g);
        if (!r) continue;
        @try {
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
            id r = AISafeObjGet(v, g);       // v24：同样只接受对象返回，绝不碰标量 getter
            if (!r) continue;
            @try {
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
    // v24：全部改走 AISafeObjGet。即使是 text / currentTitle 这种「看起来肯定返回
    //      NSString」的方法，自绘类也可能把它实现成返回 BOOL/NSInteger，照样闪退。
    @try {
        id r = AISafeObjGet(v, @selector(text));
        if ([r isKindOfClass:[NSString class]] && [(NSString *)r length]) return (NSString *)r;
        if ([r isKindOfClass:[NSAttributedString class]] && [(NSAttributedString *)r length])
            return [(NSAttributedString *)r string];

        r = AISafeObjGet(v, @selector(attributedText));
        if ([r isKindOfClass:[NSAttributedString class]] && [(NSAttributedString *)r length])
            return [(NSAttributedString *)r string];

        r = AISafeObjGet(v, @selector(currentTitle));
        if ([r isKindOfClass:[NSString class]] && [(NSString *)r length]) return (NSString *)r;

        r = AISafeObjGet(v, @selector(placeholder));
        if ([r isKindOfClass:[NSString class]] && [(NSString *)r length])
            return [NSString stringWithFormat:@"[%@]", r];
    } @catch (id e) {}
    @try { NSString *a = v.accessibilityLabel; if (a.length) return a; } @catch (id e) {}
    @try { NSString *a = v.accessibilityValue; if (a.length) return a; } @catch (id e) {}
    // v24：runtime 试探是最贵也最危险的一步（要真调用对方的方法），
    //      只在「叶子/接近叶子」的 view 上做。文字控件基本都是叶子，
    //      容器类被跳过 —— 触达面从上千个 view 掉到几十个，风险与开销同时降两个量级。
    if (v.subviews.count <= 2) {
        @try { NSString *a = AIRuntimeTextOf(v); if (a.length) return a; } @catch (id e) {}
    }
    return nil;
}

// parentTxt：父 view 已经输出过的文本。容器常把子控件的文字抄到自己的
// accessibilityLabel 上，不去重的话快手这种深树会刷出满屏重复行。
static NSString *AITextListD(UIView *v, int depth, int maxDepth, NSString *parentTxt) {
    NSMutableString *m = [NSMutableString string];
    if (!AIBudgetTake() || !AIMemSafe()) return m;   // v24：额度 + 内存双阀
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

// ---------------------------------------------------------------------------
// v52：签名侦察（sigprobe）—— 纯只读，只枚举/观察，不改 App 任何行为
//
// 背景：v51c 的 http op 能发请求，但快手接口要 __NS_sig3 每请求签名，
//       而快手【不走 NSURLSession】（v49 真机实证）→ 抄不到。
//       所以必须先【侦察】签名藏在哪：① 哪些 ObjC 类像签名器；
//       ② 哪些 C 符号像签名函数；③ 快手请求头到底由谁写。
// 三部分全部只读：枚举类/方法、dlsym 探符号、旁路记录（不阻断不篡改）。
// ---------------------------------------------------------------------------

// ""快手系""类名前缀（KS/KW/Kwai/gif/Yoda/Aegis/nebula）
static NSArray *AIKSPrefixes(void) {
    static NSArray *p = nil;
    if (!p) p = @[@"KS", @"KW", @"Kwai", @"gif", @"Yoda", @"Aegis", @"nebula"];
    return p;
}
static BOOL AIIsKSPrefix(NSString *s) {
    for (NSString *p in AIKSPrefixes()) if ([s hasPrefix:p]) return YES;
    return NO;
}
// 系统 / 三方框架前缀（v52 实测：sign/secur 关键词会把这些全捞进来占满名额）
static NSArray *AISysPrefixes(void) {
    static NSArray *p = nil;
    if (!p) p = @[@"Swift", @"os.", @"_Tt",
                  @"SwiftUI", @"VisualIntelligence", @"GameCenter", @"SiriTTS",
                  @"AuthenticationServices", @"JetEngine", @"Copresence", @"CoreODI",
                  @"Pegasus", @"RxSwift", @"CryptoKit", @"CryptoKitPrivate",
                  @"ktrace", @"gifCoronaMetrics", @"Contacts", @"CoreFoundation"];
    return p;
}
static BOOL AIIsSysClass(NSString *s) {
    for (NSString *p in AISysPrefixes()) if ([s hasPrefix:p]) return YES;
    return NO;
}

// —— ① 扫 ObjC 类：找名字像「签名/安全/加密」的类，列出其方法 ——
// v53：支持自定义关键词 + 排除系统框架噪声。
// 教训（v52 真机）：默认关键词 sign/secur 太宽泛，60 个候选里 33 个是
// Apple 系统框架（SwiftUI/VisualIntelligence/GameCenterUI…），快手自有的
// 网络层类名被噪声挤掉。所以：① 可传自定义关键词；② 可选「只看 App 自有类」。
// ★ v57：NSObject/NSProxy 的固有方法 —— 关键词 "sign" 会误命中
//   `methodSignatureForSelector:`（v56 实测：每个类都有一条，150 个名额瞬间被它占满，
//   真正的 KSLASecurityHandler 排在后面根本没机会被扫到）。必须白名单之外先排掉。
static NSArray *AINoiseMethods(void) {
    static NSArray *a = nil;
    if (!a) a = @[@"methodSignatureForSelector:", @"instanceMethodSignatureForSelector:",
                  @"methodSignatureForSelectorOpt:", @"methodSignatureCache",
                  @"setMethodSignatureCache:", @"methodForSelector:",
                  @"forwardInvocation:", @"forwardingTargetForSelector:",
                  @"doesNotRecognizeSelector:", @"respondsToSelector:",
                  @"conformsToProtocol:", @"isKindOfClass:", @"isMemberOfClass:",
                  @"performSelector:", @"performSelector:withObject:",
                  @"performSelector:withObject:withObject:",
                  @"description", @"debugDescription", @"hash", @"class", @"superclass",
                  @"isEqual:", @"retain", @"release", @"autorelease", @"retainCount",
                  @"copy", @"mutableCopy", @"dealloc", @"zone"];
    return a;
}
static BOOL AIIsNoiseMethod(NSString *m) {
    for (NSString *n in AINoiseMethods()) if ([m isEqualToString:n]) return YES;
    return NO;
}

static NSArray *AIScanSignClasses(NSArray *kwsIn, BOOL appOnly, BOOL methodMode) {
    // ★ v56：新增 methodMode（按**方法名**命中）。
    //   这是被 v55 真机逼出来的：之前只按**类名**匹配关键词，结果
    //   ① appOnly 时"KS 前缀即命中" → 150 个全是 KSXxxProxy/KSXxxProcessor 噪音，关键词被架空；
    //   ② 更要命的是：签名函数几乎不可能在类名里带 sign —— 它多半藏在
    //      KSNetworkManager / KWRequestSerializer 这种**类名不含 sig** 的类里。
    //      只扫类名 = 永远找不到。必须按方法名扫。
    //   methodMode 下只扫快手自有前缀的类（系统类几万个，全扫会卡死轮询线程）。
    NSMutableArray *hits = [NSMutableArray array];
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return hits;
    Class *buf = (Class *)calloc(n, sizeof(Class));
    if (!buf) return hits;
    n = objc_getClassList(buf, n);
    // 默认关键词（未传时的兜底）
    NSArray *kws = (kwsIn.count ? kwsIn : @[@"sign", @"signat", @"security", @"secur", @"crypto",
                                            @"kws", @"nebula", @"encrypt", @"hash", @"hmac", @"token"]);
    for (int i = 0; i < n; i++) {
        Class c = buf[i];
        if (!c) continue;
        const char *cn = class_getName(c);
        if (!cn) continue;
        NSString *name = [NSString stringWithUTF8String:cn];
        if (!name.length) continue;
        if (appOnly) {
            // ★ v53：「快手自有」模式 —— 快手前缀保留，其余的若是系统框架就跳过
            if (!AIIsKSPrefix(name) && AIIsSysClass(name)) continue;
        }
        NSString *low = [name lowercaseString];
        // ★ v56 修正：关键词命中是**必要条件**，前缀不再直接算命中。
        //   （v55 实测：KS 前缀即命中 → 150 个类全是噪音，关键词形同虚设）
        BOOL clsHit = NO;
        for (NSString *k in kws) { if ([low rangeOfString:k].location != NSNotFound) { clsHit = YES; break; } }
        if (methodMode && !AIIsKSPrefix(name)) continue;    // 方法模式：只看快手自有类
        // 收集该类的实例方法 + 类方法名（只收名字，不收实现）
        NSMutableArray *ms = [NSMutableArray array];
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(c, &mc);
        for (unsigned int j = 0; j < mc && j < 400; j++) {
            const char *sn = sel_getName(method_getName(ml[j]));
            if (sn) [ms addObject:[NSString stringWithUTF8String:sn]];
        }
        if (ml) free(ml);
        unsigned int cmc = 0;
        Method *cml = class_copyMethodList(object_getClass(c), &cmc);
        for (unsigned int j = 0; j < cmc && j < 200; j++) {
            const char *sn = sel_getName(method_getName(cml[j]));
            if (sn) [ms addObject:[NSString stringWithFormat:@"+%@", [NSString stringWithUTF8String:sn]]];
        }
        if (cml) free(cml);
        // 方法名命中判定
        NSMutableArray *mHit = [NSMutableArray array];
        for (NSString *mn in ms) {
            NSString *raw = [mn hasPrefix:@"+"] ? [mn substringFromIndex:1] : mn;
            if (AIIsNoiseMethod(raw)) continue;                  // ★ v57：排掉固有方法
            NSString *ml2 = [raw lowercaseString];
            for (NSString *k in kws) { if ([ml2 rangeOfString:k].location != NSNotFound) { [mHit addObject:mn]; break; } }
        }
        BOOL hit = clsHit || (methodMode && mHit.count > 0);
        if (!hit) continue;
        NSArray *outM = methodMode ? mHit : ms;
        [hits addObject:@{@"cls": name, @"n": @(outM.count), @"m": outM,
                          @"by": (clsHit ? @"类" : @"方法")}];
        if (hits.count >= 150) break;     // v53：上限 60→150（v52 实测 60 不够，被系统类占满）
    }
    free(buf);
    return hits;
}

// —— ② 探 C 符号：dlsym 找可能算签名的函数 ——
static NSDictionary *AIProbeSignSymbols(void) {
    const char *cands[] = {
        // 常见签名/摘要
        "CC_MD5", "CC_SHA1", "CC_SHA256", "CCHmac", "CCCrypt",
        "MD5", "SHA1", "SHA256", "HMAC",
        // 网络层（快手若走 CFNetwork，这些会有）
        "CFURLConnectionCreateWithProperties", "CFReadStreamCreateForHTTPRequest",
        "CFHTTPMessageCreateRequest", "CFHTTPMessageSetHeaderFieldValue",
        // socket/TLS（自封装栈的迹象）
        "SSLHandshake", "SSLWrite", "SSLRead", "tls_handshake",
        "CFNetworkExecuteLocalProxyServer",
        // 快手可能的自有符号（猜测，命中即惊喜）
        "KWSecuritySign", "kwai_sign", "nebula_sign", "KWSign",
        "NSURLSessionConfiguration",   // 只看符号在不在，不说明快手用
    };
    NSMutableDictionary *r = [NSMutableDictionary dictionary];
    NSMutableArray *found = [NSMutableArray array], *miss = [NSMutableArray array];
    for (int i = 0; i < (int)(sizeof(cands)/sizeof(cands[0])); i++) {
        void *p = dlsym(RTLD_DEFAULT, cands[i]);
        if (p) [found addObject:[NSString stringWithUTF8String:cands[i]]];
        else   [miss  addObject:[NSString stringWithUTF8String:cands[i]]];
    }
    r[@"found"] = found; r[@"miss"] = miss;
    return r;
}

// —— ③ 旁路：hook NSMutableURLRequest 的 header setter，只记录不改 ——
//
//  ★ v55 结构重构（v54 真机逼出来的）：
//    原来 gSigHeaderLog 是「一个头一条记录」的摊平数组 —— 同一个请求的 8~13 个头
//    被拆成 8~13 条碎片，沙箱侧只能按 URL 反聚合；而 URL 又被截到 600 →
//    同一请求的不同头记录里 URL 字符串还可能不一致（快手先设头后 setURL 加参数），
//    反聚合根本对不齐。改成 **以 req 指针为 key 的槽位**：
//      · key 用 OpaqueMemory（纯指针比较，不走 isEqual 深比较，快且不误合并）
//      · value 里强引用 req 本身 → 对象保活 → 地址不会被新对象复用（G87）
//      · 一次 dump 直接拿到 {url, method, body, 全套头} 的完整请求快照
static NSMapTable *gSigReqs = nil;              // (void*)req -> NSMutableDictionary 槽位
static NSMutableArray *gSigOrder = nil;         // 槽位数组（强引用 slot，保证 dump 顺序 = 发生顺序）
static NSObject *gSigLock = nil;                // 专用锁（不能拿 gSigReqs 当锁：它会被重建）
static BOOL gSigHookOn = NO;
static IMP gOrigSetValue = NULL, gOrigAddValue = NULL;

// 截断上限（v53:160 → v54:600 → v55:4000）
//   600 仍然不够：快手业务 URL 实测接近 2000 字符（51 个查询参数）、
//   body 常见 >600（xinhui 搜索那条 608 就是被截后的长度）。
//   「抄不全 = 不能原样重放」—— v54 重放 clock/r 拿到的就是 result=40 缺鉴权。
#define AISIG_TRUNC 4000
#define AISIG_MAXREQ 600          // 最多记 600 个请求对象（每个含全套头，内存可控）

static NSString *AITruncN(NSString *s, NSUInteger n) {
    if (!s) return @"";
    if (n == 0) n = AISIG_TRUNC;
    return (s.length > n) ? [[s substringToIndex:n] stringByAppendingString:@"…⟨TRUNC⟩"] : s;
}
static NSString *AITrunc(NSString *s) { return AITruncN(s, AISIG_TRUNC); }

static NSMutableDictionary *AISigSlotFor(id req, NSString *url) {
    // 必须在 gSigReqs 的锁内调用
    if (!gSigReqs) {
        gSigReqs = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory
                                        valueOptions:NSPointerFunctionsStrongMemory];
    }
    if (!gSigOrder) gSigOrder = [NSMutableArray array];
    NSMutableDictionary *slot = [gSigReqs objectForKey:(id)req];
    if (!slot) {
        if (gSigOrder.count >= AISIG_MAXREQ) return nil;
        slot = [NSMutableDictionary dictionary];
        slot[@"h"] = [NSMutableDictionary dictionary];   // 头
        slot[@"k"] = [NSString stringWithFormat:@"%p", (void *)req];
        slot[@"req"] = req;                              // ★ 强引用保活：防地址复用（G87）
        slot[@"t"] = @((long long)[[NSDate date] timeIntervalSince1970]);
        [gSigReqs setObject:slot forKey:(id)req];
        [gSigOrder addObject:slot];                      // 存 slot 本体，dump 直接按序取
    }
    return slot;
}

static void AISigRecord(id req, NSString *field, NSString *value) {
    if (!gSigHookOn || !field) return;
    // ★ v54：先把 URL 取出来，若是咱们自己的中继流量就直接丢 —— 否则名额
    //   一大半被自己占满（v53 实测：315 条里 78 条是中继），快手真流量只能捡剩的。
    NSString *u0 = @"";
    @try {
        if ([req respondsToSelector:@selector(URL)]) {
            NSURL *uu = [(NSURLRequest *)req URL];
            u0 = uu.absoluteString ?: @"";
        }
    } @catch (id e) {}
    if ([u0 rangeOfString:@"workbuddy.host"].location != NSNotFound) return;   // 中继：丢弃

    if (!gSigLock) gSigLock = [NSObject new];
    @synchronized (gSigLock) {
        NSMutableDictionary *slot = AISigSlotFor(req, u0);
        if (!slot) return;
        // ★ v55：我们自己 replay 发出的请求带 X-AI-Replay 头 → 反手把它从记录里剔掉，
        //   否则重放一次就污染一条，多试几次名额全是我们自己。
        if ([field caseInsensitiveCompare:@"X-AI-Replay"] == NSOrderedSame) {
            [gSigReqs removeObjectForKey:(id)req];
            [gSigOrder removeObjectIdenticalTo:slot];
            return;
        }
        if (u0.length) slot[@"u"] = u0;                       // ★ 存原始完整 URL，dump 时才截
        @try {
            if ([req respondsToSelector:@selector(HTTPMethod)]) {
                NSString *mm = [(NSURLRequest *)req HTTPMethod];
                if (mm.length) slot[@"m"] = mm;
            }
            if ([req respondsToSelector:@selector(HTTPBody)]) {
                NSData *d = [(NSURLRequest *)req HTTPBody];
                if (d.length) {
                    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                    slot[@"b"] = s ?: [NSString stringWithFormat:@"<非UTF8 %lu字节>", (unsigned long)d.length];
                }
            }
            if ([req respondsToSelector:@selector(allHTTPHeaderFields)]) {
                NSDictionary *ah = [(NSURLRequest *)req allHTTPHeaderFields];
                if (ah.count) slot[@"ah"] = ah;               // 兜底：万一漏了某个头
            }
        } @catch (id e) {}
        NSMutableDictionary *h = slot[@"h"];
        h[field] = value ?: @"";
    }
}

// dump 用：把槽位整理成可 JSON 化的字典（此时才截断，截断长度由调用方定）
static NSArray *AISigSnapshot(NSUInteger maxlen) {
    NSMutableArray *out = [NSMutableArray array];
    if (!gSigOrder) return out;
    if (!gSigLock) gSigLock = [NSObject new];
    @synchronized (gSigLock) {
        for (NSMutableDictionary *slot in gSigOrder) {
            NSMutableDictionary *h = [NSMutableDictionary dictionary];
            NSDictionary *src = slot[@"h"];
            NSMutableDictionary *merged = [NSMutableDictionary dictionary];
            if ([slot[@"ah"] isKindOfClass:[NSDictionary class]]) [merged addEntriesFromDictionary:slot[@"ah"]];
            [merged addEntriesFromDictionary:src];      // hook 记的优先
            for (NSString *f in merged) h[f] = AITruncN([merged[f] description], maxlen);
            [out addObject:@{@"k": slot[@"k"] ?: @"",
                             @"u": AITruncN(slot[@"u"], maxlen),
                             @"m": slot[@"m"] ?: @"",
                             @"b": AITruncN(slot[@"b"], maxlen),
                             @"t": slot[@"t"] ?: @0,
                             @"n": @(h.count),
                             @"h": h}];
        }
    }
    return out;
}

static void AISigClear(void) {
    if (gSigReqs) [gSigReqs removeAllObjects];   // 释放对 req 的强引用，内存回落
    [gSigOrder removeAllObjects];
}
static NSUInteger AISigCount(void) { return gSigOrder ? gSigOrder.count : 0; }

static void AIHookSetValue(id self, SEL _cmd, NSString *value, NSString *field) {
    AISigRecord(self, field, value);
    if (gOrigSetValue) ((void (*)(id, SEL, id, id))gOrigSetValue)(self, _cmd, value, field);
}
static void AIHookAddValue(id self, SEL _cmd, NSString *value, NSString *field) {
    AISigRecord(self, field, value);
    if (gOrigAddValue) ((void (*)(id, SEL, id, id))gOrigAddValue)(self, _cmd, value, field);
}

static NSString *AISigHookEnable(void) {
    if (gSigHookOn) return @"已在监听";
    Class c = objc_getClass("NSMutableURLRequest");
    if (!c) return @"找不到 NSMutableURLRequest";
    Method m1 = class_getInstanceMethod(c, @selector(setValue:forHTTPHeaderField:));
    Method m2 = class_getInstanceMethod(c, @selector(addValue:forHTTPHeaderField:));
    if (m1) { gOrigSetValue = method_setImplementation(m1, (IMP)AIHookSetValue); }
    if (m2) { gOrigAddValue = method_setImplementation(m2, (IMP)AIHookAddValue); }
    gSigHookOn = YES;
    return [NSString stringWithFormat:@"已挂 setValue:%@ addValue:%@", m1?@"OK":@"无", m2?@"OK":@"无"];
}

// 统一上报：所有结果都 POST 回中继，我在沙箱里 GET /report?dev=... 就能读到
static void AIReportDict(NSDictionary *d) {
    NSMutableDictionary *m = [d mutableCopy];
    m[@"dev"] = gDevId ?: @"?";
    m[@"ts"]  = @((long long)[[NSDate date] timeIntervalSince1970]);
    NSData *bd = [NSJSONSerialization dataWithJSONObject:m options:0 error:nil];
    if (!bd) return;
    @try {
        // G30（v39 真机确诊）：飞行模式令域名 poll 连败 4 次后 gActiveBase 切 IP 兜底，
        // 轮询带 AITrustDelegate（信任任意证书）活着，回执/心跳 POST 却没带 ——
        // IP 直连证书 CN 不匹配 → -1202「此服务器的证书无效」，一切回执单边全灭，
        // 而看门狗只看轮询 tick（命令还在执行）永不换代，IP 态又无自动回切路径，
        // 只能杀 App。修法：回执与轮询同待遇 —— IP 态同样 trustAny + Host 覆盖回域名。
        BOOL isIP = [(gActiveBase ?: @"") hasPrefix:@"https://4"];
        NSData *out = nil; NSInteger httpCode = 0; NSTimeInterval ms = 0;
        NSError *e = nil;
        AIHttpEx([(gActiveBase ?: gBase) stringByAppendingString:@"/report"], bd, 15.0,
                 isIP, isIP ? @"aa0c466b5cdb559bb.app.workbuddy.host" : nil,
                 &out, &e, &httpCode, &ms, nil);
        if (e || httpCode >= 400) {
            gRepErr++; gLastErrCode = e ? e.code : httpCode;
            gLastErrText = e.localizedDescription
                         ?: [NSString stringWithFormat:@"HTTP %ld", (long)httpCode];
            AILog(@"  ⚠️ 上报失败(%@): %@ (code=%ld)", m[@"op"], gLastErrText, (long)gLastErrCode);
        } else {
            gRepOK++;
        }
        AIHudApply();
    } @catch (id e) {}
}

static NSMutableArray *gUIOffViews = nil;   // v27：被 uioff 剥掉交互的遮挡层，uion 可还原

static void AIExecCmd(NSDictionary *cmd) {
    NSString *op = cmd[@"op"];
    // v36：执行命令也算「活着」。v35 的看门狗只看轮询 tick，而 text 这类命令
    // 一跑就是 30~60s 且在轮询线程内同步执行 —— tick 期间不更新，45s 一到就被
    // 误判 hang 触发换代，积压队列越长换代越频繁，rst 8 次耗尽后自愈瘫痪。
    // 修法：命令一开始就把 tick 打上去（「我在忙，别换我」），单条命令 <45s 就不会再误判。
    gPollTick = [[NSDate date] timeIntervalSince1970];
    if (!op) return;
    // v34：凡是「会让手机发生真实变化」的命令，都点亮罩层（人能看到"AI 正在操作手机"）。
    // 只读类（text/tree/probe/find/rows/status/wins/log/wininfo…）不算，不然读屏也糊一层。
    static NSSet *kTouchOps = nil;
    if (!kTouchOps) kTouchOps = [NSSet setWithObjects:
        @"tapui", @"gtap", @"rntap", @"gdtap", @"wintap", @"tap", @"swipe",
        @"scroll", @"pick", @"picktxt", @"back", @"nav", @"dismiss", @"open",
        @"chain", @"macro", @"task", @"uioff", @"uion", nil];
    if ([kTouchOps containsObject:op]) AIOpMark();
    // v38：ocr —— 整屏识字（会话A 加）。s=只留含该关键词的(可选)，n=最多几条(默认60)
    if ([op isEqualToString:@"ocr"]) {
        NSString *kw = cmd[@"s"] ?: @"";
        int lim = cmd[@"n"] ? [cmd[@"n"] intValue] : 60;
        __block NSDictionary *r = nil;
        AIMainSync(^{ @try { r = AIOCRRun(kw, lim); } @catch (id e) {} });
        NSMutableDictionary *rep = [r mutableCopy] ?: [NSMutableDictionary dictionary];
        rep[@"op"] = @"ocr"; rep[@"s"] = kw;
        AIReportDict(rep);
        AILog(@"  [cmd] ocr s=%@ -> %@ 条 %@ms luma=%@ via %@",
              kw.length ? kw : @"(全部)", r[@"n"] ?: @0, r[@"cost"] ?: @0,
              r[@"luma"] ?: @(-1), r[@"how"] ?: @"-");
        return;
    }
    // v38：vfind —— 按文字找并点它。s=关键词 idx=第几个(默认0) tap=1 则真的点
    if ([op isEqualToString:@"vfind"]) {
        NSString *kw = cmd[@"s"] ?: @"";
        int idx = cmd[@"idx"] ? [cmd[@"idx"] intValue] : 0;
        BOOL tap = cmd[@"tap"] && [cmd[@"tap"] intValue] == 1;
        if (tap) AIOpMark();
        __block NSDictionary *r = nil;
        AIMainSync(^{ @try { r = AIOCRFindTap(kw, idx, tap); } @catch (id e) {} });
        NSMutableDictionary *rep = [r mutableCopy] ?: [NSMutableDictionary dictionary];
        rep[@"op"] = @"vfind";
        AIReportDict(rep);
        return;
    }
    // v27：find —— 列出该点上所有「框里包含它」的非全屏 view（面积升序）
    if ([op isEqualToString:@"find"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        int n = cmd[@"n"] ? [cmd[@"n"] intValue] : 12;
        __block NSArray *arr = nil;
        AIMainSync(^{ @try { arr = AIFindViewsAt(CGPointMake(x, y), n); } @catch (id e) {} });
        NSMutableString *s = [NSMutableString string];
        int i = 0;
        for (NSDictionary *d in (arr ?: @[]))
            [s appendFormat:@"%2d %-26@ %-22@ tag=%-9@ %@\n", i++,
             d[@"cls"], d[@"f"], d[@"tag"] ?: @"-", d[@"txt"] ?: @""];
        if (!s.length) s = [NSMutableString stringWithString:@"(该点没有非全屏 view 的框包含它)"];
        AIReportDict(@{@"op": @"find", @"ok": @YES, @"x": @(x), @"y": @(y), @"text": s});
        AILog(@"  [cmd] find (%.0f,%.0f) -> %d 个", x, y, (int)((arr ?: @[]).count));
        return;
    }
    // v27：rntap —— 拿「精确命中的那个 view」的 reactTag 去喂手势
    if ([op isEqualToString:@"rntap"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        int up = cmd[@"up"]   ? [cmd[@"up"]   intValue] : 0;
        int rk = cmd[@"rank"] ? [cmd[@"rank"] intValue] : 0;
        int dl = cmd[@"d"]    ? [cmd[@"d"]    intValue] : 60;
        __block NSDictionary *res = nil;
        AIMainSync(^{ @try { res = AIRNTap(CGPointMake(x, y), up, rk, dl); } @catch (id e) {} });
        NSMutableDictionary *mm = [(res ?: @{}) mutableCopy];
        mm[@"op"] = @"rntap"; mm[@"x"] = @(x); mm[@"y"] = @(y);
        AIReportDict(mm);
        AILog(@"  [cmd] rntap (%.0f,%.0f) up=%d rank=%d -> tv=%@ tag=%@ grs=%@",
              x, y, up, rk, mm[@"tv"], mm[@"tag"], mm[@"grs"]);
        return;
    }
    // v28：dismiss —— 自动找「关闭/取消/稍后再看/返回」这类文字并点掉
    if ([op isEqualToString:@"dismiss"]) {
        __block NSDictionary *res = nil;
        AIMainSync(^{ @try { res = AIDismiss(); } @catch (id e) {} });
        NSMutableDictionary *mm = [(res ?: @{}) mutableCopy];
        mm[@"op"] = @"dismiss";
        AIReportDict(mm);
        AILog(@"  [cmd] dismiss -> how=%@ kw=%@ pt=%@ err=%@",
              mm[@"how"], mm[@"kw"], mm[@"pt"], mm[@"err"] ?: @"-");
        return;
    }
    // v27：uioff —— 剥遮挡层：把该点 hitTest 命中的 view 的交互关掉（不改外观）
    if ([op isEqualToString:@"uioff"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSString *info = @"";
        AIMainSync(^{
            @try {
                if (!gUIOffViews) gUIOffViews = [NSMutableArray array];
                UIView *h = AIHitAtPoint(CGPointMake(x, y));
                if (h && h.userInteractionEnabled) {
                    h.userInteractionEnabled = NO;
                    [gUIOffViews addObject:h];
                    info = [NSString stringWithFormat:@"已关交互 %@ 框%@",
                            NSStringFromClass(h.class),
                            NSStringFromCGRect([h convertRect:h.bounds toView:nil])];
                } else info = h ? @"该 view 的交互本来就是关的" : @"hitTest 未命中";
            } @catch (id e) { info = @"异常"; }
        });
        AIReportDict(@{@"op": @"uioff", @"ok": @YES, @"x": @(x), @"y": @(y), @"txt": info});
        AILog(@"  [cmd] uioff (%.0f,%.0f) -> %@", x, y, info);
        return;
    }
    if ([op isEqualToString:@"uion"]) {         // v27：把剥掉的交互全部还原
        __block int n = 0;
        AIMainSync(^{
            @try {
                for (UIView *v in gUIOffViews ?: @[]) { v.userInteractionEnabled = YES; n++; }
                [gUIOffViews removeAllObjects];
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"uion", @"ok": @YES, @"n": @(n)});
        return;
    }
    // v25：把手势喂进手势识别器本体 —— RN / 自绘 UI 的点击通路
    if ([op isEqualToString:@"gdtap"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        int tv = cmd[@"tv"] ? [cmd[@"tv"] intValue] : 1;
        int mv = cmd[@"mv"] ? [cmd[@"mv"] intValue] : 0;
        int dl = cmd[@"d"]  ? [cmd[@"d"]  intValue] : 60;
        __block NSDictionary *res = nil;
        AIMainSync(^{ @try { res = AIGestureDirectTap(CGPointMake(x, y), tv, mv, dl); } @catch (id e) {} });
        NSMutableDictionary *mm = [(res ?: @{}) mutableCopy];
        mm[@"op"] = @"gdtap"; mm[@"x"] = @(x); mm[@"y"] = @(y);
        AIReportDict(mm);
        AILog(@"  [cmd] gdtap (%.0f,%.0f) tv=%d -> gv=%@ tv=%@ grs=%@ errs=%@",
              x, y, tv, mm[@"gv"], mm[@"tv"], mm[@"grs"], mm[@"errs"] ?: @"-");
        return;
    }
    if ([op isEqualToString:@"wintap"]) {
        CGFloat x = [cmd[@"x"] floatValue], y = [cmd[@"y"] floatValue];
        __block NSDictionary *res = nil;
        AIMainSync(^{ @try { res = AIWindowTap(CGPointMake(x, y)); } @catch (id e) {} });
        NSMutableDictionary *mm = [(res ?: @{}) mutableCopy];
        mm[@"op"] = @"wintap"; mm[@"x"] = @(x); mm[@"y"] = @(y);
        AIReportDict(mm);
        AILog(@"  [cmd] wintap (%.0f,%.0f) -> dse=%@ dact=%@ errs=%@",
              x, y, mm[@"dse"], mm[@"dact"], mm[@"errs"] ?: @"-");
        return;
    }
    if ([op isEqualToString:@"schemes"]) {
        __block NSString *s = @"";
        AIMainSync(^{
            @try {
                NSArray *types = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
                NSMutableArray *lines = [NSMutableArray array];
                for (NSDictionary *t in types) {
                    NSString *role = t[@"CFBundleTypeRole"] ?: @"?";
                    for (NSString *sc in (t[@"CFBundleURLSchemes"] ?: @[]))
                        [lines addObject:[NSString stringWithFormat:@"%@ (%@)", sc, role]];
                }
                s = lines.count ? [lines componentsJoinedByString:@", "] : @"(无 URL scheme)";
            } @catch (id e) { s = @"读取失败"; }
        });
        AIReportDict(@{@"op": @"schemes", @"ok": @YES, @"text": s});
        return;
    }
    if ([op isEqualToString:@"open"]) {
        NSString *u = cmd[@"url"];
        if (!u.length) { AIReportDict(@{@"op": @"open", @"ok": @NO, @"err": @"缺 url"}); return; }
        NSURL *url = [NSURL URLWithString:u];
        __block BOOL ok = NO;
        AIMainSync(^{
            @try {
                UIApplication *app = [UIApplication sharedApplication];
                if ([app respondsToSelector:@selector(openURL:options:completionHandler:)])
                    [app openURL:url options:@{} completionHandler:^(BOOL r){ ok = r; }];
                else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
                    ok = [app openURL:url];
#pragma clang diagnostic pop
            } @catch (id e) {}
        });
        AIReportDict(@{@"op": @"open", @"ok": @(ok), @"url": u});
        return;
    }
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
    } else if ([op isEqualToString:@"wininfo"]) {
        // v33：三个自建窗口的体检报告。悬浮球「看不见」时先打这一条，
        // 一眼分清是「没建」「没挂 scene」「被藏了」还是「跑到屏外」。
        NSMutableString *s = [NSMutableString string];
        UIWindow *ws[3]   = { gFloatWindow, gOverlayWindow, gHudWindow };
        NSString *ns[3]   = { @"float(球)", @"guard(罩)", @"hud(顶栏)" };
        for (int i = 0; i < 3; i++) {
            UIWindow *w = ws[i];
            if (!w) { [s appendFormat:@"%@ —— 不存在\n", ns[i]]; continue; }
            [s appendFormat:@"%@ hidden=%d scn=%d frame=%.0f,%.0f %.0fx%.0f lv=%.0f subs=%d\n",
                ns[i], w.hidden ? 1 : 0, w.windowScene ? 1 : 0,
                w.frame.origin.x, w.frame.origin.y, w.frame.size.width, w.frame.size.height,
                w.windowLevel, (int)(w.rootViewController.view.subviews.count)];
        }
        AIReportDict(@{@"op": @"wininfo", @"ok": @YES, @"text": s});
    } else if ([op isEqualToString:@"panel"]) {
        // v34：L3 详细面板的开关。之前只能靠点球展开，我没法自动化验证它，
        // 加个命令入口，面板内容也能被脚本巡检。
        BOOL open = cmd[@"on"] ? ([cmd[@"on"] intValue] != 0) : YES;
        dispatch_async(dispatch_get_main_queue(), ^{
            gFloatExpanded = open ? YES : NO;
            gFloatForce = YES; AIFloatApply();
        });
        AIReportDict(@{@"op": @"panel", @"ok": @YES, @"open": @(open ? 1 : 0)});
    } else if ([op isEqualToString:@"recapknow"]) {
        // v42：等价于点回顾卡上的「知道了」。给脚本一个入口，让「收卡 + 之后不再弹」
        // 这条状态机能被自动化验证，而不必依赖真手指去点。
        dispatch_async(dispatch_get_main_queue(), ^{ AIDismissRecap(); });
        AIReportDict(@{@"op": @"recapknow", @"ok": @YES});
    } else if ([op isEqualToString:@"copysteps"]) {
        // v42：等价于点面板上的「复制步骤全文」，回传剪贴板长度供断言。
        // 复用现成的 AIFloatTarget 实例 gFT（若尚未建，就在主线程补一个），
        // 保证走的是和真实按钮**同一条**代码路径，不另起一套逻辑。
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!gFT) gFT = [[AIFloatTarget alloc] init];
            [gFT copySteps:nil];
        });
        __block NSInteger clen = 0;
        AIMainSync(^{ clen = (NSInteger)([UIPasteboard generalPasteboard].string.length); });
        AIReportDict(@{@"op": @"copysteps", @"ok": @YES, @"len": @(clen)});
    } else if ([op isEqualToString:@"flag"]) {
        // v42：通用 flag 读写（edge / reduce / recap 等），让脚本能驱动那些
        // 本来只跟系统设置/触摸挂钩的状态，从而可断言。
        NSString *k = cmd[@"k"] ?: @"";
        if (cmd[@"v"] != nil) AISetFlag(k, [cmd[@"v"] intValue] != 0);
        if ([k isEqualToString:@"reduce"]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                gReduceMotion = ([cmd[@"v"] intValue] != 0);
                gFloatForce = YES; AIFloatApply();
            });
        }
        AIReportDict(@{@"op": @"flag", @"ok": @YES, @"k": k,
                       @"v": @(AIFlag(k, NO) ? 1 : 0)});
    } else if ([op isEqualToString:@"status"]) {
        // v30：自报「我是谁」—— 本 dylib 在手机上的真实路径 + 构建时刻 + op 集。
        // 背景：v28 起存档把「源码版本」当「注入版本」写，导致 v27/v28 之争；
        // 以后 status 一次看清手机跑的到底是什么。
        NSString *libPath = @"?";
        Dl_info di;
        if (dladdr((void *)&AIExecCmd, &di) && di.dli_fname)
            libPath = [NSString stringWithUTF8String:di.dli_fname];
        // v37（G25）：task{}/ui{} 只能在主线程读 —— 轮询线程在这里裸读 gTask*，
        // 主线程 AITaskSet 同时在裸写（copy 后 release 旧值），objc_retain 已释放
        // 对象 = SIGSEGV。所有 gTask* 触碰统一 AIMainSync（与 probe/tapui 同模式）。
        __block NSDictionary *tsk = nil, *ui = nil;
        AIMainSync(^{ tsk = AITaskDict(); ui = AIUiDict(); });
        AIReportDict(@{@"op": @"status", @"ok": @YES, @"ver": kAIVer,
                       @"built": @(__DATE__ " " __TIME__),        // v30：编译器固化的构建时刻
                       @"lib": libPath,                            // v30：注入文件真实路径
                       @"ops": @"wait pick picktxt tapui tap scroll swipe rows tree toast probe http sigprobe "
                               @"back nav find rntap dismiss uioff uion gdtap wintap schemes open "
                               @"shot wins win gtap chain text dump update core ball overlay "
                               @"status log hud task macro diag ocr vfind recapknow copysteps call",
                       @"proc": gProcName, @"bundle": gBundleId, @"pid": @(getpid()),
                       @"tap": @(gBestTap), @"shot": @(gBestShot),
                       @"mon": @(gMonHits), @"se": @(gSendEventHits),
                       @"tvhits": @(gTargetHits), @"act": @(gActionHits),
                       @"mem": @(AIMemMB()),          // v24：常驻内存 MB，判断 OOM 用
                       @"overlay": (gOverlayWindow && !gOverlayWindow.hidden) ? @"on" : @"off",
                       // v30 UI 三层：task{}/ui{} 是唯一状态源（旧字段保留供诊断，不进屏）
                       @"busy": @(gBusy),
                       // v35：G13 看门狗可观测 —— gen=轮询线程第几代 / rst=自愈重启过几次 /
                       //      age=轮询 tick 多少秒没动 / mainLag=主线程卡了多少秒
                       @"wd": @{@"gen": @(gPollGen), @"rst": @(gPollRst),
                                @"age": @((long long)(gPollTick > 0
                                          ? ([[NSDate date] timeIntervalSince1970] - gPollTick) : -1.0)),
                                @"mainLag": @((long long)gMainLag)},
                       @"task": tsk,
                       @"ui":   ui});
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
    } else if ([op isEqualToString:@"task"]) {      // v30：任务态 -> 三层 UI（唯一状态源）
        // v37（G25）竞态修复：整个处理体挪主线程。原实现 gTaskName/gTaskBrief/
        // gTaskStep/gGuardMode 在轮询线程裸写、AITaskSet 在主线程裸写、AITaskDict/
        // AIUiDict 在轮询线程裸读 —— v5 脚本每 8s 一条 task 命令，几分钟必踩中
        // 「主线程 release 旧串 × 轮询线程 objc_retain 旧串」→ SIGSEGV 闪退
        // （.ips 112750：AITaskDict+468 → +[NSDictionary dictionaryWithObjects:
        //   forKeys:count:] → objc_retain+16）。主线程串行 = 无锁消灭竞态。
        // cmd 本身是不可变字典（JSON 反序列化产物），跨线程只读安全。
        // 云端可下发：name / step(动作) / idx / total / ok / state / brief / ev / pin / guard
        NSString *nm  = [cmd[@"name"]  isKindOfClass:[NSString class]] ? cmd[@"name"]  : @"";
        NSString *st  = [cmd[@"step"]  isKindOfClass:[NSString class]] ? cmd[@"step"]  : @"";
        NSString *bf  = [cmd[@"brief"] isKindOfClass:[NSString class]] ? cmd[@"brief"] : nil;
        NSString *stt = [cmd[@"state"] isKindOfClass:[NSString class]] ? cmd[@"state"] : nil;
        NSString *evv = [cmd[@"ev"]    isKindOfClass:[NSString class]] ? cmd[@"ev"]    : nil;
        __block NSDictionary *rep = nil;
        AIMainSync(^{
            NSString *name  = nm, *step = st;
            NSString *brief = bf ?: step;
            int idx   = [cmd[@"idx"] intValue];
            int total = [cmd[@"total"] intValue];
            int ok    = cmd[@"ok"] ? [cmd[@"ok"] intValue] : -1;
            NSString *state = stt ?: ((total > 0) ? @"exec" : @"idle");
            if (cmd[@"guard"]) gGuardMode = [cmd[@"guard"] isEqualToString:@"verify"] ? @"verify" : @"privacy";
            if (cmd[@"pin"])   gGuardPinned = [cmd[@"pin"] boolValue];
            // 结果侧证据进 L3 步骤列表（有 ev 才记，避免把列表刷满）
            if ([evv isKindOfClass:[NSString class]] && [evv length])
                AIStepAdd(state, step.length ? step : (brief.length ? brief : @"步骤"),
                          (total > 0 ? [NSString stringWithFormat:@"%d/%d", idx, total] : @""), evv);
            AITaskSet(name, idx, total, state, ok, brief);
            gTaskStep = step;              // v37：主线程写（原轮询线程裸写，G25 竞态点）
            if (ok >= 0 && total > 0) {
                // 结束回顾卡：只写「原因」，不写标题也不写形状（规划 §8.1）。
                // v42 修：原来这里写成 "✓ 任务完成 · 名字 N 步" / "✕ 任务没跑完 · 卡在第 N 步：xxx"，
                //   而 AIRecapCardView 自己已经有 ✓/■ 大图形 + "任务完成"/"任务没跑完" 标题，
                //   于是同一句话在卡上出现两遍（实测卡面：「■ / 任务没跑完 / ✕ 任务没跑完 · 卡在第 5 步：…」），
                //   且形状还自相矛盾（标题区 ■，正文里 ✕）。现改为只留纯原因，标题与形状交给卡自己渲染。
                gTaskResult = (ok == 1)
                    ? [NSString stringWithFormat:@"%@ %d 步全部完成",
                       (name.length ? name : @"任务"), total]
                    : [NSString stringWithFormat:@"卡在第 %d 步：%@", idx,
                       (step.length ? step : (brief.length ? brief : @"未知原因"))];
                // v42：弹出回顾卡（罩层中央大卡，规划 §8.1「收尾闭环」）。
                // AIGuardShouldShow 已含 gRecapShown，故任务结束 gBusy 归零后罩仍保持显示给卡当容器。
                gRecapShown = YES;
                gRecapDismissed = NO;
            }
            // v42 UI 结构实现：回顾卡要跟着任务结论一起刷新。
            // 不能只靠 AIGuardSync —— 它在「罩已显示」时不会重绘（只在 !window 或 hidden 时才 render），
            // 于是卡的状态变了屏上却还是旧的。这里显式重绘一次。
            AIGuardRender();
            rep = @{@"op": @"task", @"ok": @YES, @"show": @(total > 0),
                    @"text": (total > 0)
                        ? [NSString stringWithFormat:@"%@ %d/%d %@", name, idx, total, brief ?: @""]
                        : @"(空闲)",
                    @"task": AITaskDict(), @"ui": AIUiDict()};
        });
        AIReportDict(rep);
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
        int fire = [cmd[@"fire"] respondsToSelector:@selector(intValue)] ? [cmd[@"fire"] intValue] : 0;
        AIMainSync(^{ @try { d = AIScrollAt(p, dy, dx, anim, fire); } @catch (NSException *e) {} });
        AILog(@"  [cmd] scroll dy=%.0f -> %@", dy, d);
        AIReportDict(@{@"op": @"scroll", @"info": d ?: @{@"err": @"scroll 返回 nil"}});
    } else if ([op isEqualToString:@"http"]) {
        // v51：通用 HTTP 原语 —— 与 tap / scroll / find 平级。
        //
        //  为什么进插件而不是写沙箱脚本：脚本发请求必须手抄 Cookie 与设备指纹，
        //  抄错就失败、过期就失效；而设备内发请求时，Cookie 就在本进程的
        //  NSHTTPCookieStorage 里、UA/egid 天然是真的 —— 这是「通用能力」与
        //  「快手专属胶水」的分界线。
        //
        //  参数：url(必填) / method(默认 GET) / headers(字典) / body(字符串) / tmo(秒)
        //  cookieJar=1 时自动附带全量 Cookie（只发与目标域相关的）。
        NSString *url = cmd[@"url"];
        if (![url isKindOfClass:[NSString class]] || !url.length) {
            AIReportDict(@{@"op": @"http", @"ok": @NO, @"err": @"缺 url"});
            return;
        }
        NSString *method = [cmd[@"method"] isKindOfClass:[NSString class]]
                         ? [cmd[@"method"] uppercaseString] : @"GET";
        NSTimeInterval tmo = cmd[@"tmo"] ? [cmd[@"tmo"] doubleValue] : 15.0;
        if (tmo <= 0 || tmo > 120) tmo = 15.0;

        NSMutableDictionary *hs = [NSMutableDictionary dictionary];
        if ([cmd[@"headers"] isKindOfClass:[NSDictionary class]]) {
            [hs addEntriesFromDictionary:cmd[@"headers"]];
        }
        // cookieJar=1：把本进程 Cookie 带上（快手这类接口的鉴权主体）
        NSInteger nCookie = 0;
        if ([cmd[@"cookieJar"] respondsToSelector:@selector(boolValue)] && [cmd[@"cookieJar"] boolValue]) {
            NSArray<NSHTTPCookie *> *ck = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies];
            NSMutableArray *kv = [NSMutableArray array];
            for (NSHTTPCookie *c in ck) {
                if (!c.name || !c.value) continue;
                // 只发与目标域相关的 cookie，避免把中继域名的凭证也漏出去
                if (c.domain.length > 1 && [url rangeOfString:c.domain options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
                [kv addObject:[NSString stringWithFormat:@"%@=%@", c.name, c.value]];
            }
            nCookie = kv.count;
            if (kv.count && !hs[@"Cookie"] && !hs[@"cookie"]) {
                hs[@"Cookie"] = [kv componentsJoinedByString:@"; "];
            }
        }

        NSData *bodyData = nil;
        if ([cmd[@"body"] isKindOfClass:[NSString class]] && [cmd[@"body"] length]) {
            bodyData = [(NSString *)cmd[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
        }
        if ([method isEqualToString:@"POST"] && !bodyData) bodyData = [NSData data];

        // 不能复用 AIHttpEx 的 body 分支（它会强制 POST + JSON Content-Type），
        // 这里自建请求，把 method / headers / body 完全交给调用方。
        NSURL *u = [NSURL URLWithString:url];
        if (!u) { AIReportDict(@{@"op": @"http", @"ok": @NO, @"err": @"URL 非法"}); return; }
        NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u
                                    cachePolicy:NSURLRequestReloadIgnoringCacheData
                                timeoutInterval:tmo];
        rq.HTTPMethod = method;
        if (bodyData) rq.HTTPBody = bodyData;
        for (NSString *k in hs) {
            id v = hs[k];
            if (![v isKindOfClass:[NSString class]]) v = [v description];
            @try { [rq setValue:(NSString *)v forHTTPHeaderField:k]; } @catch (id ex) {}
        }
        // ★ v62：回执体积上限可调（**KSN1-1**）。
        //
        //  为什么必须加：`http` op 原来把回执硬编码在 20000 字符，
        //  实测 `/homepage/tasks` 响应 **20005 B** → 正好被砍在边界，
        //  拿到的 JSON 尾部不完整（`json.loads` 报 Unterminated string）。
        //  「写接口」的响应往往比读接口更大（签到/宝箱领取带上完整账户快照），
        //  所以这个口子必须先开。
        //
        //  取值语义：`maxlen` 缺省 20000（保持原行为）；<=0 表示不截断（调用方自负体积）。
        //  注意：这条是**回执**上限，不是请求上限；调大只影响回传，不影响请求本身。
        NSUInteger cap = 20000;   // 回执体积上限，避免撑爆中继（v62：可由 cmd.maxlen 覆盖）
        if (cmd[@"maxlen"] != nil) {
            NSInteger ml = [cmd[@"maxlen"] integerValue];
            cap = (ml <= 0) ? 0 : (NSUInteger)ml;   // 0 = 不截断
        }
        __block NSUInteger bcap = cap;
        // ★ v51c：不能在轮询线程上 dispatch_semaphore_wait 死等 ——
        // v51b 实测：一进这个分支，轮询线程被占死，之后连 status/probe 都不再消费，
        // 整条通道瘫掉（lastOp 冻住、beat 还在跳）。改用「异步 + 独立线程」：
        // 请求在后台线程发，回执从那里上报，轮询线程立刻返回继续接下一串。
        __block NSString *bu = url, *bm = method;
        __block NSInteger bnCookie = nCookie;
        NSMutableURLRequest *rqC = [rq copy];
        [NSThread detachNewThreadWithBlock:^{
            @autoreleasepool {
                // ★ 必须 __block：这三者要被内层 completionHandler block 写入
                __block NSData *out = nil; __block NSError *e = nil; __block NSInteger code = 0;
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                NSDate *t0 = [NSDate date];
                NSURLSessionDataTask *t = [[NSURLSession sharedSession]
                    dataTaskWithRequest:rqC
                      completionHandler:^(NSData *dd, NSURLResponse *r, NSError *er) {
                        out = dd; e = er;
                        if ([r isKindOfClass:[NSHTTPURLResponse class]])
                            code = [(NSHTTPURLResponse *)r statusCode];
                        dispatch_semaphore_signal(sem);
                    }];
                [t resume];
                // 后台线程同步等；即使超时也只卡这条 detached 线程，绝不碰轮询线程
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW,
                                        (int64_t)((tmo + 2.0) * NSEC_PER_SEC)));
                NSTimeInterval ms = [[NSDate date] timeIntervalSinceDate:t0];
                NSString *txt = out ? [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] : nil;
                if (!txt && out) txt = [out base64EncodedStringWithOptions:0];
                // ★ v62：截断上限由外层 cap/maxlen 决定（0 = 不截断）。KSN1-1
                if (bcap > 0 && txt.length > bcap) {
                    txt = [[txt substringToIndex:bcap] stringByAppendingString:@"…(截断)"];
                }
                AILog(@"  [cmd] http %@ %@ -> code=%ld %ldB %.0fms cookie=%ld",
                      bm, bu, (long)code, (long)out.length, ms * 1000, (long)bnCookie);
                AIReportDict(@{@"op": @"http", @"ok": @(out != nil && e == nil),
                               @"code": @(code), @"ms": @(ms * 1000),
                               @"len": @(out.length), @"nCookie": @(bnCookie),
                               @"text": txt ?: @"",
                               @"err": e ? e.localizedDescription : @""});
            }
        }];
        // 立刻回一条 ack，让调用方知道命令被受理（真实结果随后异步到达）
        AILog(@"  [cmd] http %@ %@ 已派发（异步）", method, url);
    } else if ([op isEqualToString:@"call"]) {
        // v57：通用 ObjC **类方法**调用（NSInvocation）。
        //
        //  为什么做成通用能力而不是"快手签名专用"：
        //    调任意类方法 = App 无关的通用原语（跟 tap/scroll/find 平级）。
        //    真正 App 专属的是"调哪个类的哪个方法"，那部分留在脚本里。
        //
        //  安全边界（刻意收紧，别搞成万能后门）：
        //    ① 只支持**类方法**（+）—— 实例方法要拿到对象实例，语义太宽，暂不开；
        //    ② 参数只接受 NSString/NSNumber/NSArray/NSDictionary/NSNull，
        //       且个数超过签名声明直接拒绝（避免越界写）；
        //    ③ 返回值只回可 JSON 化的类型，NSData 转 base64，其余回 description；
        //    ④ 全程 @try，异常不炸主线程；耗时记账，调用者自己判断是否超时。
        //
        //  ★ 红线：本 op 本身不做任何读写语义判断 —— 调什么由调用方负责。
        //    调用方必须自己确认目标方法是**纯函数/只读**（例如算签名），
        //    不得调用任何会改业务状态、下单、扣款、上报的方法。
        NSString *cn = [cmd[@"cls"] isKindOfClass:[NSString class]] ? cmd[@"cls"] : @"";
        NSString *sn = [cmd[@"sel"] isKindOfClass:[NSString class]] ? cmd[@"sel"] : @"";
        NSArray *args = [cmd[@"args"] isKindOfClass:[NSArray class]] ? cmd[@"args"] : @[];
        if (!sn.length || (!cn.length && !cmd[@"inst"])) {
            AIReportDict(@{@"op": @"call", @"ok": @NO, @"err": @"缺 cls 或 sel"}); return;
        }
        // ★ v60：**只读单例白名单** —— 解决「单例 + 实例方法」这类最常见的只读形态。
        //
        //  为什么必须开这个口子：`NSHTTPCookieStorage.sharedHTTPCookieStorage.cookies` 是最典型的
        //  「取单例 → 调实例方法」，但 v57 的 call 只认类方法（+），够不着实例方法。
        //  实证：设备 http op 发出的请求 `nCookie: 0`（一个 Cookie 都没带）→ 服务端 result:40
        //  「服务器繁忙」（其实是认不出身份）。要拿到真实鉴权头，就必须能从进程里读 Cookie。
        //
        //  ★ 安全边界（刻意收得极窄，绝不是万能后门）：
        //    ① **只认白名单里的单例**，且单例方法必须无参、返回对象；白名单外的 inst 一律拒绝；
        //    ② 白名单内全是**只读容器/只读偏好**（Cookie 存储、UserDefaults），不含任何业务对象；
        //    ③ 仍然只走 NSInvocation 按真实签名设参（G94 个数必须恰好相等）；
        //    ④ 本 op 仍不做读写语义判断 —— 调用方负责只调只读方法。
        id targetObj = nil;      // 实际被 invoke 的对象（类对象 或 白名单单例）
        NSString *instName = @"";
        BOOL isInstMode = NO;
        if ([cmd[@"inst"] isKindOfClass:[NSString class]] && [(NSString *)cmd[@"inst"] length]) {
            isInstMode = YES;
            NSString *iw = cmd[@"inst"];
            // 白名单：单例方法名 → 该单例所属类（用于校验，避免任意类调任意方法）
            NSDictionary *instWhite = @{
                @"NSHTTPCookieStorage":     @[@"sharedHTTPCookieStorage"],
                @"NSUserDefaults":          @[@"standardUserDefaults"],
                @"NSFileManager":           @[@"defaultManager"],
                @"NSNotificationCenter":    @[@"defaultCenter"],
                @"NSURLCache":              @[@"sharedURLCache"],
                @"NSProcessInfo":           @[@"processInfo"],
            };
            NSString *wantCls = cn.length ? cn : nil;
            if (!wantCls) {
                AIReportDict(@{@"op": @"call", @"ok": @NO,
                               @"err": @"inst 模式必须同时给 cls（用于白名单校验）"}); return;
            }
            NSArray *allowed = instWhite[wantCls];
            if (!allowed || ![allowed containsObject:iw]) {
                AIReportDict(@{@"op": @"call", @"ok": @NO,
                               @"err": [NSString stringWithFormat:@"inst 白名单外：%@.%@（只读单例白名单见 v60 注释）",
                                        wantCls, iw]}); return;
            }
            Class wc = NSClassFromString(wantCls);
            SEL ws = NSSelectorFromString(iw);
            if (!wc || ![wc respondsToSelector:ws]) {
                AIReportDict(@{@"op": @"call", @"ok": @NO,
                               @"err": [NSString stringWithFormat:@"%@ 不响应 %@", wantCls, iw]}); return;
            }
            @try {
                NSMethodSignature *wms = [wc methodSignatureForSelector:ws];
                if ([wms numberOfArguments] != 2) {   // 单例方法必须无参
                    AIReportDict(@{@"op": @"call", @"ok": @NO,
                                   @"err": @"白名单单例方法必须无参"}); return;
                }
                NSInvocation *winv = [NSInvocation invocationWithMethodSignature:wms];
                winv.selector = ws;
                [winv invokeWithTarget:wc];
                __unsafe_unretained id got = nil;
                [winv getReturnValue:&got];
                targetObj = got;
                instName = [NSString stringWithFormat:@"%@.%@", wantCls, iw];
            } @catch (NSException *ex) {
                AIReportDict(@{@"op": @"call", @"ok": @NO,
                               @"err": [NSString stringWithFormat:@"取单例异常 %@", ex.reason]}); return;
            } @catch (id e) {
                AIReportDict(@{@"op": @"call", @"ok": @NO, @"err": @"取单例未知异常"}); return;
            }
            if (!targetObj) {
                AIReportDict(@{@"op": @"call", @"ok": @NO,
                               @"err": [NSString stringWithFormat:@"单例 %@ 返回 nil", instName]}); return;
            }
        }
        Class c = NSClassFromString(cn);
        if (!isInstMode) {
            if (!c) { AIReportDict(@{@"op": @"call", @"ok": @NO,
                                     @"err": [NSString stringWithFormat:@"找不到类 %@", cn]}); return; }
            targetObj = c;
        }
        id invTarget = targetObj;
        if (!invTarget) {
            AIReportDict(@{@"op": @"call", @"ok": @NO, @"err": @"目标对象为空"}); return;
        }
        SEL target = NSSelectorFromString(sn);
        if (![invTarget respondsToSelector:target]) {
            AIReportDict(@{@"op": @"call", @"ok": @NO,
                           @"err": [NSString stringWithFormat:@"%@ 不响应%@ %@",
                                    (instName.length ? instName : cn),
                                    (isInstMode ? @"实例方法" : @"该类方法"), sn]}); return;
        }
        NSMethodSignature *ms = nil;
        @try { ms = [invTarget methodSignatureForSelector:target]; } @catch (id e) {}
        if (!ms) { AIReportDict(@{@"op": @"call", @"ok": @NO, @"err": @"取不到方法签名"}); return; }
        NSUInteger want = [ms numberOfArguments] - 2;      // 减去 self / _cmd
        // ★ v58 probe：只查签名不调用 —— 这是**只读**操作（只读 methodSignatureForSelector）。
        //   为什么必须有：`getArgumentTypeAtIndex:` 要按声明个数逐个设参，
        //   args 少于 want 时后面几个槽是**未初始化内存**，invoke 会按垃圾指针发消息 → 崩溃/未定义。
        //   所以调用方必须先 probe 拿到 want 与各槽类型，再精确构造 args。
        if ([cmd[@"probe"] respondsToSelector:@selector(boolValue)] && [cmd[@"probe"] boolValue]) {
            NSMutableArray *argTypes = [NSMutableArray array];
            for (NSUInteger i = 2; i < [ms numberOfArguments]; i++) {
                const char *t = [ms getArgumentTypeAtIndex:i];
                [argTypes addObject:(t ? [NSString stringWithUTF8String:t] : @"?")];
            }
            const char *rt = [ms methodReturnType];
            AIReportDict(@{@"op": @"call", @"probe": @YES, @"ok": @YES,
                           @"cls": cn, @"sel": sn, @"inst": instName,
                           @"mode": (isInstMode ? @"instance" : @"class"),
                           @"want": @(want), @"argTypes": argTypes,
                           @"retType": (rt ? [NSString stringWithUTF8String:rt] : @"?"),
                           @"hint": @"返回值大时加 pick={\"fields\":[...],\"n\":N,\"maxLen\":M} 设备侧抽取（v61）"});
            return;
        }
        // ★ v58：个数必须**恰好相等**才调 —— 少一个就是拿未初始化内存当参数，多一个已拒绝。
        if (args.count != want) {
            AIReportDict(@{@"op": @"call", @"ok": @NO,
                           @"err": [NSString stringWithFormat:@"参数个数不符：给了 %lu 个 / 方法要 %lu 个（先 probe=1 查签名）",
                                    (unsigned long)args.count, (unsigned long)want]}); return;
        }
        NSDate *t0 = [NSDate date];
        id outVal = nil;
        NSString *errMsg = @"";
        // ★ v59：输出参数（by-reference）支持。Cocoa 惯用法：形如 `xxxPlainText:` 的参数
        //   是**输出**——函数会把算出来的明文 `setString:` 写回你传进去的对象，
        //   所以必须传**可变**容器（NSMutableString/NSMutableArray/NSMutableDictionary）。
        //   传不可变 NSString 会炸：`Attempt to mutate immutable object with setString:`（真机实测）。
        //   语法：参数写成 {"$mstr":"初值"} / {"$marr":[...]} / {"$mdict":{...}} 即自动构造可变容器，
        //   调用后我们把容器的**最终内容**一并回传（out[]），供调用方读输出。
        NSMutableArray *outBoxIdx = [NSMutableArray array];       // 记录哪些槽是输出容器
        NSMutableArray *outBoxObj = [NSMutableArray array];
        @try {
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:ms];
            inv.selector = target;
            for (NSUInteger i = 0; i < args.count; i++) {
                id a = args[i];
                if (a == [NSNull null]) a = nil;
                // ★ v59：可变容器包装（输出参数）
                if ([a isKindOfClass:[NSDictionary class]] && [a count] == 1) {
                    id mk = [(NSDictionary *)a allKeys][0];
                    id mv = [(NSDictionary *)a objectForKey:mk];
                    if ([mk isEqualToString:@"$mstr"]) {
                        id mo = [[NSMutableString alloc] initWithString:([mv isKindOfClass:[NSString class]] ? mv : @"")];
                        if (mo) { a = mo; [outBoxIdx addObject:@(i)]; [outBoxObj addObject:mo]; }
                    } else if ([mk isEqualToString:@"$marr"]) {
                        id mo = [[NSMutableArray alloc] initWithArray:([mv isKindOfClass:[NSArray class]] ? mv : @[])];
                        if (mo) { a = mo; [outBoxIdx addObject:@(i)]; [outBoxObj addObject:mo]; }
                    } else if ([mk isEqualToString:@"$mdict"]) {
                        id mo = [[NSMutableDictionary alloc] initWithDictionary:([mv isKindOfClass:[NSDictionary class]] ? mv : @{})];
                        if (mo) { a = mo; [outBoxIdx addObject:@(i)]; [outBoxObj addObject:mo]; }
                    }
                }
                const char *t = [ms getArgumentTypeAtIndex:i + 2];
                if (t && (t[0] == 'i' || t[0] == 'l' || t[0] == 'q' || t[0] == 'I' || t[0] == 'L' || t[0] == 'Q')) {
                    long long v = [a respondsToSelector:@selector(longLongValue)] ? [a longLongValue] : 0;
                    if (t[0] == 'i') { int vi = (int)v; [inv setArgument:&vi atIndex:i + 2]; }
                    else if (t[0] == 'I') { unsigned int vi = (unsigned int)v; [inv setArgument:&vi atIndex:i + 2]; }
                    else if (t[0] == 'l') { long vi = (long)v; [inv setArgument:&vi atIndex:i + 2]; }
                    else if (t[0] == 'L') { unsigned long vi = (unsigned long)v; [inv setArgument:&vi atIndex:i + 2]; }
                    else if (t[0] == 'q') { long long vi = v; [inv setArgument:&vi atIndex:i + 2]; }
                    else { unsigned long long vi = (unsigned long long)v; [inv setArgument:&vi atIndex:i + 2]; }
                } else if (t && (t[0] == 'f' || t[0] == 'd')) {
                    double v = [a respondsToSelector:@selector(doubleValue)] ? [a doubleValue] : 0.0;
                    if (t[0] == 'f') { float vf = (float)v; [inv setArgument:&vf atIndex:i + 2]; }
                    else { [inv setArgument:&v atIndex:i + 2]; }
                } else if (t && t[0] == 'B') {
                    BOOL v = [a respondsToSelector:@selector(boolValue)] ? [a boolValue] : NO;
                    [inv setArgument:&v atIndex:i + 2];
                } else {
                    [inv setArgument:&a atIndex:i + 2];
                }
            }
            [inv invokeWithTarget:invTarget];
            const char *rt = [ms methodReturnType];
            if (rt && (rt[0] == '@' || rt[0] == '#')) {
                __unsafe_unretained id rv = nil;
                [inv getReturnValue:&rv];
                outVal = rv;
            } else if (rt && rt[0] == 'v') {
                outVal = @"<void>";
            } else {
                // 标量返回值
                if (rt && strcmp(rt, "d") == 0) { double d = 0; [inv getReturnValue:&d]; outVal = @(d); }
                else if (rt && strcmp(rt, "B") == 0) { BOOL b = NO; [inv getReturnValue:&b]; outVal = @(b); }
                else { long long n = 0; [inv getReturnValue:&n]; outVal = @(n); }
            }
        } @catch (NSException *ex) {
            errMsg = [NSString stringWithFormat:@"异常 %@: %@", ex.name, ex.reason];
        } @catch (id e) {
            errMsg = @"未知异常";
        }
        NSTimeInterval ms2 = [[NSDate date] timeIntervalSinceDate:t0];
        // 把返回值整理成可 JSON 化的东西（★ v61：声明提到 pick 之前，两个分支共用）
        id jsonVal = nil; NSString *clsOf = @"";
        // ★ v61：**设备侧就地抽取**（pick）—— 在回传前把大返回值砍成小结果。
        //   为什么：`NSHTTPCookieStorage.cookies` 返回 744 个对象，description 数百 KB，
        //   一旦塞进回执 JSON，POST 就超限丢包，调用方只看到"无回执"（见 v61 头部注释）。
        //   语法（pick 是一个 dict）：
        //     {"onlyArray":1}                  → 只回元素个数 + 类型，不回内容（探规模）
        //     {"n":10}                         → 数组只取前 10 个
        //     {"fields":["name","value"]}      → 每个元素是 dict 时，只投影这几个 key
        //     {"key":"name"}                   → 按该字段去重（配合 fields 用）
        //     {"maxLen":200}                   → 每个字符串值截断到 200 字符
        //     {"keys":["a","b"]}               → 返回值是 dict 时，只取这几个 key
        //   ★ 只读：只做取值/投影/截断，不改动任何对象状态。
        NSDictionary *pick = [cmd[@"pick"] isKindOfClass:[NSDictionary class]] ? cmd[@"pick"] : nil;
        NSUInteger pickN = pick[@"n"] ? [pick[@"n"] unsignedIntegerValue] : 0;   // 0 = 不限
        NSUInteger pickMaxLen = pick[@"maxLen"] ? [pick[@"maxLen"] unsignedIntegerValue] : 0;
        NSArray *pickFields = [pick[@"fields"] isKindOfClass:[NSArray class]] ? pick[@"fields"] : nil;
        NSArray *pickKeys = [pick[@"keys"] isKindOfClass:[NSArray class]] ? pick[@"keys"] : nil;
        NSString *pickKey = [pick[@"key"] isKindOfClass:[NSString class]] ? pick[@"key"] : nil;
        // 小工具：把任意值安全转成"短"字符串
        NSString * (^pickShrink)(id) = ^NSString *(id v) {
            NSString *s = nil;
            if ([v isKindOfClass:[NSString class]]) s = v;
            else if ([v isKindOfClass:[NSNumber class]]) s = [v stringValue];
            else if (v) s = [v description];
            else s = @"";
            s = s ?: @"";
            if (pickMaxLen > 0 && s.length > pickMaxLen)
                s = [[s substringToIndex:pickMaxLen] stringByAppendingString:@"…"];
            return s;
        };
        if (pick && [outVal isKindOfClass:[NSArray class]]) {
            NSArray *arr = (NSArray *)outVal;
            NSUInteger lim = (pickN > 0 && pickN < arr.count) ? pickN : arr.count;
            NSMutableArray *rows = [NSMutableArray arrayWithCapacity:lim];
            for (NSUInteger j = 0; j < lim; j++) {
                id el = arr[j];
                @try {
                    if (pickFields && pickFields.count) {
                        // 元素是 dict → 只投影指定字段（这是 Cookie 场景的主力用法）
                        if ([el isKindOfClass:[NSDictionary class]]) {
                            NSMutableDictionary *one = [NSMutableDictionary dictionary];
                            for (id fk in pickFields) {
                                if (![fk isKindOfClass:[NSString class]]) continue;
                                id fv = [(NSDictionary *)el objectForKey:fk];
                                if (fv) one[fk] = pickShrink(fv);
                            }
                            [rows addObject:one];
                        } else {
                            // 元素是对象 → 用 KVC 取字段（NSHTTPCookie 的 name/value 走这条）
                            NSMutableDictionary *one = [NSMutableDictionary dictionary];
                            for (id fk in pickFields) {
                                if (![fk isKindOfClass:[NSString class]]) continue;
                                id fv = nil;
                                @try { fv = [el valueForKey:fk]; } @catch (id e) { fv = nil; }
                                if (fv) one[fk] = pickShrink(fv);
                            }
                            [rows addObject:one];
                        }
                    } else if (pickKey) {
                        // 只要某字段的值
                        id fv = nil;
                        @try { fv = [el isKindOfClass:[NSDictionary class]] ? [(NSDictionary *)el objectForKey:pickKey]
                                                                          : [el valueForKey:pickKey]; } @catch (id e) {}
                        [rows addObject:pickShrink(fv)];
                    } else {
                        [rows addObject:pickShrink(el)];
                    }
                } @catch (id e) { [rows addObject:@"<err>"]; }
            }
            jsonVal = rows; clsOf = @"NSArray(picked)";
        } else if (pick && [outVal isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *one = [NSMutableDictionary dictionary];
            if (pickKeys && pickKeys.count) {
                for (id k in pickKeys)
                    if ([k isKindOfClass:[NSString class]] && [(NSDictionary *)outVal objectForKey:k])
                        one[k] = pickShrink([(NSDictionary *)outVal objectForKey:k]);
            } else {
                [(NSDictionary *)outVal enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
                    one[[k description]] = pickShrink(v);
                }];
            }
            jsonVal = one; clsOf = @"NSDictionary(picked)";
        } else if (pick && pick[@"onlyArray"] && [outVal isKindOfClass:[NSArray class]]) {
            // 纯计数（其实上面已覆盖，这里保留语义）
            jsonVal = @( [(NSArray *)outVal count] ); clsOf = @"NSArray(count)";
        } else {
        // 把返回值整理成可 JSON 化的东西（jsonVal/clsOf 已在上方声明）
        if ([outVal isKindOfClass:[NSString class]])        { jsonVal = outVal; clsOf = @"NSString"; }
        else if ([outVal isKindOfClass:[NSNumber class]])   { jsonVal = outVal; clsOf = @"NSNumber"; }
        else if ([outVal isKindOfClass:[NSDictionary class]]){ jsonVal = outVal; clsOf = @"NSDictionary"; }
        else if ([outVal isKindOfClass:[NSArray class]])    { jsonVal = outVal; clsOf = @"NSArray"; }
        else if ([outVal isKindOfClass:[NSData class]])     {
            jsonVal = [(NSData *)outVal base64EncodedStringWithOptions:0]; clsOf = @"NSData(base64)";
        }
        else if (outVal) { jsonVal = [outVal description] ?: @""; clsOf = NSStringFromClass([outVal class]); }
        else { jsonVal = @"<nil>"; clsOf = @"nil"; }
        }
        // ★ v62：call 的单串返回上限可调（**KSN1-1**）。
        //
        //  为什么要加：原来硬编码 8000，`_methodDescription` 实测 8005 字符
        //  → 正好被砍（且中继层还有 ~4000 的第二道坎，见 G105）。
        //  挖方法列表/读大字符串时，需要一个能放宽的口子。
        //
        //  取值：`maxlen` 缺省 8000（保持原行为）；<=0 表示不截断。
        NSUInteger strCap = 8000;
        if (cmd[@"maxlen"] != nil) {
            NSInteger ml = [cmd[@"maxlen"] integerValue];
            strCap = (ml <= 0) ? 0 : (NSUInteger)ml;
        }
        if (strCap > 0 && [jsonVal isKindOfClass:[NSString class]]
            && [(NSString *)jsonVal length] > strCap)
            jsonVal = [[(NSString *)jsonVal substringToIndex:strCap] stringByAppendingString:@"…(截断)"];
        // ★ v59：读回输出参数容器的**最终内容**（函数调完后的值 = 它算出来的明文）
        NSMutableArray *outs = [NSMutableArray array];
        for (NSUInteger j = 0; j < outBoxObj.count; j++) {
            id o = outBoxObj[j];
            id v = nil;
            @try {
                if ([o isKindOfClass:[NSString class]])       v = [o copy];   // NSMutableString 调完已变
                else if ([o isKindOfClass:[NSArray class]])   v = [o copy];
                else if ([o isKindOfClass:[NSDictionary class]]) v = [o copy];
            } @catch (id e) {}
            // 统一成可 JSON 化
            if (!v) v = @"";
            else if (![v isKindOfClass:[NSString class]] && ![v isKindOfClass:[NSNumber class]] &&
                     ![v isKindOfClass:[NSArray class]] && ![v isKindOfClass:[NSDictionary class]])
                v = [v description] ?: @"";
            [outs addObject:@{@"i": outBoxIdx[j], @"v": v}];
        }
        AILog(@"  [cmd] call %@ %@%@ -> %@ %.1fms%@", cn, instName, sn, clsOf, ms2 * 1000,
              pick ? @" (picked)" : @"");
        AIReportDict(@{@"op": @"call", @"ok": @(errMsg.length == 0), @"cls": cn, @"sel": sn,
                       @"inst": instName, @"mode": (isInstMode ? @"instance" : @"class"),
                       @"ret": jsonVal ?: @"", @"retCls": clsOf, @"out": outs,
                       @"pick": pick ? @YES : @NO,
                       @"ms": @(ms2 * 1000), @"err": errMsg});
    } else if ([op isEqualToString:@"sigprobe"]) {
        // v53：签名侦察（只读）。子动作 a=：
        // v55 子动作一览（a=）：
        //   scan   → 扫 ObjC 类（可选 k=自定义关键词, app=1 只看快手自有类）+ 探 C 符号
        //   on     → 挂 NSMutableURLRequest 头 setter 旁路
        //   dump   → 读已记录的**请求快照**（all=1 全出；h=域名；path=路径；i=下标；
        //            n=条数；maxlen=截断长度；clear=1 读完清空）
        //   replay → i=下标 取一条，dry=1（默认）只回显完整原文，dry=0 才真发
        //            ★ 真发要过两道红线：写语义关键词黑名单 + 只读接口白名单
        //   off    → 摘钩（不还原实现，只停记录）
        //   status → 看钩子/记录状态
        NSString *a = [cmd[@"a"] isKindOfClass:[NSString class]] ? cmd[@"a"] : @"scan";
        if ([a isEqualToString:@"on"]) {
            NSString *r = AISigHookEnable();
            AILog(@"  [cmd] sigprobe on -> %@", r);
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES, @"how": r,
                           @"note": @"旁路只记录 NSMutableURLRequest 的 setValue/addValue，不改行为"});
        } else if ([a isEqualToString:@"off"]) {
            gSigHookOn = NO;
            AILog(@"  [cmd] sigprobe off");
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES, @"n": @(AISigCount())});
        } else if ([a isEqualToString:@"dump"] || [a isEqualToString:@"replay"]) {
            // ★ v55：dump 出的不再是一条条头碎片，而是 **一个请求一份完整快照**
            //   {k(槽位号), u(完整URL), m(方法), b(完整body), n(头数), h(全套头)}
            //   参数：all=1 全出（默认只出「像签名/业务」的）；h=域名关键字；path=路径关键字；
            //        n=条数（默认 20，注意回执体积）；maxlen=单字段截断长度（默认 4000，0=不截）；
            //        clear=1 读完清空；i=槽位下标 → 只出这一条（配合 maxlen=0 拿全量原文）
            NSUInteger maxlen = [cmd[@"maxlen"] respondsToSelector:@selector(intValue)]
                              ? (NSUInteger)[cmd[@"maxlen"] intValue] : AISIG_TRUNC;
            if ([cmd[@"maxlen"] intValue] == 0 && [cmd[@"maxlen"] isKindOfClass:[NSString class]]
                && [(NSString *)cmd[@"maxlen"] isEqualToString:@"0"]) maxlen = 4000;
            if (![cmd objectForKey:@"maxlen"]) maxlen = AISIG_TRUNC;
            NSArray *snap = AISigSnapshot(maxlen);
            NSString *hostKW = [cmd[@"h"] isKindOfClass:[NSString class]] ? cmd[@"h"] : @"";
            NSString *pathKW = [cmd[@"path"] isKindOfClass:[NSString class]] ? cmd[@"path"] : @"";
            NSUInteger cap = [cmd[@"n"] intValue] ? (NSUInteger)[cmd[@"n"] intValue] : 20;
            NSInteger wantI  = [cmd[@"i"] respondsToSelector:@selector(intValue)] ? [cmd[@"i"] intValue] : -1;

            // ① 过滤：域名 / 路径 / 指定下标
            NSMutableArray *base = [NSMutableArray array];
            for (NSDictionary *e in snap) {
                NSString *u = e[@"u"] ?: @"";
                if (hostKW.length && [u rangeOfString:hostKW options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
                if (pathKW.length && [u rangeOfString:pathKW options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
                [base addObject:e];
            }
            if (wantI >= 0) {
                base = (wantI < (NSInteger)snap.count) ? [NSMutableArray arrayWithObject:snap[wantI]] : [NSMutableArray array];
            }
            // ② 是否只要「像签名」的槽（URL 含 sig/token，或头里有 sig/token/__NS 字段）
            NSMutableArray *sel = [NSMutableArray array];
            BOOL wantAll = [cmd[@"all"] intValue] == 1 || wantI >= 0;
            for (NSDictionary *e in snap) {
                if (![base containsObject:e]) continue;
                if (wantAll) { [sel addObject:e]; continue; }
                NSString *u = e[@"u"] ?: @"";
                BOOL hit = ([u rangeOfString:@"sig"   options:NSCaseInsensitiveSearch].location != NSNotFound
                         || [u rangeOfString:@"token" options:NSCaseInsensitiveSearch].location != NSNotFound);
                if (!hit) {
                    NSDictionary *h = e[@"h"];
                    for (NSString *f in h) {
                        if ([f rangeOfString:@"sig"   options:NSCaseInsensitiveSearch].location != NSNotFound
                         || [f rangeOfString:@"token" options:NSCaseInsensitiveSearch].location != NSNotFound
                         || [f hasPrefix:@"__NS"]) { hit = YES; break; }
                    }
                }
                if (hit) [sel addObject:e];
            }
            NSArray *show = sel.count > cap ? [sel subarrayWithRange:NSMakeRange(sel.count - cap, cap)] : sel;
            // ③ 「出现过的域名」统计 —— 一眼看出这些请求到底属于谁
            NSMutableDictionary *hosts = [NSMutableDictionary dictionary];
            for (NSDictionary *e in snap) {
                NSString *u = e[@"u"] ?: @"";
                NSString *h = @"(无URL)";
                if (u.length > 8) {
                    NSRange r = [u rangeOfString:@"://"];
                    NSUInteger st = (r.location == NSNotFound) ? 0 : r.location + 3;
                    NSString *rest = [u substringFromIndex:MIN(st, u.length - 1)];
                    NSRange sr = [rest rangeOfString:@"/"];
                    NSString *hostPart = (sr.location == NSNotFound) ? rest : [rest substringToIndex:sr.location];
                    NSRange qr = [hostPart rangeOfString:@"?"];
                    if (qr.location != NSNotFound) hostPart = [hostPart substringToIndex:qr.location];
                    if (hostPart.length) h = hostPart;
                }
                hosts[h] = @([hosts[h] intValue] + 1);
            }
            if ([cmd[@"clear"] intValue] == 1) { AISigClear(); }

            // ★ replay：把抄到的请求在设备内原样重放（默认 dry=1，只回显不真发）
            //   红线闸门：dry=0 真发时必须过「只读白名单」，含写语义关键词一律拒绝。
            if ([a isEqualToString:@"replay"]) {
                NSInteger idx = wantI;
                if (idx < 0) idx = (NSInteger)snap.count - 1;      // 默认最后一条
                if (idx < 0 || idx >= (NSInteger)snap.count) {
                    AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @NO,
                                   @"err": [NSString stringWithFormat:@"下标越界 i=%ld / 共 %lu",
                                            (long)idx, (unsigned long)snap.count]});
                    return;
                }
                NSDictionary *e = snap[idx];
                NSString *u = e[@"u"] ?: @"";
                NSString *m = [e[@"m"] length] ? e[@"m"] : @"GET";
                NSString *b = e[@"b"] ?: @"";
                NSDictionary *h = e[@"h"] ?: @{};
                BOOL dry = ![cmd[@"dry"] respondsToSelector:@selector(intValue)] || [cmd[@"dry"] intValue] != 0;
                if (dry) {
                    // 只回显完整原文（maxlen 已按调用方指定，默认 4000）
                    AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES, @"dry": @YES,
                                   @"i": @(idx), @"u": u, @"m": m, @"b": b, @"h": h});
                    return;
                }
                // —— 红线闸门：默认拒绝，只有命中只读白名单才放行 ——
                NSArray *deny = @[@"report", @"claim", @"divide", @"register", @"complete",
                                  @"watch", @"draw", @"lottery", @"award", @"withdraw",
                                  @"exchange", @"submit", @"signin", @"sign_in", @"receive"];
                NSString *low = u.lowercaseString;
                for (NSString *w in deny) {
                    if ([low rangeOfString:w].location != NSNotFound) {
                        AILog(@"  [cmd] sigprobe replay 被红线拒绝：URL 含『%@』", w);
                        AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @NO, @"dry": @NO,
                                       @"err": [NSString stringWithFormat:@"红线拒绝：URL 含写语义关键词『%@』，本 op 只放只读接口", w],
                                       @"u": u});
                        return;
                    }
                }
                NSArray *allow = @[@"/xinhui/", @"/clock/r", @"treasurebox", @"basicinfo",
                                   @"taskpanel", @"search/get", @"/nebula/task/", @"/rest/zt/gp/up/wz"];
                BOOL ok2 = NO;
                for (NSString *w in allow) if ([low rangeOfString:w].location != NSNotFound) { ok2 = YES; break; }
                if (!ok2) {
                    AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @NO, @"dry": @NO,
                                   @"err": @"不在只读白名单内，拒绝真发（可先用 dry=1 看原文，再用 http op 自行判断）",
                                   @"u": u});
                    return;
                }
                // —— 真发（异步，绝不占死轮询线程：G58）——
                NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:u]
                                            cachePolicy:NSURLRequestReloadIgnoringCacheData
                                        timeoutInterval:15.0];
                rq.HTTPMethod = m;
                if (b.length) rq.HTTPBody = [b dataUsingEncoding:NSUTF8StringEncoding];
                for (NSString *f in h) { @try { [rq setValue:[h[f] description] forHTTPHeaderField:f]; } @catch (id ex) {} }
                [rq setValue:@"1" forHTTPHeaderField:@"X-AI-Replay"];   // 自我标记，避免污染记录
                __block NSString *bu = u, *bm = m;
                NSMutableURLRequest *rqC = [rq copy];
                [NSThread detachNewThreadWithBlock:^{
                    @autoreleasepool {
                        __block NSData *out = nil; __block NSError *er = nil; __block NSInteger code = 0;
                        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                        NSDate *t0 = [NSDate date];
                        NSURLSessionDataTask *t = [[NSURLSession sharedSession]
                            dataTaskWithRequest:rqC
                              completionHandler:^(NSData *dd, NSURLResponse *r, NSError *e2) {
                                out = dd; er = e2;
                                if ([r isKindOfClass:[NSHTTPURLResponse class]]) code = [(NSHTTPURLResponse *)r statusCode];
                                dispatch_semaphore_signal(sem);
                            }];
                        [t resume];
                        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(17.0 * NSEC_PER_SEC)));
                        NSTimeInterval ms = [[NSDate date] timeIntervalSinceDate:t0];
                        NSString *txt = out ? [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] : nil;
                        if (!txt && out) txt = [out base64EncodedStringWithOptions:0];
                        if (txt.length > 8000) txt = [[txt substringToIndex:8000] stringByAppendingString:@"…(截断)"];
                        AILog(@"  [cmd] sigprobe replay %@ %@ -> code=%ld %ldB", bm, bu, (long)code, (long)out.length);
                        AIReportDict(@{@"op": @"sigprobe", @"a": @"replay", @"ok": @(out != nil && er == nil),
                                       @"dry": @NO, @"code": @(code), @"ms": @(ms * 1000),
                                       @"len": @(out.length), @"text": txt ?: @"",
                                       @"u": bu, @"m": bm,
                                       @"err": er ? er.localizedDescription : @""});
                    }
                }];
                AILog(@"  [cmd] sigprobe replay %@ %@ 已派发（异步）", m, u);
                return;
            }

            AILog(@"  [cmd] sigprobe dump -> 总 %lu 个请求 / 选出 %lu 个",
                  (unsigned long)snap.count, (unsigned long)sel.count);
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES,
                           @"total": @(snap.count), @"nsel": @(sel.count),
                           @"hosts": hosts, @"items": show,
                           @"cleared": @([cmd[@"clear"] intValue] == 1)});
        } else if ([a isEqualToString:@"cred"]) {
            // ★ v56：导出「会话固定凭据」—— 只提取，不发任何请求。
            //   价值：G86 实测 kas/kaw/qr-xx-kv/Cookie 都是会话固定的，
            //   抄一次就能在沙箱侧复用；只有签名和 X-REQUESTID 是每请求的。
            //   把固定的一次性捞出来存档，省得每次都从 2000 字符的 URL 里人肉挑。
            // ★ v57 修：改成**逐字段取最长 / URL 参数取并集**，不再"取最后一条"。
            //   实测教训：取最后一条拿到的 Cookie 只有 region_ticket（没有 __NSWJ）、
            //   URL 参数只有 2 个电池字段 —— 因为最后一条恰好是埋点请求，凭据比业务请求少。
            //   "抄凭据"要的是**最全**的那份，不是**最新**的那份。
            NSArray *snap = AISigSnapshot(4000);
            NSMutableDictionary *best = [NSMutableDictionary dictionary];
            NSString *bestUrl = @"";
            NSMutableDictionary *qmerge = [NSMutableDictionary dictionary];
            NSDictionary *fmap = @{@"Cookie": @"cookie", @"cookie": @"cookie",
                                   @"User-Agent": @"ua", @"qr-xx-kv": @"qrx",
                                   @"kas": @"kas", @"kaw": @"kaw",
                                   @"Accept": @"accept", @"Accept-Language": @"acceptLang",
                                   @"Content-Type": @"ctype", @"ks-arg-cprs": @"kscprs"};
            NSUInteger nUsed = 0;
            for (NSDictionary *e in snap) {
                NSDictionary *h = e[@"h"] ?: @{};
                BOOL used = NO;
                for (NSString *f in h) {
                    NSString *key = fmap[f];
                    if (!key) continue;
                    NSString *v = h[f];
                    if (![v isKindOfClass:[NSString class]] || !v.length) continue;
                    NSString *cur = best[key];
                    if (!cur || v.length > cur.length) { best[key] = v; used = YES; }
                }
                NSString *u = ([e[@"u"] isKindOfClass:[NSString class]]) ? e[@"u"] : @"";
                if (u.length > bestUrl.length) bestUrl = u;
                NSRange q = [u rangeOfString:@"?"];
                if (q.location != NSNotFound && q.location + 1 < u.length) {
                    NSString *qs = [u substringFromIndex:q.location + 1];
                    for (NSString *kv in [qs componentsSeparatedByString:@"&"]) {
                        NSRange eq = [kv rangeOfString:@"="];
                        if (eq.location == NSNotFound) continue;
                        NSString *k2 = [kv substringToIndex:eq.location];
                        NSString *v2 = [kv substringFromIndex:eq.location + 1];
                        if (k2.length && !qmerge[k2]) qmerge[k2] = v2;   // 先到为准
                    }
                    used = YES;
                }
                if (used) nUsed++;
            }
            NSMutableDictionary *out = [NSMutableDictionary dictionary];
            for (NSString *k in best) out[k] = best[k];
            for (NSString *k in @[@"cookie", @"ua", @"qrx", @"kas", @"kaw", @"accept", @"acceptLang", @"ctype", @"kscprs"])
                if (!out[k]) out[k] = @"";
            out[@"ok"] = @(best.count > 0 || qmerge.count > 0);
            out[@"q"] = qmerge;
            out[@"nq"] = @(qmerge.count);
            out[@"from"] = bestUrl;
            out[@"nReqUsed"] = @(nUsed);
            AILog(@"  [cmd] sigprobe cred -> ok=%@ cookie=%lub 参数%lu个（用了%lu个请求）",
                  out[@"ok"], (unsigned long)[out[@"cookie"] length],
                  (unsigned long)qmerge.count, (unsigned long)nUsed);
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": out[@"ok"],
                           @"cookie": out[@"cookie"] ?: @"", @"ua": out[@"ua"] ?: @"",
                           @"qrx": out[@"qrx"] ?: @"", @"kas": out[@"kas"] ?: @"",
                           @"kaw": out[@"kaw"] ?: @"", @"accept": out[@"accept"] ?: @"",
                           @"acceptLang": out[@"acceptLang"] ?: @"",
                           @"q": out[@"q"] ?: @{}, @"from": out[@"from"] ?: @""});
        } else if ([a isEqualToString:@"status"]) {
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES,
                           @"hooked": @(gSigHookOn), @"n": @(AISigCount())});
        } else {   // scan（默认）
            // v53：可传 k="网络,KS,KW,http"（逗号分隔自定义关键词），app=1 → 只看快手自有类
            NSString *kstr = [cmd[@"k"] isKindOfClass:[NSString class]] ? cmd[@"k"] : @"";
            NSArray *kws = kstr.length ? [kstr componentsSeparatedByString:@","] : @[];
            BOOL appOnly = [cmd[@"app"] intValue] == 1;
            BOOL methodMode = [cmd[@"mm"] intValue] == 1;   // v56：按方法名扫（找签名函数的关键）
            NSArray *cls = AIScanSignClasses(kws, appOnly, methodMode);
            NSDictionary *syms = AIProbeSignSymbols();
            NSMutableString *s = [NSMutableString string];
            [s appendFormat:@"候选 %lu 个（%@）\n", (unsigned long)cls.count, methodMode ? @"按方法名" : @"按类名"];
            for (NSDictionary *c in cls) {
                [s appendFormat:@"  %@  [%@] (%@ 方法)\n", c[@"cls"], c[@"by"] ?: @"?", c[@"n"]];
                NSArray *ms = c[@"m"];
                NSUInteger shown = methodMode ? MIN(ms.count, (NSUInteger)30) : MIN(ms.count, (NSUInteger)12);
                for (NSUInteger i = 0; i < shown; i++) [s appendFormat:@"      %@\n", ms[i]];
                if (ms.count > shown) [s appendFormat:@"      …另 %lu 个\n", (unsigned long)(ms.count - shown)];
            }
            [s appendFormat:@"\n符号命中：%@\n", [syms[@"found"] componentsJoinedByString:@", "]];
            AILog(@"  [cmd] sigprobe scan -> 类 %lu / 符号命中 %lu",
                  (unsigned long)cls.count, (unsigned long)[syms[@"found"] count]);
            AIReportDict(@{@"op": @"sigprobe", @"a": a, @"ok": @YES,
                           @"ncls": @(cls.count),
                           @"classes": cls,
                           @"symFound": syms[@"found"],
                           @"text": s});
        }
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
        @try { AIGuardSync(); } @catch (id e) {}   // v32：罩层每秒自愈，谁偷偷显示都会被拉回真源
        @try { AIFloatSync(); } @catch (id e) {}   // v33：悬浮球每秒自愈，弄丢了 1 秒内拉回来
        @try { AIOpIdleCheck(); } @catch (id e) {} // v34：操作停下 8s 后罩层自动落下
        AIHudTickLoop();
    });
}

static BOOL gNetStarted = NO;
// v16：自适应轮询间隔（刚干完活 -> 0.35s 快轮询；空闲 -> 逐步退回 2.5s）
static double gPollGap = 2.0;
static double gLastBeat = 0;

// v35：轮询循环独立成函数 —— 看门狗要能在不重跑 AINetLoop（裸 TCP 探测 / hello
// 报到 / 起本地服务）的前提下，单独把这一条线程换掉。
static void AIPollLoop(void) {
    int32_t myGen = __sync_add_and_fetch((int32_t *)&gPollGen, 1);
    gPollTick = [[NSDate date] timeIntervalSince1970];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        int failRun = 0;
        while (1) {
            @autoreleasepool {
                @try {
                    // 被看门狗起的新一代取代了 —— 别再和新线程抢同一个命令队列
                    if (myGen != gPollGen) {
                        AILog(@"  轮询线程第%d代退出（已由第%d代接管）", myGen, gPollGen);
                        return;
                    }
                    NSString *u = [gActiveBase stringByAppendingFormat:@"/poll?dev=%@", gDevId];
                    NSError *pe = nil; NSData *d = nil;
                    BOOL ok = AIHttpEx(u, nil, 8.0,
                                       [gActiveBase hasPrefix:@"https://4"],   // IP 兜底时才信任任意证书
                                       [gActiveBase hasPrefix:@"https://4"] ? @"aa0c466b5cdb559bb.app.workbuddy.host" : nil,
                                       &d, &pe, NULL, NULL, nil);
                    if (ok) {
                        gPollOK++; failRun = 0;
                        if (gPollOK == 1) {
                            AILog(@"  ✅ 首次轮询成功，已上线 -> %@", gActiveBase);
                            // v32：盖屏已退役（决策②），别再自动糊一层。结论写 log / 诊断区即可。
                            if (NO /*sw1 日志盖屏已退役*/) AIShowOverlay();
                        }
                    } else {
                        gPollErr++; failRun++;
                        gLastErrCode = pe ? pe.code : -999;
                        gLastErrText = pe.localizedDescription;
                        AILog(@"  ⚠️ 轮询失败: %@ (code=%ld)", pe.localizedDescription, (long)gLastErrCode);
                        if ((gPollErr == 1 || gPollErr == 3) && NO /*sw1 日志盖屏已退役*/) AIShowOverlay();  // v32：同上，仅诊断模式
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
                            // v24：积压保护。App 崩掉/被杀时，云端会攒下一堆没消费的指令，
                            //      重开后一次性灌进来 —— 很可能就是当初把它搞崩的那批。
                            // v39（G28）：3 条 → 1 条。事实：13:12 事故里换代后的新代拉到
                            //      积压慢命令（text 30~90s/条）连执行，45s/条必然再触发换代
                            //      → 循环到 rst 耗尽 → 通道瘫死。积压 >3 本身就是异常态
                            //      （正常 poll 间隔 0.35~2.5s 只会攒 1~2 条），过期命令
                            //      执行最后 1 条（最新意图）即可，其余全丢并上报。
                            if (arr.count > 3) {
                                AILog(@"  ⚠️ 积压 %lu 条旧指令，只执行最后 1 条", (unsigned long)arr.count);
                                AIReportDict(@{@"op": @"drop", @"ok": @YES,
                                               @"dropped": @(arr.count - 1), @"total": @(arr.count)});
                                arr = [arr subarrayWithRange:NSMakeRange(arr.count - 1, 1)];
                            }
                            for (NSDictionary *c in arr) { gCmdGot++; AIExecCmd(c); }
                        }
                    }
                    // v16 自适应轮询：刚执行过指令说明"正在被操作"，立刻切快轮询抓紧接下一串；
                    // 空闲下来再逐步退回慢轮询省电。固定 2 秒是之前最大的速度瓶颈。
                    if (gotCmd) gPollGap = 0.35;
                    else        gPollGap = MIN(gPollGap * 1.7, 2.5);
                } @catch (NSException *e) {}
            }
            double now = [[NSDate date] timeIntervalSince1970];
            gPollTick = now;                    // v35：看门狗的判活心跳
            if (myGen != gPollGen) { AILog(@"  轮询线程第%d代退出", myGen); return; }
            // beat 改成按时间（20 秒一次），不再按轮询次数 —— 次数会随 gap 变化而失控
            if (now - gLastBeat > 20) {
                gLastBeat = now;
                AIReportDict(@{@"op": @"beat", @"ver": kAIVer, @"tap": @(gBestTap), @"shot": @(gBestShot),
                               @"tvhits": @(gTargetHits), @"act": @(gActionHits), @"gap": @(gPollGap)});
            }
            [NSThread sleepForTimeInterval:gPollGap];
        }
    });
}

// v35：G13 看门狗。两件事 ——
//   ① 主线程卡死探测：每 5 秒 ping 一下主线程，回不来就记 lag（UI 卡死时命令也执行不了）；
//   ② 轮询线程 hang 自愈：tick 超过 AI_WD_HANG_SEC 没动，就起新一代轮询线程接管。
static void AIWatchdog(void) {
    static BOOL wdStarted = NO;
    if (wdStarted) return;
    wdStarted = YES;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        while (1) {
            [NSThread sleepForTimeInterval:5.0];
            @autoreleasepool {
                double now = [[NSDate date] timeIntervalSince1970];
                @try {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        gMainTick = [[NSDate date] timeIntervalSince1970];
                    });
                    if (gMainTick > 0) {
                        gMainLag = now - gMainTick;
                        if (gMainLag > 60.0)
                            AILog(@"  🩺 主线程 %.0fs 没响应 ping（UI 卡死）", gMainLag);
                    }
                } @catch (NSException *e) {}
                double age = (gPollTick > 0) ? (now - gPollTick) : 0.0;
                if (gPollTick > 0 && age > AI_WD_HANG_SEC && gPollRst < AI_WD_MAX_RETRY) {
                    int n = __sync_add_and_fetch((int32_t *)&gPollRst, 1);
                    AILog(@"  🩺 G13 看门狗：轮询 %.0fs 没动静，判定 hang，起第 %d 代轮询线程",
                          age, gPollGen + 1);
                    // v39（G28）：换代即落盘 —— rst 耗尽/进程被杀后内存日志全丢，
                    // 13:12 事故的现场就是这么丢的。落盘文件下次冷启动仍可读。
                    @try { AIWriteReport(); } @catch (id e) {}
                    AIReportDict(@{@"op": @"wd", @"ok": @YES, @"ver": kAIVer,
                                   @"age": @((long long)age), @"restart": @(n)});
                    @try { AIPollLoop(); } @catch (NSException *e) { AILog(@"  重启轮询异常 %@", e); }
                }
                // v39（G28）：rst 冷却回收 —— 原来 rst 到 8 永久放弃换代（无响应判死刑）。
                // 13:12 事故实锤：换代后新代拉到积压慢命令（text 30~90s/条）又超阈值，
                // 循环换代 8 次 ≈7 分钟耗尽 → 彻底瘫。冷却 = 每 60s 还 1 个预算，
                // 自愈永远在线；真 hang 场景 150s 阈值 + 预算回收依然能救。
                static volatile double gLastRstCool = 0;   // 看门狗单线程访问，static 即可
                if (gPollRst > 0 && now - gLastRstCool > 60) {
                    gLastRstCool = now;
                    __sync_sub_and_fetch((int32_t *)&gPollRst, 1);
                }
            }
        }
    });
}

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
    // v35：轮询本体交给 AIPollLoop（看门狗可单独重启它），看门狗随后启动。
    AIPollLoop();
    AIWatchdog();
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
                   @"tap": @(gBestTap), @"shot": @(gBestShot), @"act": @(gActionHits),
                   @"ver": kAIVer, @"busy": @(gBusy),
                   @"task": AITaskDict(), @"ui": AIUiDict()});
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
                        NO, nil, &out, &e, &code, &ms, nil);
    [s appendFormat:@"①苹果 %@ %@\n", ok1 ? @"✅" : @"❌",
     ok1 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 2) 主链路：域名 HTTPS 轮询
    NSString *base = gActiveBase ?: gBase ?: AIBase();
    e = nil; code = 0; ms = 0;
    BOOL ok2 = AIHttpEx([base stringByAppendingFormat:@"/poll?dev=%@", gDevId], nil, 10.0,
                        NO, nil, &out, &e, &code, &ms, nil);
    [s appendFormat:@"②中继域名 %@ %@\n", ok2 ? @"✅" : @"❌",
     ok2 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 3) 兜底：IP 直连 + 信任证书 + 覆盖 Host（域名 DNS 挂了就靠这条）
    e = nil; code = 0; ms = 0;
    BOOL ok3 = AIHttpEx(@"https://49.233.240.214/poll?dev=DIAG", nil, 10.0,
                        YES, @"aa0c466b5cdb559bb.app.workbuddy.host", &out, &e, &code, &ms, nil);
    [s appendFormat:@"③IP直连 %@ %@\n", ok3 ? @"✅" : @"❌",
     ok3 ? [NSString stringWithFormat:@"%ld %.0fms", (long)code, ms * 1000]
         : [NSString stringWithFormat:@"%ld", (long)e.code]];

    // 4) 上报能不能出去
    e = nil; code = 0; ms = 0;
    NSData *bd = [NSJSONSerialization dataWithJSONObject:@{@"dev": gDevId ?: @"?", @"op": @"diag"} options:0 error:nil];
    BOOL ok4 = AIHttpEx([base stringByAppendingString:@"/report"], bd, 10.0, NO, nil, &out, &e, &code, &ms, nil);
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
        // v32：恢复也走真源（不是无条件显示）；诊断盖屏仅在 sw1 时刷
        AIGuardSync();
        if (NO /*sw1 日志盖屏已退役*/) AIShowOverlay();
    }
}

static void AITestTapButton(void) {
    CGPoint pt = CGPointZero;
    NSString *desc = nil;
    if (!AIFindFirstButton(&pt, &desc)) { AILog(@"  没找到可点的 UIButton"); if (NO /*sw1 日志盖屏已退役*/) AIShowOverlay(); return; }
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
// v30 · L2 防护罩按钮回调：暂停 / 露出App(验证模式) / 结束任务
// 必须定义在 AIGuardRender 之前（ObjC 类不能前向声明后使用 [X new]）
@interface AIGuardTarget : NSObject
@end
@implementation AIGuardTarget
- (void)guardPause:(id)sender {
    if (gTaskTotal > 0) AITaskSet(gTaskName, gTaskIdx, gTaskTotal, @"wait", -1, @"已暂停");
    AIToast(@"已暂停");
}
- (void)guardVerify:(id)sender {
    gGuardMode = [gGuardMode isEqualToString:@"verify"] ? @"privacy" : @"verify";
    // v32：只重绘、不 pin（pin 会让任务结束后罩层赖着不走）
    AIGuardRender();
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gOverlayWindow) { gOverlayWindow.hidden = NO; [gOverlayWindow makeKeyAndVisible]; }
    });
    AIToast([gGuardMode isEqualToString:@"verify"] ? @"已露出 App（仍防误触）" : @"已恢复模糊");
}
- (void)guardEnd:(id)sender {
    AITaskSet(nil, 0, 0, @"idle", -1, nil);
    gGuardPinned = NO;
    AIGuardSync();                                // v32：结束任务后立刻落下，不等 tick
    AIToast(@"任务已结束");
}
// v42：回顾卡「知道了」出口
- (void)recapKnow:(id)sender {
    AIDismissRecap();
}
@end
static AIGuardTarget *gGT = nil;

// v30 · L2 防护罩渲染（规划 §9.3，拍板决策 1：毛玻璃 + 暗化兜底）
//   privacy = 模糊+暗化挡隐私；verify = 模糊降到≈0 但仍 makeKey（人能看清 AI 在干嘛，误触继续屏）
//   🔑 关键机制（勿改）：AIFakeTapAtWindowPoint / AIFakeSwipe 直接对 AIHostWindow() 做 hitTest
//      派发、不经过本窗口 → 罩当 keyWindow 屏住人类误触时，AI 程序化点击照常打到 App。
// v42：结束回顾卡（规划 §8.1 impeccable 收尾闭环）——任务结束不直接跳回"已就绪"。
// 原型 .g-card：大图标 + 标题 + 原因 + 三个数字 + 「知道了」。尺寸 246×214。
static UIView *AIRecapCardView(CGFloat screenW) {
    BOOL okDone = (gTaskOk != 0);                  // 0 = 失败（AITaskStateNow 也是这个判据）
    CGFloat cw = 246, ch = 214;
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(0, 0, cw, ch)];
    card.backgroundColor = [UIColor colorWithRed:0.063 green:0.086 blue:0.129 alpha:0.94];
    card.layer.cornerRadius = 14; card.layer.masksToBounds = YES;
    card.layer.borderWidth = 1;
    card.layer.borderColor = [[UIColor whiteColor] colorWithAlphaComponent:0.10].CGColor;

    UILabel *big = [[UILabel alloc] initWithFrame:CGRectMake(0, 14, cw, 36)];
    big.text = okDone ? @"✓" : @"■";
    big.textColor = AIColorFor(okDone ? @"ok" : @"fail");
    big.font = [UIFont boldSystemFontOfSize:30];
    big.textAlignment = NSTextAlignmentCenter;
    [card addSubview:big];

    UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(12, 52, cw - 24, 20)];
    t.text = okDone ? @"任务完成" : @"任务没跑完";
    t.textColor = [UIColor whiteColor];
    t.font = [UIFont boldSystemFontOfSize:16];   // v44：14 → 16，原型 .g-card h4{font-size:var(--fz-4)=16px}
    t.textAlignment = NSTextAlignmentCenter;
    [card addSubview:t];

    // 原因文案：gTaskResult 只存纯原因（v42 修：形状与标题由本卡自己渲染，不再重复）。
    // 卡面整体读作：「■ / 任务没跑完 / 卡在第 5 步：xxx」——无重复、无形状矛盾。
    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(12, 76, cw - 24, 34)];
    sub.numberOfLines = 2;
    sub.textAlignment = NSTextAlignmentCenter;
    sub.text = gTaskResult ?: @"";
    sub.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.72];
    sub.font = [UIFont systemFontOfSize:12];
    [card addSubview:sub];

    int fails = 0;
    for (NSDictionary *d in gSteps) if ([d[@"s"] isEqualToString:@"fail"]) fails++;
    NSArray *kv = @[@[@"用时", AITaskElapsedText()],
                    @[@"动作", [NSString stringWithFormat:@"%d 次", gTaskActCount]],
                    @[@"失败", [NSString stringWithFormat:@"%d", fails]]];
    CGFloat nx = 24, nw = (cw - 48) / 3.0;
    for (NSArray *p in kv) {
        UILabel *k = [[UILabel alloc] initWithFrame:CGRectMake(nx, 116, nw, 14)];
        k.text = p[0]; k.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.72];
        k.font = [UIFont systemFontOfSize:11]; k.textAlignment = NSTextAlignmentCenter;
        [card addSubview:k];
        UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(nx, 131, nw, 18)];
        v.text = p[1]; v.textColor = [UIColor whiteColor];
        v.font = [UIFont boldSystemFontOfSize:14]; v.textAlignment = NSTextAlignmentCenter;   // v44：13→14，原型 .nums b{--fz-3=14px}
        [card addSubview:v];
        nx += nw;
    }

    UIButton *ok = [UIButton buttonWithType:UIButtonTypeSystem];
    ok.frame = CGRectMake((cw - 104) / 2.0, ch - 56, 104, 44);   // ≥44pt（唯一收尾出口）
    [ok setTitle:@"知道了" forState:UIControlStateNormal];
    [ok setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    ok.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.14];
    ok.layer.cornerRadius = 10;
    ok.layer.borderWidth = 1;
    ok.layer.borderColor = [[UIColor whiteColor] colorWithAlphaComponent:0.52].CGColor;
    ok.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [ok addTarget:gGT action:@selector(recapKnow:) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:ok];
    return card;
}

// v42：回顾卡出口。点「知道了」→ 关卡 + 真正清空任务 + 罩落下。
// 关键：先把 gRecapDismissed 置 YES，再调 AITaskSet(0,0) —— 否则清空分支会被闸门挡住，
//       任务结论残留，下次任务一进来又弹旧卡。
static void AIDismissRecap(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AIDismissRecap(); });
        return;
    }
    gRecapShown     = NO;
    gRecapDismissed = YES;
    gTaskResult     = nil;
    gTaskStartTs    = 0;
    gTaskActCount   = 0;
    gGuardPinned    = NO;
    AITaskSet(nil, 0, 0, @"idle", -1, nil);   // 走清空分支（此时闸门已放行）
    gRecapDismissed = YES;                    // AITaskSet 内部可能复位，这里再保一次
    AIGuardSync();                            // 罩落下（idle 且无 pin → ShouldShow=NO）
}

static void AIGuardRender(void) {
    if (gIsSpringBoard) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            CGRect f = [UIScreen mainScreen].bounds;
            if (!gOverlayWindow) {
                UIWindowScene *scn = AIFirstWindowScene();
                if (scn) gOverlayWindow = [[UIWindow alloc] initWithWindowScene:scn];
                else     gOverlayWindow = [[UIWindow alloc] initWithFrame:f];
                gOverlayWindow.windowLevel = UIWindowLevelStatusBar + 100;
            }
            // 窗口可能已由诊断盖屏（AIShowOverlayText）建过，rootViewController 必须兜底
            if (!gOverlayWindow.rootViewController) {
                gOverlayWindow.rootViewController = [UIViewController new];
            }
            gOverlayWindow.backgroundColor = [UIColor clearColor];   // verify 模式要能透出 App
            gOverlayWindow.frame = f;
            UIView *host = gOverlayWindow.rootViewController.view;
            host.backgroundColor = [UIColor clearColor];
            host.frame = f;
            for (UIView *v in host.subviews) [v removeFromSuperview];

            BOOL verify = [gGuardMode isEqualToString:@"verify"];
            if (!verify) {
                UIBlurEffect *be = [UIBlurEffect effectWithStyle:UIBlurEffectStyleDark];
                UIVisualEffectView *vv = [[UIVisualEffectView alloc] initWithEffect:be];
                vv.frame = f;
                [host addSubview:vv];                       // 毛玻璃（采样下方已渲染缓冲）
                UIView *dim = [[UIView alloc] initWithFrame:f];
                // v41：0.55 → 0.65。原型实测 0.55 在浅色宿主上罩面次级文字仅 3.33:1、
                // 按钮边框 1.69:1，均不达 WCAG；0.65 是四种宿主（深色/浅白/中性灰/高饱和）
                // 全部达标的最小可用值（罩上白字 6.57~15.64）。
                dim.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.65];
                [host addSubview:dim];
            } else {
                UIView *dim = [[UIView alloc] initWithFrame:f];
                dim.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.06];
                [host addSubview:dim];
            }

            // v43：罩层标题对齐原型 .g-title —— 原型是一个 8px **脉动圆点** + 纯白标题（gap 7），
            // 不是「形状 + 彩色标题」挤在一个 label 里。
            //   .g-title{font-size:16px;font-weight:650;color:#fff;display:flex;align-items:center;gap:7px}
            //   .g-title i{width:8px;height:8px;border-radius:50%;background:var(--ok)}
            //   .g-title i.spin{animation:breathe 1.4s}   ← 脉动只给圆点，文字不动
            // 上一版把形状当标题前缀且整体上色，视觉上是个「彩色大符号+彩色字」，与原型的
            // 「小白点呼吸 + 稳重白字」气质完全不同 —— 这正是用户说「界面还是原来的」的原因之一。
            NSString *stG = (gTaskTotal > 0) ? gTaskState : @"exec";
            if (gTaskTotal > 0 && gTaskOk == 0) stG = @"fail";
            CGFloat cy = f.size.height * 0.30;
            BOOL spin = ([AITaskStateNorm(stG) isEqualToString:@"exec"] ||
                         [AITaskStateNorm(stG) isEqualToString:@"wait"]) && !gReduceMotion;
            UIView *gdot = [[UIView alloc] initWithFrame:CGRectMake((f.size.width - 178) / 2.0, cy + 11, 8, 8)];
            gdot.backgroundColor = AIColorFor(stG);          // 圆点随状态着色（原型默认 --ok）
            gdot.layer.cornerRadius = 4;
            if (spin) {
                CABasicAnimation *a1 = [CABasicAnimation animationWithKeyPath:@"opacity"];
                a1.fromValue = @1.0; a1.toValue = @0.45; a1.duration = 1.4;
                a1.autoreverses = YES; a1.repeatCount = HUGE_VALF;
                [gdot.layer addAnimation:a1 forKey:@"spin"];
            }
            [host addSubview:gdot];
            UILabel *tl = [[UILabel alloc] initWithFrame:CGRectMake(0, cy, f.size.width, 32)];
            tl.text = @"AI 正在操作手机";
            tl.textColor = [UIColor whiteColor];             // 原型 .g-title color:#fff（不随状态变色）
            tl.font = [UIFont boldSystemFontOfSize:16];      // 原型 .g-title{font-size:var(--fz-4)=16px}
            tl.textAlignment = NSTextAlignmentCenter;
            [host addSubview:tl];
            UILabel *bl = [[UILabel alloc] initWithFrame:CGRectMake(20, cy + 38, f.size.width - 40, 60)];
            bl.numberOfLines = 3; bl.textAlignment = NSTextAlignmentCenter;
            bl.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.88];   // 原型 .g-brief --txt-2
            bl.font = [UIFont systemFontOfSize:13];          // 原型 .g-brief{font-size:var(--fz-2)=13px}
            bl.text = AITaskLine();
            [host addSubview:bl];

            // ---- v42：回顾卡分支 ----
            // 任务跑完（ok>=0）时，罩层中央弹全屏回顾卡（规划 §8.1「任务结束不直接跳回已就绪」），
            // 并隐藏操作按钮（此时无事可暂停/结束）。gRecapShown 由 task op 置位。
            if (gRecapShown) {
                UIView *card = AIRecapCardView(f.size.width);
                card.center = CGPointMake(f.size.width / 2.0, f.size.height / 2.0);
                [host addSubview:card];
                return;
            }

            // ---- v42：进度条（原型 .g-meta + .g-bar）----
            // 旧实现只有标题+副标题，看不出「跑到第几步、还剩多少」。
            UILabel *meta = [[UILabel alloc] initWithFrame:CGRectMake(20, cy + 100, f.size.width - 40, 16)];
            meta.textAlignment = NSTextAlignmentCenter;
            meta.font = [UIFont systemFontOfSize:11];
            meta.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.85];   // v45：.72→.85 回原型 .g-meta{opacity:.85}
            meta.text = (gTaskTotal > 0)
                ? [NSString stringWithFormat:@"共 %d 步 · 当前第 %d 步", gTaskTotal, gTaskIdx]
                : @"无任务执行中";
            [host addSubview:meta];
            CGFloat barW = 196, barH = 6;
            UIView *barBg = [[UIView alloc] initWithFrame:CGRectMake((f.size.width - barW) / 2.0, cy + 122, barW, barH)];
            barBg.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.18];
            barBg.layer.cornerRadius = barH / 2.0; barBg.clipsToBounds = YES;
            CGFloat prog = (gTaskTotal > 0) ? MIN(1.0, (CGFloat)gTaskIdx / (CGFloat)gTaskTotal) : 0;
            UIView *fill = [[UIView alloc] initWithFrame:CGRectMake(0, 0, barW * prog, barH)];
            fill.backgroundColor = AIColorFor(stG);      // 进度条与状态同色
            fill.layer.cornerRadius = barH / 2.0;
            [barBg addSubview:fill];
            [host addSubview:barBg];

            // 三个大控件对齐原型 .gbtn：高度 46（≥44pt 触摸下限，原型实测值）、圆角 10（--r1）、
            // 字 13（--fz-2）、gap 8（--sp2）。v43：52→46 高 / 12→10 圆角 / 14→13 字号，全部回原型。
            // 「结束」用 .gbtn.stop 的红色语义（原型 border rgba(255,93,93,.7) + bg rgba(255,93,93,.16)）——
            // 破坏性动作必须与另两个在视觉上可区分，这是安全设计不是装饰。
            if (!gGT) gGT = [AIGuardTarget new];
            NSString *bt[] = {@"⏸ 暂停", (verify ? @"👁 恢复模糊" : @"👁 露出 App"), @"⏹ 结束"};
            SEL ba[] = {@selector(guardPause:), @selector(guardVerify:), @selector(guardEnd:)};
            CGFloat bw = (f.size.width - 40 - 16) / 3.0;      // 左右各 20 边距 + 2 个 8px gap
            for (int i = 0; i < 3; i++) {
                BOOL isStop = (i == 2);
                UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
                b.frame = CGRectMake(20 + i * (bw + 8), f.size.height - 110, bw, 46);
                b.backgroundColor = isStop
                    ? [UIColor colorWithRed:1.0 green:0.365 blue:0.365 alpha:0.16]    // 原型 .gbtn.stop 底
                    : [[UIColor whiteColor] colorWithAlphaComponent:0.10];            // 原型 .gbtn 底
                b.layer.cornerRadius = 10;
                b.layer.borderWidth = 1;
                b.layer.borderColor = isStop
                    ? [UIColor colorWithRed:1.0 green:0.365 blue:0.365 alpha:0.7].CGColor
                    : [[UIColor whiteColor] colorWithAlphaComponent:0.52].CGColor;
                [b setTitle:bt[i] forState:UIControlStateNormal];
                [b setTitleColor:(isStop ? [UIColor colorWithRed:1.0 green:0.835 blue:0.835 alpha:1.0]
                                          : [UIColor whiteColor]) forState:UIControlStateNormal];
                b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
                [b addTarget:gGT action:ba[i] forControlEvents:UIControlEventTouchUpInside];
                [host addSubview:b];
            }
        } @catch (NSException *e) { AILog(@"guard 渲染异常 %@", e); }
    });
}

// v32 · 罩层的唯一真源：手动 pin 或 任务进行中 → 该显示；否则必须落下。
// 为什么要有这个：v31 实测「idle 时罩层可见且 overlay off 三次都关不掉」——
// 老代码里 AINetLoop 首次轮询成功会无条件 AIShowOverlay()（v20 之前盖屏还是主 UI 的遗留），
// 每次冷启动都糊一层，而且它是 dispatch_async 异步的，跟 off 命令赛跑。
// 与其逐个追凶，不如把「该不该显示」收敛成纯函数，再让 tick 每秒自愈一次。
static BOOL AIGuardShouldShow(void) {
    // v42：加 gRecapShown —— 任务跑完那一刻 gBusy 会归零，若不含这个条件，
    //       罩层会在回顾卡弹出来的同一帧落下，卡就没有容器了（无处可显示的坏体验）。
    return (gGuardPinned || gBusy > 0 || gOpBusy > 0 || gRecapShown) ? YES : NO;
}

// v34 · 「AI 真的动了一下手机」也该遮挡 —— 之前只有 task{} 驱动的 busy 才会升起，
// 于是我单独发一条 tapui/scroll 时屏幕上没有任何提示，人不知道手机正在被操作。
// 现在任何操作类命令都会点亮罩层，停下 8 秒后自动落下（不会常驻挡视线）。
#define AI_GUARD_OP_IDLE 8.0
static void AIOpMark(void) {
    if (!AIFlag(@"guardAuto", YES)) return;    // 嫌挡眼可以关掉这个开关
    gOpBusy = 1;
    gLastOpTs = CFAbsoluteTimeGetCurrent();
    AIGuardSync();
}
static void AIOpIdleCheck(void) {
    if (gOpBusy && (CFAbsoluteTimeGetCurrent() - gLastOpTs) > AI_GUARD_OP_IDLE) {
        gOpBusy = 0;
        AIGuardSync();
    }
}

// 按真源收敛罩层（主线程）。幂等，可每 tick 调。
static void AIGuardSync(void) {
    if (gIsSpringBoard) return;
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AIGuardSync(); });
        return;
    }
    BOOL want = AIGuardShouldShow();
    if (!want) {
        if (gOverlayWindow && !gOverlayWindow.hidden) {
            gOverlayWindow.hidden = YES;
            // 把 key 交还宿主窗口，否则 App 收不到按键/触摸链
            @try { UIWindow *h = AIHostWindow(); if (h && h != gOverlayWindow) [h makeKeyAndVisible]; }
            @catch (id e) {}
        }
        return;
    }
    if (!gOverlayWindow || !gOverlayWindow.rootViewController) { AIGuardRender(); return; }
    if (gOverlayWindow.hidden) { gOverlayWindow.hidden = NO; [gOverlayWindow makeKeyAndVisible]; }
}

static void AISetOverlayVisible(BOOL vis) {
    // v32：vis 不再只是「改 hidden」，而是一次带语义的显式控制：
    //   vis=YES -> 视为手动 pin（任务结束也不落）；vis=NO -> 解 pin 并按真源收敛。
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AISetOverlayVisible(vis); });
        return;
    }
    gGuardPinned = vis ? YES : NO;
    if (vis) {
        AIGuardRender();
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!gOverlayWindow) return;
            gOverlayWindow.hidden = NO;
            [gOverlayWindow makeKeyAndVisible];
            AILog(@"  [guard] 防护罩已升起（吃掉人类触摸；AI 点击走宿主窗口照常生效）");
        });
    } else {
        AIGuardSync();
        AILog(@"  [guard] 防护罩已落下（解 pin，按 busy 收敛）");
    }
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
    if (NO /*sw1 日志盖屏已退役*/) AIShowOverlayText(@"AgentInject2 已加载 ✓\n正在自检，请稍候…", NO, nil);
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
            if (NO /*sw1 日志盖屏已退役*/) { @try { AIShowOverlay(); } @catch (NSException *e) {} }
            // v32：冷启动收尾 —— 强制按真源收敛罩层（idle 必须是落下的）
            @try { AIGuardSync(); } @catch (NSException *e) {}
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
    BOOL ok = AIHttpEx(urlStr, nil, 40.0, YES, nil, &d, nil, &code, nil, nil);
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
            BOOL ok = AIHttpEx(AI_MANIFEST, nil, 20.0, YES, nil, &d, nil, &code, nil, nil);
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
@implementation AIFloatTarget
- (void)ballTapped:(id)sender {
    gFloatExpanded = !gFloatExpanded;
    gFloatForce = YES;                  // 点了就要立刻响应，别被节流挡住
    AIFloatApply();
}
- (void)ballDragged:(UIPanGestureRecognizer *)g {
    if (!gFloatWindow) return;
    // v47 · G53 修复：原来拖的是 gFloatWindow 里的 ball 子视图，但 clamp 用的是**屏幕**尺寸
    //   （sc.width/sc.height），而 ball.center 是**窗口内**坐标（恒为 30,30）。
    //   两套坐标混算 → 球被推到窗口外，表现就是「手指拖了，球偏移/跑飞/看着没动」。
    //   正确做法：直接拖**窗口**本身。窗口原点就是屏幕坐标，与 sc 同一坐标系，无需换算。
    //   球是窗口内的固定子视图，跟着窗口走即可 —— 这样同时也避免了展开态（窗口 280×380，
    //   球已不在窗口内）误拖到面板。
    //
    // v48 · G55 修复：拖动起步阈值。
    //   v47 加 [pan requireGestureRecognizerToFail:tap] 解决「拖完点不动」，但引入了新问题：
    //   pan 必须等 tap 失败才 recognize，而 tap 失败要手指位移超过其容差（约 10pt），
    //   于是「按住球心拖，得拖到球边缘（约 28pt）才开始跟手」——用户报障的手感。
    //   本版改为：两个手势**并存识别**（delegate 返回 YES，见手势挂载处），
    //   在 pan 回调里按**累计位移**自己决定何时进入拖动：
    //     · 位移 < kAIxFLOAT_DRAG_SLOP  → 不动，把判定权留给 tap（保证轻点能展开）
    //     · 位移 ≥ 阈值                  → 进入拖动；并把 tap 主动置失败，避免拖完又触发一次点击
    CGPoint t = [g translationInView:nil];   // nil = 窗口坐标系（screen 坐标，与 sc 一致）
    [g setTranslation:CGPointZero inView:nil];

    if (g.state == UIGestureRecognizerStateBegan) {
        gFloatDragOn  = NO;
        gFloatDragAcc = CGPointZero;
    }
    // 累计位移（translation 每次都被清零，必须自己攒）
    gFloatDragAcc.x += t.x;
    gFloatDragAcc.y += t.y;
    CGFloat moved = hypot(gFloatDragAcc.x, gFloatDragAcc.y);

    if (!gFloatDragOn) {
        if (moved < 6.0) {
            // 还没走够阈值：不移动窗口。若此时手指抬起（Ended/Cancelled），
            // 说明是一次轻点 —— 交给 tap 处理，这里什么都不做。
            if (g.state == UIGestureRecognizerStateEnded ||
                g.state == UIGestureRecognizerStateCancelled) {
                gFloatDragAcc = CGPointZero;
            }
            return;
        }
        gFloatDragOn = YES;
        // 已确认是拖动 —— 立刻让 tap 失败，防止手指抬起时又触发一次「展开/收起」
        for (UIGestureRecognizer *r in g.view.gestureRecognizers) {
            if ([r isKindOfClass:[UITapGestureRecognizer class]]) {
                r.enabled = NO; r.enabled = YES;   // 强制重置为失败态
            }
        }
    }

    CGSize sc = [UIScreen mainScreen].bounds.size;
    CGRect f = gFloatWindow.frame;
    // 屏幕内边距：半宽/半高 + 安全边距，保证球完整可见且不被系统手势条盖住
    CGFloat halfW = f.size.width  / 2.0;
    CGFloat halfH = f.size.height / 2.0;
    CGFloat cx = MIN(MAX(f.origin.x + halfW + t.x, halfW), sc.width  - halfW);
    CGFloat cy = MIN(MAX(f.origin.y + halfH + t.y, halfH), sc.height - halfH);
    // 只挪窗口原点；窗口尺寸不变（收起态 60×60）
    if (!gFloatExpanded) {
        gFloatWindow.frame = CGRectMake(cx - halfW, cy - halfH, f.size.width, f.size.height);
        // 拖动期间禁掉自愈重算，否则心跳每秒按旧 fpx/fpy 把窗口拽回去
        gFloatForce = NO; gFloatLast = CFAbsoluteTimeGetCurrent();
    }
    if (g.state == UIGestureRecognizerStateEnded ||
        g.state == UIGestureRecognizerStateCancelled) {
        gFloatDragOn  = NO;
        gFloatDragAcc = CGPointZero;
        // v47：存成 0~1 比例（换机型/转屏不跑出屏）。
        // 注意取值范围与 AIFloatApply 的还原公式必须严格互逆：
        //   c.x = 30 + px*(sc.width -60)   →   px = (cx - 30) / (sc.width  - 60)
        //   c.y = 90 + py*(sc.height-180)  →   py = (cy - 90) / (sc.height - 180)
        CGFloat px = (cx - 30) / MAX(1.0, sc.width  - 60);
        CGFloat py = (cy - 90) / MAX(1.0, sc.height - 180);
        px = MIN(MAX(px, 0.0), 1.0);
        py = MIN(MAX(py, 0.0), 1.0);
        [[NSUserDefaults standardUserDefaults] setFloat:(float)px forKey:AIK(@"fpx")];
        [[NSUserDefaults standardUserDefaults] setFloat:(float)py forKey:AIK(@"fpy")];
        [[NSUserDefaults standardUserDefaults] synchronize];
        // v47：拖完强制按 fpx/fpy 重算一次，让「存的值」与「屏上位置」立刻一致，
        //   不留下「存的是新的、显示是旧的」的漂移窗口。
        gFloatForce = YES;
        AIFloatApply();
    }
}
// v48 · G55：允许 tap 与 pan 同时识别。
//   不加这条，iOS 默认「pan 一识别就取消 tap」——那正是 G54。加了 requireGestureRecognizerToFail
//   又会把 pan 起步拖到 tap 失败之后（G55）。正解是让它们并存，由 ballDragged: 按位移分流。
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)a
shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)b {
    return YES;
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
// v30 · L3 面板：诊断区折叠 / 暂停 / 结束（安全控件，唯一能打断 AI 的入口）
- (void)toggleDiag:(id)sender { gPanelDiag = !gPanelDiag; gFloatForce = YES; AIFloatApply(); }
- (void)pauseTask:(id)sender {
    if (gTaskTotal > 0) { AITaskSet(gTaskName, gTaskIdx, gTaskTotal, @"wait", -1, @"已暂停"); }
    AIToast(@"已暂停（点「结束」彻底停手）");
}
- (void)endTask:(id)sender {
    AITaskSet(nil, 0, 0, @"idle", -1, nil);
    gGuardPinned = NO;
    AIToast(@"任务已结束");
}
// v42：复制步骤全文（规划 §2 L3 控件）。给人拿去贴给 AI 或留痕。
- (void)copySteps:(id)sender {
    NSMutableString *ms = [NSMutableString new];
    [ms appendFormat:@"%@ %@\n", kAIVer, (gTaskName.length ? gTaskName : @"无任务")];
    for (NSDictionary *d in gSteps) {
        [ms appendFormat:@"%@ %@ %@", AIShapeFor(d[@"s"]), d[@"act"], d[@"obj"]];
        if ([d[@"ev"] length]) [ms appendFormat:@"  -> %@", d[@"ev"]];
        [ms appendString:@"\n"];
    }
    if (gTaskResult.length) [ms appendFormat:@"\n%@\n", gTaskResult];
    if (ms.length == 0) [ms appendString:@"（暂无步骤记录）\n"];
    [UIPasteboard generalPasteboard].string = ms;
    AILog(@"  [ui] copySteps -> %lu 字符", (unsigned long)ms.length);
}
@end
// gFT 已在文件头部前置声明（v42：copysteps 命令要先用到它）

// ============================================================
// v30 · UI 三层任务态：状态源与编码（规划 §9.1 / §9.2）
//   task{} + ui{} 是唯一真相；L1 球 / L2 罩 / L3 面板全部读它。
// ============================================================
static NSString *AITaskStateNorm(NSString *s) {
    if (!s.length) return @"idle";
    NSString *l = s.lowercaseString;
    if ([l isEqualToString:@"exec"] || [l isEqualToString:@"run"]  || [l isEqualToString:@"busy"])   return @"exec";
    if ([l isEqualToString:@"wait"] || [l isEqualToString:@"pause"])                                  return @"wait";
    if ([l isEqualToString:@"ok"]   || [l isEqualToString:@"done"] || [l isEqualToString:@"success"]) return @"ok";
    if ([l isEqualToString:@"fail"] || [l isEqualToString:@"error"])                                  return @"fail";
    return @"idle";
}
// 形状优先（色盲可用），颜色只做加强
static NSString *AIShapeFor(NSString *st) {
    st = AITaskStateNorm(st);
    if ([st isEqualToString:@"exec"]) return @"●";
    if ([st isEqualToString:@"wait"]) return @"◐";
    if ([st isEqualToString:@"ok"])   return @"✓";
    // v41：✕ → ■，与原型 v4/v8 对齐（规划文档 §2 与 §9.2 自相矛盾，取 ■）。
    // 形状是语义载体，原型与源码必须一致，否则落地就会错。
    if ([st isEqualToString:@"fail"]) return @"■";
    return @"○";
}
static UIColor *AIColorFor(NSString *st) {
    st = AITaskStateNorm(st);
    if ([st isEqualToString:@"exec"]) return [UIColor colorWithRed:0.24 green:0.86 blue:0.59 alpha:1.0];  // #3ddc97
    if ([st isEqualToString:@"wait"]) return [UIColor colorWithRed:1.00 green:0.71 blue:0.33 alpha:1.0];  // #ffb454
    if ([st isEqualToString:@"ok"])   return [UIColor colorWithRed:0.24 green:0.86 blue:0.59 alpha:1.0];
    if ([st isEqualToString:@"fail"]) return [UIColor colorWithRed:1.00 green:0.37 blue:0.37 alpha:1.0];  // #ff5d5d
    return [UIColor colorWithRed:0.54 green:0.58 blue:0.63 alpha:1.0];                                     // #8a93a0
}
// 悬浮球一句话：人话动作，不是原始日志
static NSString *AITaskLine(void) {
    if (gTaskTotal > 0) {
        NSString *n = gTaskName.length ? gTaskName : @"任务";
        NSString *b = gTaskBrief.length ? gTaskBrief : (gTaskStep.length ? gTaskStep : @"");
        if (b.length) return [NSString stringWithFormat:@"%@ %d/%d\n%@", n, gTaskIdx, gTaskTotal, b];
        return [NSString stringWithFormat:@"%@ %d/%d", n, gTaskIdx, gTaskTotal];
    }
    return gTaskBrief.length ? gTaskBrief : @"待命";
}
// v42：回顾卡「用时 1:24」。任务起点在 AITaskSet 首次进任务时记。
static NSString *AITaskElapsedText(void) {
    if (gTaskStartTs <= 0) return @"—";
    int sec = (int)[[NSDate date] timeIntervalSince1970] - gTaskStartTs;
    if (sec < 0) sec = 0;
    if (sec > 99 * 60 + 59) return @"99:59+";      // 防溢出显示成天文数字
    return [NSString stringWithFormat:@"%d:%02d", sec / 60, sec % 60];
}
// v42：L3 单行步骤视图 = [状态形状] [动作 目标] / [结果侧证据] / 分隔线（原型 .step）
// 全部用 frame 手写，不引 Auto Layout —— 30~60 行时自动布局会被全量重建放大成卡顿。
static UIView *AIStepRowView(NSDictionary *d, CGFloat w) {
    NSString *st = d[@"s"] ?: @"idle";
    UIColor  *c  = AIColorFor(st);
    NSString *ev = d[@"ev"];
    BOOL hasEv = [ev length] > 0;
    // v43：行高按原型实测重算（不再拍脑袋）。
    // 原型 .step{padding:7px 12px;line-height:1.55}：无证据行 = 7+18.6+7+0.5 ≈ 34；有证据行 =
    // 7+18.6+2(.ev margin-top)+15.5+7+0.5 ≈ 51。原实现 48 是漏算了 .ev 的 margin-top 与 .l1 的
    // line-height 余量，行会挤 —— 步骤多时越挤越明显。
    CGFloat rowH = hasEv ? 51.0 : 34.0;
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, rowH)];
    row.backgroundColor = [UIColor clearColor];

    // v43：形状列宽/字号按原型 .step .sy 取值。原型里 **.step .sy 没有 font-size 声明**，
    // 继承 .step 的 font-size:var(--fz-1)=12px；而 .p-hd .sy{font-size:15px} 是**面板头部**那个
    // 大形状的尺寸，不是步骤行的。上一版我按 15px 改是读错了选择器 —— 这类「同一 class 名在不同
    // 作用域下取值不同」的坑，正是 v41 翻车的同类错误，落地前必须回到选择器原文核对。
    // 列宽 12 也取自原型 .step .sy{width:12px}（不是按字号拍脑袋给的 14）。
    // Y = 7(.step padding-top) + (18.6-16)/2 ≈ 8，让形状在 l1 行内垂直居中。
    UILabel *sy = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, 12, 16)];
    sy.text = AIShapeFor(st); sy.textColor = c;
    sy.font = [UIFont boldSystemFontOfSize:12];
    sy.textAlignment = NSTextAlignmentCenter;
    [row addSubview:sy];

    CGFloat nmX = 12 + 12 + 7;                     // = 31（原型 .step padding-left 12 + .sy 宽 12 + .l1 gap 7）
    // Y 同上取 8（与形状同基线），高度 18 容纳 12px 字。
    UILabel *nm = [[UILabel alloc] initWithFrame:CGRectMake(nmX, 7, w - nmX - 12, 18)];
    NSString *act = d[@"act"] ?: @"", *obj = d[@"obj"] ?: @"";
    nm.text = obj.length ? [NSString stringWithFormat:@"%@ %@", act, obj] : act;
    nm.textColor = [UIColor colorWithRed:0.913 green:0.933 blue:0.953 alpha:1.0];   // #e9eef3
    nm.font = [UIFont systemFontOfSize:12];
    nm.lineBreakMode = NSLineBreakByTruncatingTail;
    [row addSubview:nm];

    if (hasEv) {
        // v43：证据行左缩进对齐原型 .ev{padding-left:19px}，即「.step 左内边距 12 + 19 = 31」。
        // 原实现写 nmX=33（按 图标14+gap7+12 推出来），比原型多 2px —— 依据错了：
        // 原型的证据行缩进是**相对 .step 的固定值**，不是按图标宽度算的。
        // 巧合的是：图标列宽改回 12 后 nmX 也正好 = 31，但两者语义不同（动作行对齐图标+gap，
        // 证据行对齐 .ev 的固定 padding），所以这里仍按 .ev 独立取值，不做「复用 nmX」的优化。
        CGFloat evX = 12 + 19;                     // = 31
        UILabel *el = [[UILabel alloc] initWithFrame:CGRectMake(evX, 26, w - evX - 12, 14)];
        el.text = ev;
        el.font = [UIFont fontWithName:@"Menlo" size:10];    // 等宽只用在真数据（证据）
        el.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.88];  // 原型 .ev 用 --txt-2=rgba(255,255,255,.88)
        el.lineBreakMode = NSLineBreakByTruncatingTail;
        [row addSubview:el];
    }
    UIView *ln = [[UIView alloc] initWithFrame:CGRectMake(0, rowH - 0.5, w, 0.5)];
    ln.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.06];       // 原型分隔线
    [row addSubview:ln];
    return row;
}
// 统一设状态源：主线程赋值 → 重绘 L1 球 + L2 罩自动显隐
static void AITaskSet(NSString *name, int step, int total, NSString *state, int ok, NSString *brief) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AITaskSet(name, step, total, state, ok, brief); });
        return;
    }
    if (name)  gTaskName  = name.copy;
    if (step  >= 0) gTaskIdx   = step;
    if (total >= 0) gTaskTotal = total;
    if (state) gTaskState = AITaskStateNorm(state);
    if (ok    >= 0) gTaskOk    = ok;
    if (brief) gTaskBrief = brief.copy;
    // v42：任务起点。只在「从无到有」时记一次，用于回顾卡算「用时」。
    // 条件里带 step>0 是为了避开云端发 task{step:0,total:N} 这种中间态把起点冲掉。
    if (total > 0 && step > 0 && gTaskStartTs == 0) {
        gTaskStartTs    = (int)[[NSDate date] timeIntervalSince1970];
        gTaskActCount   = 0;
        gRecapDismissed = NO;
    }
    // 清任务：step/total 同时归零就是清空信号。
    // v34：不再要求 name 也为空 —— v33 实测 name 非空时 brief 会残留（idle 了还挂着上一步的话）。
    // v42：回顾卡闸门 —— 只有用户点过「知道了」(gRecapDismissed) 才允许清掉任务结论。
    //      否则云端任务结束后补发的清空信号会把刚弹出的回顾卡提前干掉（无出口的坏体验）。
    if (total == 0 && step == 0) {
        gTaskState = @"idle"; gTaskBrief = nil; gTaskOk = -1;
        gTaskIdx = 0; gTaskTotal = 0;
        gGuardMode = @"privacy";          // v34：verify 模式随任务一起复位
        [gSteps removeAllObjects];
        if (gRecapDismissed) {
            gTaskResult = nil;
            gRecapShown = NO;
        }
    }
    // v34 · busy 判定修正：v33 只认 exec/wait，导致「第 2 步 ok（2/5，任务还没完）」
    // 罩层就提前落下、隐私裸露。正确语义：任务还在跑 = 有任务 && 没走到最后一步 && 不是 idle。
    BOOL stExec = [gTaskState isEqualToString:@"exec"] || [gTaskState isEqualToString:@"wait"];
    BOOL done   = (gTaskTotal > 0 && gTaskIdx >= gTaskTotal && !stExec);   // 最后一步且非执行态
    gBusy = (gTaskTotal > 0 && !done && ![gTaskState isEqualToString:@"idle"]) ? 1 : 0;
    gFloatForce = YES;
    AIFloatApply();
    // L2 防护罩：任务期自动升起 + 手动 pin（拍板决策 3：两者都要）
    // v32：走 AIGuardSync 而不是 AISetOverlayVisible —— 后者会把 busy 误记成 pin，任务结束赖着不走
    AIGuardSync();
}
// 当前有效状态：无任务=idle；有任务但最近一步失败=fail（失败优先，别让 exec 盖住错误）
static NSString *AITaskStateNow(void) {
    if (gTaskTotal <= 0) return @"idle";
    if (gTaskOk == 0) return @"fail";
    return AITaskStateNorm(gTaskState);
}
// /status 的 task{}：AI 与 UI 共用一套词汇（规划 §5）
static NSDictionary *AITaskDict(void) {
    return @{@"name":  gTaskName  ?: @"",
             @"step":  @(gTaskIdx),
             @"total": @(gTaskTotal),
             @"state": AITaskStateNow() ?: @"idle",
             @"ok":    @(gTaskOk),
             @"brief": gTaskBrief ?: (gTaskStep ?: @"")};
}
// /status 的 ui{}：三层 UI 各自读自己那块
static NSDictionary *AIUiDict(void) {
    NSString *st = AITaskStateNow();
    // v33：float 加可观测字段 —— 球到底在不在，看 win/vis/scn/frame 四个数，不用再靠肉眼猜
    CGRect ff = gFloatWindow ? gFloatWindow.frame : CGRectZero;
    // ============ v42：结构可观测化（这是对被否掉的 v41 最直接的补救） ============
    // v41 之所以「测试全绿但用户不认」，根因是回执里只有颜色/几何这类数值字段，
    // 结构（步骤行、回顾卡、进度条）在回执里**根本不可见**，脚本想测也测不到，
    // 于是只能退化成测颜色。v42 把结构量全部暴露出来，让脚本能对「用户要的东西」下断言。
    //   结构量：panel.steps.n（步骤行数）、panel.okcnt（成功步数）
    //           guard.recap（回顾卡在不在）、guard.pct（进度条百分比）
    //           float.edge / float.reduce（吸边、减弱动效）
    int okCnt = 0;
    for (NSDictionary *d in gSteps) if ([d[@"s"] isEqualToString:@"ok"]) okCnt++;
    int pct = (gTaskTotal > 0) ? (int)((gTaskIdx * 100.0) / gTaskTotal + 0.5) : 0;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    // recaptext 回显「卡面上真正看到的一段话」，供脚本断言。
    // v42 修：gTaskResult 现在只存纯原因，所以这里必须把卡自己的标题拼回来才等价于屏上所见
    //   （原来 gTaskResult 自带标题，这里再拼一次 → 「任务没跑完 · ✕ 任务没跑完 · …」重复）。
    NSString *recapTxt = gTaskResult ? [NSString stringWithFormat:@"%@ · %@",
                            (gTaskOk == 0 ? @"任务没跑完" : @"任务完成"), gTaskResult] : @"";
    return @{@"float": @{@"dot": st ?: @"idle", @"line": AITaskLine(),
                         @"win":  @(gFloatWindow ? 1 : 0),
                         @"vis":  (gFloatWindow && !gFloatWindow.hidden) ? @1 : @0,
                         @"scn":  (gFloatWindow && gFloatWindow.windowScene) ? @1 : @0,
                         @"edge": @(AIFlag(@"edge", NO) ? 1 : 0),      // v42：吸边半隐
                         @"reduce": @(gReduceMotion ? 1 : 0),          // v42：减弱动态效果
                         @"frame": [NSString stringWithFormat:@"%.0f,%.0f %.0fx%.0f",
                                    ff.origin.x, ff.origin.y, ff.size.width, ff.size.height]},
             @"guard": @{@"visible": (gOverlayWindow && !gOverlayWindow.hidden) ? @1 : @0,
                         @"want":    @(AIGuardShouldShow() ? 1 : 0),   // v32：真源 vs 实际的差就是 bug
                         @"mode":    gGuardMode ?: @"privacy",
                         @"pinned":  @(gGuardPinned),
                         @"recap":   @(gRecapShown ? 1 : 0),           // v42：回顾卡可见
                         @"recaptext": recapTxt,                       // v42：卡上文案
                         @"pct":     @(pct)},                          // v42：进度条百分比
             @"panel": @{@"open": @(gFloatExpanded ? 1 : 0),
                         @"okcnt": @(okCnt),                           // v42：成功步数
                         @"steps": @{@"n": @(gSteps.count)}}};          // v42：步骤行数
}

// L3 步骤列表：状态图标 + 动作 + 目标 + 结果侧证据
static void AIStepAdd(NSString *state, NSString *act, NSString *obj, NSString *ev) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AIStepAdd(state, act, obj, ev); });
        return;
    }
    if (!gSteps) gSteps = [NSMutableArray new];
    [gSteps addObject:@{@"s": AITaskStateNorm(state) ?: @"idle",
                        @"act": act ?: @"", @"obj": obj ?: @"", @"ev": ev ?: @""}];
    gTaskActCount++;                     // v42：回顾卡「动作 N 次」
    if (gSteps.count > 60) [gSteps removeObjectAtIndex:0];
}

// v33 · 悬浮球自愈：跟罩层一个套路 —— 「该不该在」由 ball flag 决定，
// 只要窗口不存在 / 被藏 / 没挂 scene / 尺寸为 0 / 跑到屏外，就强制重建一次。
// 每秒调一次，任何把它弄丢的路径都会在 1 秒内被拉回来。
static void AIFloatSync(void) {
    if (gIsSpringBoard) return;
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ AIFloatSync(); });
        return;
    }
    if (!AIFlag(@"ball", YES)) return;      // 用户主动关了就别强开
    BOOL need = NO;
    if (!gFloatWindow) need = YES;
    else if (gFloatWindow.hidden) need = YES;
    else if (gFloatWindow.windowScene == nil && AIFirstWindowScene()) need = YES;  // 无 scene 不上屏
    else {
        CGRect f  = gFloatWindow.frame;
        CGRect sb = [UIScreen mainScreen].bounds;
        if (f.size.width <= 0 || f.size.height <= 0) need = YES;
        else if (!CGRectIntersectsRect(f, sb))        need = YES;   // 跑到屏幕外
    }
    if (need) { gFloatForce = YES; AIFloatApply(); }
}

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

        // v33 · 关键修复：boot 早期 AIFirstWindowScene() 可能还没返回 scene（connectedScenes 为空），
        // 于是建出「无 windowScene 的窗口」—— iOS 13+ 上这种窗口永远不上屏，而且因为
        // gFloatWindow 已非 nil，后面再也不会重建。表现就是「悬浮球不见了」。
        // 这里一旦发现缺 scene 且现在能拿到 scene，就销毁重建。
        if (gFloatWindow && gFloatWindow.windowScene == nil) {
            UIWindowScene *scnFix = AIFirstWindowScene();
            if (scnFix) { @try { gFloatWindow.hidden = YES; } @catch (id e) {} gFloatWindow = nil; }
        }
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
        host.frame = gFloatWindow.bounds;   // v33：root view 尺寸必须跟着窗口，否则球画到屏外

        BOOL want = AIFlag(@"ball", YES);
        gFloatWindow.hidden = !want;
        if (!want) return;
        // v42：减少动效 —— 跟随系统开关，也支持 reduce 开关强制（便于云端验收，不必改系统设置）
        gReduceMotion = UIAccessibilityIsReduceMotionEnabled();
        if ([[NSUserDefaults standardUserDefaults] objectForKey:AIK(@"reduce")])
            gReduceMotion = AIFlag(@"reduce", NO);

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
            // v41 · L1 可辨识性修复（原型 v8 实测结论）
            //   旧：黑 0.62 半透明 + 无描边 → 在深色宿主上球与底色几乎同亮度，
            //       实测对比度仅 ~1.13:1，球"消失"在视频画面里。
            //   新：不透明深底 #14161a + 2px 亮描边 rgba(255,255,255,.92)。
            //       「双对比元素取最大值」：深色宿主靠亮描边、浅色宿主靠深底，两极都可辨识
            //       （实测 深色 16.29 / 浅白 6.74 / 中性灰 12.48 / 高饱和 14.62，全部 ≥3）。
            // ⚠️ 这是 UIView 不是窗口，不抢 key；绝不对球调 makeKeyAndVisible。
            ball.backgroundColor = [UIColor colorWithRed:0.078 green:0.086 blue:0.102 alpha:1.0]; // #14161a
            ball.layer.borderWidth = 2.0;
            ball.layer.borderColor = [[UIColor colorWithWhite:1.0 alpha:0.92] CGColor];
            // v30 三层 UI · L1：收起态 = 状态形状 + 一句话（纯任务语言，不再显示版本/指令数）
            NSString *stNow = AITaskStateNow();
            // v41：优先读 task.brief（云端下发的一句话人话，如「正在刷第 3 个视频」），
            //      没有才退回「任务名 步骤/总数」。原实现忽略 brief，导致球上只有干巴巴的 3/7。
            NSString *shortLine = gTaskBrief.length
                ? gTaskBrief
                : ((gTaskTotal > 0)
                   ? [NSString stringWithFormat:@"%@ %d/%d", (gTaskName.length ? gTaskName : @"任务"), gTaskIdx, gTaskTotal]
                   : @"待命");
            // v43：L1 球内部结构对齐原型 .ball .shape / .word —— 上一版把两者塞进同一个
            // 11px 双行 label，字号被强行拉平，球上根本没有原型那种「大形状 + 小词」的层次。
            // 原型：.shape{font-size:19px;line-height:1}、.word{font-size:9px;max-width:52px}，
            // 两者上下排列（.ball flex-direction:column; gap:2px）。这里拆成两个 label。
            // 纵向：内容高 = 形状 20 + gap 2 + 词 13 = 35，球 58 → 居中偏移 (58-35)/2 ≈ 11.5，
            // 取 12/33 让形状与词之间真正空出 1~2px（原型 .ball gap:2px + column 居中）。
            UILabel *sh = [[UILabel alloc] initWithFrame:CGRectMake(0, 12, 56, 20)];
            sh.text = AIShapeFor(stNow);
            sh.textColor = AIColorFor(stNow);
            sh.font = [UIFont boldSystemFontOfSize:19];          // 原型 .ball .shape{font-size:19px}
            sh.textAlignment = NSTextAlignmentCenter;
            [ball addSubview:sh];

            UILabel *wd = [[UILabel alloc] initWithFrame:CGRectMake(2, 34, 52, 13)];
            wd.text = shortLine;
            wd.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.88];   // 原型 --txt-2
            wd.font = [UIFont systemFontOfSize:9];               // 原型 .ball .word{font-size:9px}
            wd.textAlignment = NSTextAlignmentCenter;
            wd.lineBreakMode = NSLineBreakByTruncatingTail;
            wd.minimumScaleFactor = 0.75; wd.adjustsFontSizeToFitWidth = YES;
            [ball addSubview:wd];
            // v42：脉动（原型 .shape.pulse，breathe 1.8s）—— 执行/等待态才动，减少动效时不加。
            // v43：动画挂在形状 label（sh）上，原型 .shape.pulse 也是这一层，不是球整体。
            NSString *qn = AITaskStateNorm(stNow);
            BOOL pulsing = ([qn isEqualToString:@"exec"] || [qn isEqualToString:@"wait"]) && !gReduceMotion;
            if (pulsing) {
                CABasicAnimation *an = [CABasicAnimation animationWithKeyPath:@"opacity"];
                an.fromValue = @1.0; an.toValue = @0.45;
                an.duration = 1.8;
                an.autoreverses = YES;
                an.repeatCount = HUGE_VALF;
                [sh.layer addAnimation:an forKey:@"breathe"];
            }
            // done 态右上角徽标脉冲：不点开也知道结果（规划 §8.4）
            NSString *stN = AITaskStateNorm(stNow);
            if ([stN isEqualToString:@"ok"] || [stN isEqualToString:@"fail"]) {
                UIView *bg = [[UIView alloc] initWithFrame:CGRectMake(38, 3, 15, 15)];
                bg.layer.cornerRadius = 7.5;
                bg.backgroundColor = AIColorFor(stNow);
                bg.layer.borderWidth = 1.5;
                bg.layer.borderColor = [UIColor whiteColor].CGColor;
                if (!gReduceMotion) {
                    CABasicAnimation *an2 = [CABasicAnimation animationWithKeyPath:@"opacity"];
                    an2.fromValue = @1.0; an2.toValue = @0.4;
                    an2.duration = 1.6; an2.autoreverses = YES; an2.repeatCount = HUGE_VALF;
                    [bg.layer addAnimation:an2 forKey:@"badge"];
                }
                [ball addSubview:bg];
            }
            // v42：吸边半隐（原型 .ball.edging）——球贴在右半屏且开了 edge 开关时淡到 0.55 并贴边，
            //      不遮挡宿主内容；减少动效时不做位移（只调透明度是允许的，但仍尊重开关）。
            if (AIFlag(@"edge", NO) && (c.x > sc.width / 2.0)) {
                ball.alpha = 0.55;
                if (!gReduceMotion) ball.transform = CGAffineTransformMakeTranslation(18, 0);
            }
            // v48 · G55 修复：拖动起步阈值 —— 不再用 requireGestureRecognizerToFail。
            //   v47 的 [pan requireGestureRecognizerToFail:tap] 让 pan 必须等 tap 失败，
            //   而 tap 失败要求手指位移超过其容差（约 10pt）→ 用户按住球心往外拖，
            //   得拖到接近球边缘（半径 28pt）才跟手，手感就是「拖不动 / 只有边上能动」。
            //   本版：两个手势**并存识别**（shouldRecognizeSimultaneously 返回 YES），
            //   由 ballDragged: 内部按累计位移自行判定「这是拖动还是轻点」——
            //   位移 < 6pt 不动（留给 tap），≥ 6pt 才真正拖窗口并主动让 tap 失败。
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
                                           initWithTarget:gFT action:@selector(ballTapped:)];
            [ball addGestureRecognizer:tap];
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
                                           initWithTarget:gFT action:@selector(ballDragged:)];
            if (@available(iOS 10.0, *)) pan.maximumNumberOfTouches = 1;
            pan.minimumNumberOfTouches = 1;
            [ball addGestureRecognizer:pan];
            // 两者同时挂着，靠 delegate 允许并存、靠位移阈值区分语义（见上）
            tap.delegate = gFT;
            pan.delegate = gFT;
            [host addSubview:ball];
        } else {
            CGFloat w = 280, h = 380;   // v41：360 → 380，为底部 44pt 大按钮让出空间
            CGFloat ox = MIN(MAX(c.x - w / 2, 8), sc.width  - w - 8);
            CGFloat oy = MIN(MAX(c.y - h / 2, 70), sc.height - h - 8);
            gFloatWindow.frame = CGRectMake(ox, oy, w, h);
            UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, h)];
            panel.layer.cornerRadius = 14; panel.layer.masksToBounds = YES;
            panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.90];

            // L3 头部：状态形状 + 任务名。v43 对齐原型 .p-hd —— 原型里形状与标题是**两个元素**：
            //   .p-hd{display:flex;align-items:center;gap:var(--sp2)=8px}
            //   .p-hd .sy{font-size:15px}
            //   .p-hd h3{font-size:var(--fz-3);font-weight:650;flex:1}
            // 上一版把形状和任务名塞进同一个 label 并统一用状态色（14px），于是标题颜色跟着状态变、
            // 形状也没了 15px 的层级。这里拆开：形状独立着色 15px，标题恒白。
            // v45 修正：h3 字号我上一版写成 13px 并注释成「--fz-2=13px」——**抄错了 token**：
            //   原型取的是 var(--fz-3)，而 --fz-3 = **14px**（--fz-2 才是 13px）。差 1px 看似无所谓，
            //   但「抄 token 名」本身就是 G47 那类「以为差不多」的具体形态，必须回令牌表核。
            NSString *stP = (gTaskTotal > 0) ? gTaskState : @"idle";
            if (gTaskTotal > 0 && gTaskOk == 0) stP = @"fail";
            UILabel *syP = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, 18, 22)];
            syP.text = AIShapeFor(stP);
            syP.textColor = AIColorFor(stP);
            syP.font = [UIFont boldSystemFontOfSize:15];     // 原型 .p-hd .sy{font-size:15px}
            syP.textAlignment = NSTextAlignmentCenter;
            [panel addSubview:syP];
            UILabel *ti = [[UILabel alloc] initWithFrame:CGRectMake(12 + 18 + 8, 8, w - 12 - 18 - 8 - 82, 22)];
            ti.text = (gTaskName.length ? gTaskName : @"无任务");
            ti.textColor = [UIColor whiteColor];             // 原型 .p-hd h3 是 --txt 白，不随状态着色
            ti.font = [UIFont boldSystemFontOfSize:14];      // 原型 .p-hd h3{font-size:var(--fz-3)=14px}（v45 修：原写 13px 抄错 token）
            ti.lineBreakMode = NSLineBreakByTruncatingTail;
            [panel addSubview:ti];
            // v44：头部补 「3/7」步数（原型 .p-hd .stepno{font-size:11px;color:var(--txt-2)}）。
            // 原型的头部信息是「形状 标题 步数 ✕」四段；上一版把步数塞进了第二行副标题，
            // 于是「一眼看到第几步」变成了「要读一行小字」——头部就要给结论，这是层级设计。
            UILabel *sno = [[UILabel alloc] initWithFrame:CGRectMake(w - 82, 10, 36, 18)];
            sno.textAlignment = NSTextAlignmentRight;
            sno.text = (gTaskTotal > 0)
                ? [NSString stringWithFormat:@"%d/%d", gTaskIdx, gTaskTotal] : @"";
            sno.font = [UIFont systemFontOfSize:11];
            sno.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.88];   // 原型 --txt-2
            [panel addSubview:sno];
            UIButton *cx = [UIButton buttonWithType:UIButtonTypeSystem];
            // v44：对齐原型 .p-close —— 30×30 圆角 8 的 ✕ 图标按钮（原为「收起」纯文字 44×26）。
            // 文字按钮占宽且与「暂停/结束」语义不够区分；✕ 是通用关闭语汇，且留出头部步数位。
            cx.frame = CGRectMake(w - 42, 6, 30, 30);
            [cx setTitle:@"✕" forState:UIControlStateNormal];
            cx.titleLabel.font = [UIFont systemFontOfSize:13];
            cx.layer.cornerRadius = 8;
            cx.layer.borderWidth = 1;
            cx.layer.borderColor = [[UIColor whiteColor] colorWithAlphaComponent:0.10].CGColor;  // 原型 --line
            [cx setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            [cx addTarget:gFT action:@selector(collapse:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:cx];

            UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(12, 30, w - 24, 30)];
            st.numberOfLines = 2; st.font = [UIFont systemFontOfSize:11];
            st.textColor = [UIColor lightGrayColor];
            // v42：副标题加成功计数（规划 §9.5 要求「成功 ✓/✗」可见）。
            // 计数先算好再格式化 —— C99 里别把逻辑塞进格式化参数。
            int okCnt = 0;
            for (NSDictionary *d in gSteps) if ([d[@"s"] isEqualToString:@"ok"]) okCnt++;
            st.text = (gTaskTotal > 0)
                ? [NSString stringWithFormat:@"步骤 %d/%d · 成功 ✓%d · %@",
                   gTaskIdx, gTaskTotal, okCnt, AITaskLine()]
                : [NSString stringWithFormat:@"空闲待命 · %@", kAIVer];
            [panel addSubview:st];

            // v42：步骤列表改为独立行视图（原型 .step）。
            // 旧实现把 30~60 条步骤 appendFormat 成一块 9px Menlo 纯文本塞进 UITextView：
            // 无结构、无着色、无色阶层次 —— 用户对比原型后一句「界面还是原来的」即指此处。
            // 现改为 UIScrollView 内逐行 AIStepRowView：图标/动作/目标/证据/分隔线，按状态着色。
            // v43：底部预留 152 → 174，为新增的 .recap 本轮回顾行（16px + 上分隔线 + 间距）腾位。
            // 顺序（自上而下）：步骤区 / recap行 / 诊断 / 复制 / 暂停+结束。
            CGFloat stepsY = 62, stepsH = h - 174 - stepsY;
            UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(10, stepsY, w - 20, stepsH)];
            sv.backgroundColor = [UIColor colorWithWhite:0.13 alpha:1.0];
            sv.layer.cornerRadius = 8; sv.clipsToBounds = YES;
            sv.showsVerticalScrollIndicator = YES;
            CGFloat ry = 2;
            if (gSteps.count) {
                for (NSDictionary *d in gSteps) {
                    UIView *row = AIStepRowView(d, w - 20);
                    row.frame = CGRectMake(0, ry, w - 20, row.frame.size.height);
                    [sv addSubview:row];
                    ry += row.frame.size.height;
                }
            } else {
                UILabel *empty = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, w - 44, 18)];
                empty.text = @"（暂无步骤记录）";
                empty.font = [UIFont systemFontOfSize:12];
                empty.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.55];
                [sv addSubview:empty];
            }
            sv.contentSize = CGSizeMake(w - 20, MAX(ry + 4, stepsH));
            [panel addSubview:sv];

            // v43：面板底部「本轮回顾」行（原型 .recap）——v42 漏做的一处结构。
            //   原型：.recap{display:flex;justify-content:space-between;padding:8px 12px;font-size:11px;
            //                border-top:1px solid var(--line)}  内容「本轮回顾」…「N/M 成功 · <证据>」
            // 为什么要有：回顾卡是「任务结束时的强提示」，一旦点掉就没了；面板里这行是**随时可查**的
            //   常驻摘要，二者不是一个东西，缺了它用户错过弹卡就没有任何地方能看到本轮战绩。
            // 只在有结论时显示（与原型 recap.style.display = rec?'flex':'none' 同判据）。
            if (gTaskTotal > 0) {
                UIView *rline = [[UIView alloc] initWithFrame:CGRectMake(10, h - 174, w - 20, 1)];
                rline.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.10];   // 原型 --line
                [panel addSubview:rline];
                UILabel *rl = [[UILabel alloc] initWithFrame:CGRectMake(12, h - 172, 60, 16)];
                rl.text = @"本轮回顾";
                rl.font = [UIFont systemFontOfSize:11];
                rl.textColor = [UIColor lightGrayColor];
                [panel addSubview:rl];
                UILabel *rr = [[UILabel alloc] initWithFrame:CGRectMake(72, h - 172, w - 84, 16)];
                rr.textAlignment = NSTextAlignmentRight;
                rr.font = [UIFont systemFontOfSize:11];
                rr.textColor = [UIColor lightGrayColor];
                rr.lineBreakMode = NSLineBreakByTruncatingHead;
                rr.text = [NSString stringWithFormat:@"%d/%d 成功 · %@", okCnt, gTaskTotal,
                           (gTaskResult.length ? gTaskResult : @"—")];
                [panel addSubview:rr];
            }

            // 诊断区（默认折叠）：HUD 退役后，网络/版本/中继只在这里
            UIButton *dg = [UIButton buttonWithType:UIButtonTypeSystem];
            dg.frame = CGRectMake(10, h - 146, w - 20, 28);          // v42：随布局上移到步骤区下方
            [dg setTitle:(gPanelDiag ? @"▾ 诊断 · 收起" : @"▸ 诊断 · 网络/版本") forState:UIControlStateNormal];
            dg.titleLabel.font = [UIFont systemFontOfSize:12];
            dg.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
            [dg addTarget:gFT action:@selector(toggleDiag:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:dg];
            if (gPanelDiag) {
                // v42：诊断详情改为向下展开会压到复制按钮，故整体上移并压到步骤区之上（覆盖式浮层）
                UIView *dbox = [[UIView alloc] initWithFrame:CGRectMake(10, h - 190, w - 20, 42)];
                dbox.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
                dbox.layer.cornerRadius = 6;
                UILabel *dl = [[UILabel alloc] initWithFrame:CGRectMake(2, 0, w - 24, 42)];
                dl.numberOfLines = 3; dl.font = [UIFont fontWithName:@"Menlo" size:9];
                dl.textColor = [UIColor lightGrayColor];
                dl.text = [NSString stringWithFormat:@"%@ 心跳✅%d❌%d 令%d\n%@\n%@",
                           kAIVer, gPollOK, gPollErr, gCmdGot,
                           (gActiveBase ?: (gBase ?: @"-")),
                           (gLastErrText.length ? gLastErrText : @"无错误")];
                [dbox addSubview:dl];
                [panel addSubview:dbox];
            }
            // v42：复制步骤全文（规划 §2 L3 控件）。步骤列表改行视图后文字不再可直接选中，
            //       需要一个显式出口把完整 trace 拿走。
            UIButton *cp = [UIButton buttonWithType:UIButtonTypeSystem];
            cp.frame = CGRectMake(10, h - 112, w - 20, 32);
            [cp setTitle:@"⧉ 复制步骤全文" forState:UIControlStateNormal];
            cp.titleLabel.font = [UIFont systemFontOfSize:12];
            cp.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.08];
            cp.layer.cornerRadius = 8;
            [cp addTarget:gFT action:@selector(copySteps:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:cp];
            // 安全控件：唯一能打断 AI 的入口。
            // v41：32 → 44 高。原注释写着「≥44pt 原则」实际只做了 32，触摸目标不达标 ——
            //       这是安全入口（唯一能叫停 AI 的地方），不能靠"宽度够"自我说服。
            UIButton *pz = [UIButton buttonWithType:UIButtonTypeSystem];
            pz.frame = CGRectMake(10, h - 54, (w - 30) / 2.0, 44);
            [pz setTitle:@"⏸ 暂停" forState:UIControlStateNormal];
            pz.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.12];
            pz.layer.cornerRadius = 10;
            pz.titleLabel.font = [UIFont boldSystemFontOfSize:13];   // v45：14→13 回原型 .pbtn{--fz-2=13px}
            [pz addTarget:gFT action:@selector(pauseTask:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:pz];
            UIButton *ed = [UIButton buttonWithType:UIButtonTypeSystem];
            ed.frame = CGRectMake(20 + (w - 30) / 2.0, h - 54, (w - 30) / 2.0, 44);
            [ed setTitle:@"⏹ 结束" forState:UIControlStateNormal];
            ed.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.12];
            ed.layer.cornerRadius = 10;
            ed.titleLabel.font = [UIFont boldSystemFontOfSize:13];   // v45：14→13 回原型 .pbtn{--fz-2=13px}
            [ed addTarget:gFT action:@selector(endTask:) forControlEvents:UIControlEventTouchUpInside];
            [panel addSubview:ed];
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
