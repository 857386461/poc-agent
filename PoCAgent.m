//
//  PoCAgent.m
//  TrollStore 注入链路验证 —— 阶段 A / 阶段 B
//
//  阶段 A：验证 task_for_pid 能否拿到其他进程的 task port
//  阶段 B：验证 mach_vm_allocate / mach_vm_write / mach_vm_read 往返是否可用
//
//  编译方式见 build.sh（需 macOS + Xcode Command Line Tools）
//  安装方式：TrollStore 持久化安装，建议勾选 "Install as System App"
//

#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/error.h>
#import <unistd.h>
#import <string.h>

// 部分 iOS SDK 未公开声明 task_for_pid，这里显式声明（签名与 XNU 内核一致）
extern kern_return_t task_for_pid(mach_port_name_t target_tport,
                                  int              pid,
                                  mach_port_name_t *t);

static UITextView      *gLogView = nil;
static NSMutableString *gLog     = nil;

static void POCLog(NSString *line) {
    NSLog(@"[POC] %@", line);
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

typedef struct {
    pid_t       pid;
    mach_port_t task;
} POCVictim;

#pragma mark - 阶段 A：task_for_pid

static POCVictim POC_StageA(void) {
    POCVictim victim = { -1, MACH_PORT_NULL };

    POCLog(@"===== 阶段 A：task_for_pid 权限验证 =====");

    pid_t selfPid = getpid();
    int   ok      = 0;
    int   others  = 0;

    for (pid_t pid = 1; pid < 5000; pid++) {
        mach_port_t   task = MACH_PORT_NULL;
        kern_return_t kr   = task_for_pid(mach_task_self(), pid, &task);

        if (kr == KERN_SUCCESS && task != MACH_PORT_NULL) {
            ok++;
            if (pid != selfPid) {
                others++;
                // 保留第一个「非自身」进程作为阶段 B 的操作对象
                if (victim.task == MACH_PORT_NULL) {
                    victim.pid  = pid;
                    victim.task = task;
                }
                if (others <= 8) {
                    POCLog([NSString stringWithFormat:@"  pid=%d  task=0x%08X  [OK]", pid, task]);
                }
            }
        }
    }

    if (others == 0) {
        POCLog([NSString stringWithFormat:@"结果：FAILED  可访问进程数=%d（仅自身=%d）", ok, selfPid]);
        POCLog(@"判定：entitlement 未生效，注入链路不成立");
        POCLog(@"排查 1：ent.plist 是否随 IPA 一起打包并参与签名");
        POCLog(@"排查 2：TrollStore 是否以 System App 方式安装");
        POCLog(@"排查 3：iOS 小版本是否超出 CoreTrust 漏洞可用范围");
    } else {
        POCLog([NSString stringWithFormat:@"结果：PASSED  可访问其他进程 %d 个，样本 pid=%d", others, victim.pid]);
        POCLog(@"判定：已具备跨进程访问能力，可继续阶段 B");
    }
    return victim;
}

#pragma mark - 阶段 B：远程内存读写

static void POC_StageB(POCVictim victim) {
    if (victim.task == MACH_PORT_NULL) {
        POCLog(@"阶段 B 跳过：未取得有效 task port");
        return;
    }

    POCLog(@"===== 阶段 B：远程内存读写验证 =====");
    POCLog([NSString stringWithFormat:@"目标 pid=%d", victim.pid]);

    // 1. 在目标进程分配内存
    mach_vm_address_t remote = 0;
    kern_return_t kr = mach_vm_allocate(victim.task, &remote, 4096, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        POCLog([NSString stringWithFormat:@"mach_vm_allocate 失败: %s", mach_error_string(kr)]);
        return;
    }
    POCLog([NSString stringWithFormat:@"  allocate @0x%llX  [OK]", remote]);

    // 2. 写入一段特征字符串
    const char        *payload = "POC-HELLO-FROM-AGENT";
    mach_msg_type_number_t len = (mach_msg_type_number_t)strlen(payload) + 1;

    kr = mach_vm_write(victim.task, remote, (vm_offset_t)payload, len);
    if (kr != KERN_SUCCESS) {
        POCLog([NSString stringWithFormat:@"mach_vm_write 失败: %s", mach_error_string(kr)]);
        mach_vm_deallocate(victim.task, remote, 4096);
        return;
    }
    POCLog([NSString stringWithFormat:@"  write %u bytes  [OK]", len]);

    // 3. 读回校验
    char               buf[64]  = {0};
    mach_vm_size_t     outSize  = 0;
    kr = mach_vm_read_overwrite(victim.task,
                                remote,
                                (mach_vm_size_t)len,
                                (mach_vm_address_t)buf,
                                &outSize);
    if (kr != KERN_SUCCESS) {
        POCLog([NSString stringWithFormat:@"mach_vm_read_overwrite 失败: %s", mach_error_string(kr)]);
        mach_vm_deallocate(victim.task, remote, 4096);
        return;
    }
    POCLog([NSString stringWithFormat:@"  read back: \"%s\"  [OK]", buf]);

    mach_vm_deallocate(victim.task, remote, 4096);

    if (strcmp(buf, payload) == 0) {
        POCLog(@"结果：PASSED  对目标进程拥有完整内存读写权");
        POCLog(@"判定：注入的前置条件已全部满足，下一步可实施 dylib 注入");
    } else {
        POCLog(@"结果：FAILED  读回内容与写入不一致");
    }
}

#pragma mark - UI

@interface POCRootViewController : UIViewController
@end

@implementation POCRootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"PoC Agent";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    gLogView = [[UITextView alloc] initWithFrame:CGRectZero];
    gLogView.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    gLogView.editable = NO;
    gLogView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:gLogView];

    UIButton *runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [runButton setTitle:@"开始验证" forState:UIControlStateNormal];
    runButton.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    runButton.translatesAutoresizingMaskIntoConstraints = NO;
    [runButton addTarget:self action:@selector(runTest) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:runButton];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [runButton.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12.0],
        [runButton.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [gLogView.topAnchor constraintEqualToAnchor:runButton.bottomAnchor constant:12.0],
        [gLogView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12.0],
        [gLogView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12.0],
        [gLogView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12.0],
    ]];

    // 支持被 URL Scheme 唤醒后自动执行（快捷指令自动化用）
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(runTest)
                                                 name:@"POCRunNotification"
                                               object:nil];

    POCLog(@"就绪。点上方按钮开始，或用 pocagent://run 从快捷指令唤起。");
}

- (void)runTest {
    POCLog(@"======================================");
    POCLog([NSString stringWithFormat:@"自身 pid=%d", getpid()]);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        POCVictim victim = POC_StageA();
        POC_StageB(victim);
        POCLog(@"======================================");
    });
}

@end

@interface POCAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation POCAppDelegate

- (BOOL)application:(UIApplication *)application
didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.backgroundColor = [UIColor whiteColor];

    POCRootViewController *root = [[POCRootViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:root];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

- (BOOL)application:(UIApplication *)app
            openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    POCLog([NSString stringWithFormat:@"被 URL 唤醒: %@", url.absoluteString]);
    if ([url.host isEqualToString:@"run"] || [url.scheme isEqualToString:@"pocagent"]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:@"POCRunNotification" object:nil];
        });
    }
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        gLog = [NSMutableString string];
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([POCAppDelegate class]));
    }
}
