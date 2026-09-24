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
#import <mach/vm_param.h>
#import <mach/error.h>
#import <unistd.h>
#import <string.h>

// 新版 iOS SDK 的 mach/mach_vm.h 内含 #error 占位（Apple 从未在 iOS 上公开它），
// 因此不 import 该头文件，改为显式声明所用函数；
// 所需类型（mach_vm_address_t / mach_vm_size_t / vm_map_t / vm_offset_t /
// mach_msg_type_number_t）均定义于公开的 mach/vm_types.h、mach/mach_types.h，
// 由 <mach/mach.h> 间接引入。符号本体位于 libsystem_kernel.dylib。
// 注意：签名必须与 XNU 实现完全一致。

// task_for_pid / mach_vm_* 均为跨进程特权接口，
// 需配合 ent.plist 中的 task-ports / get-task-allow entitlement 使用
extern kern_return_t task_for_pid(mach_port_name_t target_tport,
                                  int              pid,
                                  mach_port_name_t *t);

// 只读 task port 通道：对应 entitlement com.apple.system-task-ports.read，
// 权限低于 task_for_pid，但可读目标内存（iOS 14+ 引入，AMFI 检查更宽松）
extern kern_return_t task_read_for_pid(mach_port_name_t target_tport,
                                       int              pid,
                                       mach_port_name_t *t);

extern kern_return_t mach_vm_allocate(vm_map_t           target,
                                      mach_vm_address_t  *address,
                                      mach_vm_size_t     size,
                                      int                flags);

extern kern_return_t mach_vm_write(vm_map_t              target_task,
                                   mach_vm_address_t     address,
                                   vm_offset_t           data,
                                   mach_msg_type_number_t dataCnt);

extern kern_return_t mach_vm_read_overwrite(vm_map_t          target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t    size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t    *outsize);

extern kern_return_t mach_vm_deallocate(vm_map_t          target_task,
                                        mach_vm_address_t address,
                                        mach_vm_size_t    size);

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
    int         read_only;   // 1 = 只读 port（task_read_for_pid 所得）
} POCVictim;

#pragma mark - 阶段 A：task_for_pid

static POCVictim POC_StageA(void) {
    POCVictim victim = { -1, MACH_PORT_NULL, 0 };

    POCLog(@"===== 阶段 A：task_for_pid 权限验证 =====");

    pid_t selfPid     = getpid();
    int   others_full = 0;
    int   others_read = 0;

    // task_for_pid 失败错误码分布（最多记 8 种），用于远程判定拦截层
    kern_return_t errKeys[8];
    int           errCounts[8];
    int           errN = 0;

    for (pid_t pid = 1; pid < 5000; pid++) {
        mach_port_t   task = MACH_PORT_NULL;
        kern_return_t kr   = task_for_pid(mach_task_self(), pid, &task);

        if (kr != KERN_SUCCESS) {
            int found = 0;
            for (int i = 0; i < errN; i++)
                if (errKeys[i] == kr) { errCounts[i]++; found = 1; break; }
            if (!found && errN < 8) { errKeys[errN] = kr; errCounts[errN] = 1; errN++; }
            continue;
        }
        if (task == MACH_PORT_NULL) continue;
        if (pid == selfPid) continue;

        others_full++;
        if (victim.task == MACH_PORT_NULL) {
            victim.pid = pid; victim.task = task; victim.read_only = 0;
        }
        if (others_full <= 8)
            POCLog([NSString stringWithFormat:@"  task_for_pid pid=%d  [OK 完整]", pid]);
    }

    // 完整通道全灭时，试只读通道
    if (others_full == 0) {
        for (pid_t pid = 1; pid < 5000; pid++) {
            mach_port_t   task = MACH_PORT_NULL;
            kern_return_t kr   = task_read_for_pid(mach_task_self(), pid, &task);
            if (kr != KERN_SUCCESS || task == MACH_PORT_NULL || pid == selfPid) continue;

            others_read++;
            if (victim.task == MACH_PORT_NULL) {
                victim.pid = pid; victim.task = task; victim.read_only = 1;
            }
            if (others_read <= 8)
                POCLog([NSString stringWithFormat:@"  task_read_for_pid pid=%d  [OK 只读]", pid]);
        }
    }

    NSMutableString *eb = [NSMutableString string];
    for (int i = 0; i < errN; i++)
        [eb appendFormat:@"0x%X(%d次) ", errKeys[i], errCounts[i]];
    if (errN)
        POCLog([NSString stringWithFormat:@"task_for_pid 错误分布: %@", eb]);

    if (others_full == 0 && others_read == 0) {
        POCLog(@"结果：FAILED  两种通道均可访问其他进程 0 个");
        POCLog(@"判定：当前安装方式下 entitlement 未被 AMFI 放行");
        POCLog(@"排查 1：是否用『Install as System App』方式安装（no-sandbox 必需）");
        POCLog(@"排查 2：是否为 C 版（含 platform-application）；B 版无 no-sandbox 本就受限");
        POCLog(@"排查 3：iOS 小版本是否超出 TrollStore (CoreTrust) 适用范围");
    } else if (others_full > 0) {
        POCLog([NSString stringWithFormat:@"结果：PASSED  完整 task_for_pid 可用，其他进程 %d 个，样本 pid=%d", others_full, victim.pid]);
        POCLog(@"判定：已具备跨进程完整访问能力，可继续阶段 B");
    } else {
        POCLog([NSString stringWithFormat:@"结果：PARTIAL  完整端口 0 个，只读端口 %d 个（样本 pid=%d）", others_read, victim.pid]);
        POCLog(@"判定：仅只读通道生效；写入/注入仍需完整权限（C 版 + System App 安装）");
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
    POCLog([NSString stringWithFormat:@"目标 pid=%d（%s port）", victim.pid, victim.read_only ? "只读" : "完整"]);
    if (victim.read_only) {
        POCLog(@"目标为只读 port：写入验证需完整 task_for_pid（C 版 + System App 安装后再测）");
        POCLog(@"阶段 B 结束（只读通道已证明跨进程访问链路部分打通）");
        return;
    }

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
