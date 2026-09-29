#!/usr/bin/env python3
"""微信自动走位：每一步都用 probe 实测坐标，绝不靠读视图树猜。

用法：
    python3 wayfind.py probe 22 69          # 看某点命中什么
    python3 wayfind.py tapui 22 69          # 触发某点的控件
    python3 wayfind.py tree [out.txt]       # 取视图树
    python3 wayfind.py find <关键词>         # 在视图树里搜关键词，返回候选点
    python3 wayfind.py go                   # 一键：当前页 -> 朋友圈
    python3 wayfind.py macro '<JSON数组>' [gap毫秒]   # v16：一串动作一次下发本地连跑
    python3 wayfind.py back                 # v18：返回一页（自动 pop/dismiss）
    python3 wayfind.py nav                  # v18：dump 当前导航栈
"""
import sys, time, json, re, os
sys.path.insert(0, '/workspace/ios-poc')
from relayctl import post, get

# ---- 设备 id（能力层不该把某一台机器的 id 焊死）----
# 坑（2026-09-30 实测发现，长期潜伏）：这里原先硬编码微信 POC 时代的
#   68814FAE-730A-42C5-865B-4EB10F445282 —— 那台设备早已下线，队列里堆着没人消费的死命令。
#   后果：wayfind 的所有全局函数（text/tree/probe/scroll…）**静默失效**，
#   表现为 wait_op 一路超时、G13 看门狗误报「手机端 hang」（其实手机活得好好的，只是 id 错了）。
#   所有调用方（ks.py / pages_tour.py …）都在各自文件里手动覆盖 wayfind.DEV 才没暴露。
#   现在改为：优先读环境变量 AI_DEV，缺省用当前在册真机。要用别的机器就
#       AI_DEV=xxx python3 wayfind.py …   或   import wayfind; wayfind.DEV = "xxx"
DEV = os.environ.get("AI_DEV", "287CD2D8-3281-42F7-9B51-5AE3FF4426D4")

# ---- G13 看门狗 ----
# 坑：dylib 的轮询线程偶尔 hang 死（命令下去永远不回执，心跳也停），且无自愈。
# 现象：wait_op 一路超时，AI 侧看不出来是「这次慢」还是「手机死了」，
#       只能干等到最后才发现白等。恢复办法一直是：杀进程重开。
# 判据：超时后补发一条最轻的 status 探活，连它都不回 = 手机端已 hang。
WD_TMO = 10          # 探活 status 只等 10 秒（正常 1~2 秒就回）
WD_HANG = {"ts": 0.0, "op": ""}     # 最近一次判定 hang 的时刻与当时的 op


def wait_op(op, t0, timeout=25, after_ts=0, dev=None, wd=True):
    # after_ts：本次请求【发出前】服务端上该 op 的最后 ts。
    # 必须要求新结果的 ts 严格大于它，否则会读到上一次的旧数据 ——
    # 实测中连续 probe 出现过 y=86 和 y=142 返回同一个值的串扰。
    d = dev or DEV
    while time.time() - t0 < timeout:
        time.sleep(0.35)
        r = (get("/report?dev=%s&op=%s" % (d, op)).get("data") or {})
        if r.get("op") == op and r.get("ts", 0) > max(after_ts, t0 - 3):
            return r
    # 超时了：先分清是「这次真的慢」还是「手机 hang 了」
    if wd and op != "status" and not alive(dev=d):
        WD_HANG["ts"], WD_HANG["op"] = time.time(), op
        print("  ⚠️ G13：手机端轮询线程已 hang（%s 超时 %ds，连 status 探活都不回）\n"
              "     恢复办法 = 杀掉 App 进程重开；App 退后台也会这样，先切回前台再试。"
              % (op, timeout))
    return None


def _last_ts(op, dev=None):
    d = (get("/report?dev=%s&op=%s" % (dev or DEV, op)).get("data") or {})
    return d.get("ts", 0) if d.get("op") == op else 0


def alive(dev=None, timeout=WD_TMO):
    """最轻的一次判活：发 status，能答就说明手机端轮询线程还活着。
    回执 dict / None（None = hang 或 App 不在前台）。"""
    d = dev or DEV
    prev = _last_ts("status", d)
    post("/cmd", {"dev": d, "op": "status"})
    return wait_op("status", time.time(), timeout=timeout, after_ts=prev,
                   dev=d, wd=False)


def hung(max_age=120):
    """最近 max_age 秒内是否判定过 hang。长任务循环里拿它做提前中止。"""
    return (time.time() - WD_HANG["ts"]) < max_age


def doctor(verbose=True):
    """一把自检：设备 id 对不对 / 回执通不通 / 三大原语活不活。

    为什么需要：2026-09-30 实测踩到「DEV 硬编码成一台已下线设备」——
    所有全局函数静默失效，而 G13 看门狗把它误报成「手机端 hang」，
    排查方向完全跑偏。以后开工先跑这个，别先怀疑手机。

    返回 dict：
      dev        当前用的设备 id
      online     /peek 里这台设备在不在（在册 = 有 beatAge）
      beat_age   心跳秒龄（<20 健康）
      dead_queue 该 dev 之外的残留队列（有值 = 有人往错设备发过命令）
      status     status 回执能否收到
      ver/lib    回执里的版本与注入库名
      text_ok    text 原语可用（最长 25s）
      ocr_ok     ocr 原语可用
    """
    out = {"dev": DEV}
    # 1) 探活：这台设备在不在 / 心跳多新 / 有没有错设备的死队列
    try:
        pk = get("/peek") or {}
    except Exception as e:
        out["err"] = "peek 失败: %s" % e
        if verbose: print("  ✗ 中继不可达:", e)
        return out
    beat = (pk.get("beatAge") or {})
    devs = (pk.get("devices") or {})
    qs = (pk.get("queues") or {})
    out["online"] = DEV in beat
    out["beat_age"] = beat.get(DEV)
    out["dead_queue"] = {k: v for k, v in qs.items() if k != DEV and v}
    if verbose:
        if out["online"]:
            print("  ✓ 设备在册 %s  心跳 %ss  前台队列 %s" % (DEV[:8], out["beat_age"], devs.get(DEV, 0)))
        else:
            print("  ✗ 设备不在册！DEV=%s（手机没连/前台不是目标 App/中继没收到心跳）" % DEV)
        if out["dead_queue"]:
            print("  ⚠ 存在非本设备的残留队列 %s —— 有人往错 id 发过命令" % out["dead_queue"])

    # 2) status 回执
    d = None
    try:
        prev = _last_ts("status")
        post("/cmd", {"dev": DEV, "op": "status"})
        d = wait_op("status", time.time(), timeout=WD_TMO, after_ts=prev, wd=False)
    except Exception as e:
        out["err"] = str(e)
    out["status"] = bool(d)
    if d:
        out["ver"] = d.get("ver"); out["lib"] = (d.get("lib") or "").split("/")[-1]
        out["proc"] = d.get("proc")
    if verbose:
        if d:
            print("  ✓ status 通  ver=%s  proc=%s  lib=%s" % (out.get("ver"), out.get("proc"), out.get("lib")))
        else:
            print("  ✗ status 无回执 —— 若设备在册，问题在 Android/dylib 侧；若不在册，先查 DEV")

    # 3) text（视图树）
    t = None
    try:
        t = text(show=False)
    except Exception as e:
        out["err_text"] = str(e)
    out["text_ok"] = bool(t)
    if verbose:
        print("  %s text 原语（视图树 %d 字符）" % ("✓" if t else "✗", len(t or "")))

    # 4) ocr（屏幕识字 —— App 无关的核心原语）
    o = None
    try:
        o = ocr(n=25)
    except Exception as e:
        out["err_ocr"] = str(e)
    items = (o or {}).get("items") if isinstance(o, dict) else None
    out["ocr_ok"] = bool(items)
    out["ocr_n"] = len(items or [])
    if verbose:
        print("  %s ocr 原语（读到 %d 条文字）" % ("✓" if items else "✗", len(items or [])))
        if items:
            print("     屏幕样本: %s" % " | ".join(i.get("t", "") for i in items[:6]))
    return out


def macro(steps, gap=700, timeout=60, verbose=True):
    """v16：一串动作一次下发，手机本地连跑。往返只有一次。"""
    prev = _last_ts("macro")
    post("/cmd", {"dev": DEV, "op": "macro", "gap": gap, "steps": steps})
    t0 = time.time()
    d = wait_op("macro", t0, timeout=timeout, after_ts=prev)
    if not d:
        print("  macro 超时")
        return None
    if verbose:
        for r in (d.get("results") or []):
            print("  [%s] %-8s ok=%s %s" % (r.get("i"), r.get("op"), r.get("ok"),
                                            r.get("txt") or r.get("err") or ""))
    return d


def scroll(x, y, dy, dx=0, anim=True, pause=0.2):
    """v17：直接改 UIScrollView.contentOffset。判据看 moved，不看 ok。"""
    time.sleep(pause)
    prev = _last_ts("scroll")
    post("/cmd", {"dev": DEV, "op": "scroll", "x": x, "y": y,
                  "dy": dy, "dx": dx, "anim": anim})
    t0 = time.time()
    d = wait_op("scroll", t0, after_ts=prev)
    if not d:
        print("  scroll 超时")
        return None
    i = d.get("info", {})
    print("  scroll dy=%.0f -> %s before=%s after=%s moved=%s" %
          (dy, i.get("sv"), i.get("before"), i.get("after"), i.get("moved")))
    return i


def probe(x, y, verbose=True, pause=0.2):
    time.sleep(pause)                      # 给上一条指令留处理时间，避免队列串扰
    prev = _last_ts("probe")               # 发之前先记下旧 ts
    post("/cmd", {"dev": DEV, "op": "probe", "x": x, "y": y})
    t0 = time.time()
    d = wait_op("probe", t0, after_ts=prev)
    if not d:
        print("probe 超时")
        return None
    info = d.get("info", {})
    if verbose:
        print("  probe(%.0f,%.0f) -> 命中:%s 控件:%s 中心:%s 第%s层父" %
              (x, y, info.get("hit"), info.get("ctrl"),
               info.get("ctrlCenter"), info.get("ctrlUp")))
    return info


def tapui(x, y, pause=0.2):
    time.sleep(pause)
    prev = _last_ts("tapui")
    post("/cmd", {"dev": DEV, "op": "tapui", "x": x, "y": y})
    t0 = time.time()
    d = wait_op("tapui", t0, after_ts=prev)
    if not d:
        print("  tapui 超时")
        return None
    print("  tapui(%.0f,%.0f) -> ok=%s act=%s %s" %
          (x, y, d.get("ok"), d.get("act"), d.get("desc", "")))
    return d


def tree(out=None, pause=0.2):
    time.sleep(pause)
    prev = _last_ts("tree")
    post("/cmd", {"dev": DEV, "op": "tree"})
    t0 = time.time()
    d = wait_op("tree", t0, after_ts=prev)
    t = (d or {}).get("tree", "")
    if out:
        open(out, 'w').write(t)
    print("  tree: %d 行" % len(t.splitlines()))
    return t


def find(kw, save=None):
    """在视图树里搜关键词，打印带屏幕坐标的候选（坐标是相对父 view 的，仅供参考）"""
    t = tree(save)
    hits = [l for l in t.splitlines() if kw.lower() in l.lower()]
    print("  搜 '%s' -> %d 条:" % (kw, len(hits)))
    for h in hits[:15]:
        print("   ", h.strip())
    return hits


def has(kw):
    t = tree()
    return kw in t


# ---- v19：读界面文本（带窗口坐标），陌生 App 导航刚需 ----
def text(kw=None, pause=0.2, show=True):
    """v19+：读界面上所有文字（带屏幕坐标）。陌生 App 导航全靠它。"""
    time.sleep(pause)
    prev = _last_ts("text")
    post("/cmd", {"dev": DEV, "op": "text", **({"kw": kw} if kw else {})})
    t0 = time.time()
    d = wait_op("text", t0, after_ts=prev)
    if not d:
        print("  text 超时"); return ""
    t = d.get("text", "") or ""
    if show:
        print("  text: %d 行" % len([l for l in t.splitlines() if l.strip()]))
        for l in t.splitlines()[:60]:
            print("   ", l)
    return t


def dump(x, y, deep=2, pause=0.2):
    """v21+：挖某个坐标上那个对象的所有属性（自绘控件的文字常常藏在这里）。"""
    d = _op("dump", {"x": x, "y": y, "deep": deep},
            lambda r: print(r.get("text", "")))
    return (d or {}).get("text", "")


def update(url, ver, pause=0.2):
    """v20：把一份新 dylib 推到手机上（下次重开 App 生效）。"""
    d = _op("update", {"url": url, "ver": str(ver)}, lambda r: print("  update:", r.get("txt")))
    return (d or {}).get("txt", "")


def core(pause=0.2):
    """v20：看手机本地缓存了哪些 core 版本。"""
    d = _op("core", {}, lambda r: print("  core: 当前=%s 待生效=%s 文件=%s"
                                        % (r.get("ver"), r.get("pending") or "-", r.get("files"))))
    return d or {}


def ball(on=True, pause=0.2):
    """v20：悬浮球显隐。"""
    return _op("ball", {"on": 1 if on else 0}, lambda r: print("  ball:", r.get("visible")))


def task(name="", step="", idx=0, total=0, ok=None):
    """v30：任务态下发 -> 悬浮球显示「任务名 进度 / 当前动作」。

    fire-and-forget：不等回执 —— 手机端若还是旧版（无 task op），命令被
    忽略，无害。total=0 表示清空任务态（悬浮球回落显示版本/心跳）。
    需要手机端 v30+。"""
    d = {"dev": DEV, "op": "task", "name": name, "step": step,
         "idx": idx, "total": total}
    if ok is not None:
        d["ok"] = 1 if ok else 0
    post("/cmd", d)


# ---- v39：屏幕识字原语（App 无关能力层；dylib 端 op=ocr/vfind 由会话A v38 提供）----
# 为什么放 wayfind.py 不放 ks.py：读屏识字/按文字点击与宿主 App 无关，
# 微信（真机 7 用例全绿）、快手（RN 自绘层，tree 读不到字时的兜底）共用同一套。
def ocr(kw=None, n=60, region=None, pause=0.2, dev=None, timeout=40):
    """读整屏文字。返回 {ok,n,cost,luma,how,items:[{t,c,x,y,w,h,cx,cy}],sum}。

    kw     : 只留含该关键词的条目（None/""=全部）
    region : (x,y,w,h) UIKit 点坐标（左上原点），只留【中心点】落在区域内的条目。
             注意 v39 的 dylib 端仍是全屏 OCR，region 是云端过滤——省的是
             下行流量和上层比对时间，省不了 OCR 耗时；端侧真裁剪留 v40。
    luma   : 截图亮度 200~250 正常；<6 = 截错窗口/黑图，别信这次结果。
    耗时   : 实测一次 0.5~0.7s，别每步都读屏，能复用就复用。"""
    def show(r):
        print("  ocr -> %s 条 %sms luma=%s via=%s" %
              (r.get("n"), r.get("cost"), r.get("luma"), r.get("how")))
        if r.get("sum"):
            s = str(r["sum"])
            print("   ", s[:600] + ("…" if len(s) > 600 else ""))
    prev = _last_ts("ocr")
    d = {"dev": dev or DEV, "op": "ocr", "s": kw or "", "n": n}
    post("/cmd", d)
    r = wait_op("ocr", time.time(), timeout=timeout, after_ts=prev, dev=dev)
    if not r:
        print("  ocr 超时"); return None
    show(r)
    if region and r.get("items"):
        x0, y0, w, h = region
        r["items"] = [it for it in r["items"]
                      if x0 <= it.get("cx", -1) <= x0 + w and y0 <= it.get("cy", -1) <= y0 + h]
        r["n"] = len(r["items"])
        r["region"] = list(region)
    return r


def vfind(kw, idx=0, tap=1, wait_s=0, pause=0.2, dev=None, timeout=40):
    """按文字找并（可选）点它。这是「说人话就能操作」的落点。

    kw    : 要找的文字（必填）
    idx   : 命中多条时选第几个（按 上下左右 排序）。**先 vfind(kw, tap=0) 看 all
            列表再挑 idx**——多匹配凭直觉猜会点错（实测 s=微信 idx=1 是「微信支付」
            不是 tab bar 的「微信」）
    tap   : 1=真的点；0=只找不点
    wait_s: >0 时轮询等文字出现再点（每 1.2s 一次，页面还没渲染完的场景）。
            实现是先 tap=0 探测、命中后再 tap=1 点，避免对未就绪页面乱点。
    how   : 回执带 tapui（UIControl 主路）/ sendEvent（兜底）——
            上层靠它区分主路与兜底，别把兜底误读成主路成功。
    找不到: ok=false、tapok=null，绝不退化成点屏幕中心。"""
    if not kw:
        print("  vfind 缺 kw"); return None
    t_end = time.time() + wait_s
    r = None
    while True:
        prev = _last_ts("vfind")
        d = {"dev": dev or DEV, "op": "vfind", "s": kw, "idx": idx, "tap": 0}
        post("/cmd", d)
        r = wait_op("vfind", time.time(), timeout=timeout, after_ts=prev, dev=dev)
        if r and r.get("ok"):
            break
        if time.time() >= t_end:
            err = (r or {}).get("err", "超时")
            print("  vfind「%s」未出现（wait_s=%s，%s）" % (kw, wait_s, err))
            return r if r else None
        time.sleep(1.2)
    if tap:
        # G29（v39 实测）：① dylib 回执 ts 是秒级整数，两条同 op 命令间隔 <1s 时
        #   ts 过滤会误杀回执；② wait_op 的 ts>after_ts 偶发漏掉已到达的 tap=1 回执。
        # 修法：tap=1 回执必含 tapok 字段（tap=0 必无）→ 用字段存在性判新旧，
        #   ts 只做辅助（>= 而非 >），sleep 跨秒再发。真机实证 tap=1 回执 2s 内必到。
        time.sleep(1.05)
        prev = _last_ts("vfind")
        d = {"dev": dev or DEV, "op": "vfind", "s": kw, "idx": idx, "tap": 1}
        post("/cmd", d)
        t_end = time.time() + timeout
        while time.time() < t_end:
            time.sleep(0.6)
            r2 = (get("/report?dev=%s&op=vfind" % (dev or DEV)).get("data") or {})
            if r2.get("op") == "vfind" and r2.get("tapok") is not None \
                    and r2.get("ts", 0) >= prev:
                r = r2
                break
    print("  vfind「%s」-> #%s (%s,%s) hit=%s tapok=%s how=%s" %
          (kw, r.get("idx"), r.get("cx"), r.get("cy"),
           r.get("hit"), r.get("tapok"), r.get("how")))
    return r


# ---- v15：看行 / 点行（表格行不是 UIControl，必须走 delegate）----
def _op(op, payload, show, pause=0.2):
    time.sleep(pause)
    prev = _last_ts(op)
    d = dict(payload); d.update({"dev": DEV, "op": op})
    post("/cmd", d)
    r = wait_op(op, time.time(), after_ts=prev)
    if not r:
        print("  %s 超时" % op); return None
    show(r)
    return r


def rows(pause=0.2):
    def show(r):
        t = r.get("text", "")
        print("  rows -> %d 行:" % len(t.splitlines()))
        for l in t.splitlines()[:40]:
            print("   ", l)
    return _op("rows", {}, show, pause)


def pick(x, y, pause=0.2):
    def show(r):
        i = r.get("info", {})
        print("  pick(%.0f,%.0f) -> ok=%s how=%s 行=%s 文本=%s tv=%s 委托=%s" %
              (x, y, i.get("ok"), i.get("how"), i.get("row"), i.get("cellText"),
               i.get("tv"), i.get("delegate")))
        if i.get("err"): print("     err:", i["err"])
    return _op("pick", {"x": x, "y": y}, show, pause)


def picktxt(kw, pause=0.2):
    def show(r):
        i = r.get("info", {})
        print("  picktxt('%s') -> ok=%s how=%s 候选=%s 行=%s 文本=%s" %
              (kw, i.get("ok"), i.get("how"), i.get("cands"), i.get("row"), i.get("cellText")))
        if i.get("err"): print("     err:", i["err"])
    return _op("picktxt", {"text": kw}, show, pause)


# ---- v18：返回一页 / 看导航栈（治 Flutter、游戏这类"看得见点不着"的返回键）----
def back(pause=0.2):
    def show(r):
        print("  back -> ok=%s %s" % (r.get("ok"), (r.get("txt") or "")[:200]))
    return _op("back", {}, show, pause)


def nav(pause=0.2):
    def show(r):
        print("  nav:")
        for l in (r.get("txt") or "").splitlines():
            print("   ", l)
    return _op("nav", {}, show, pause)


def _tabbar_visible(t):
    """TabBar 是否真的可见。聊天会话页里它是 hidden，点了也没用。"""
    for l in t.splitlines():
        if 'MMTabBar ' in l:
            return 'hidden' not in l
    return False


def go():
    """一键：任意页面 -> 朋友圈。每一步都先看状态再决定点哪，不写死。"""
    # 1) 看当前在哪：TabBar 被 hidden 说明在二级页（聊天等），先退回
    t = tree()
    n0 = len(t.splitlines())
    print("起点: %d 行, TabBar可见=%s" % (n0, _tabbar_visible(t)))
    if not _tabbar_visible(t):
        print("→ 在二级页，先点左上角返回")
        pick(22, 69)
        time.sleep(0.35)
        t = tree()
        print("  返回后: %d 行, TabBar可见=%s" % (len(t.splitlines()), _tabbar_visible(t)))
        if not _tabbar_visible(t):
            print("❌ 还是没 TabBar，停手，别瞎点"); return

    # 2) 进「发现」页（第 3 格，实测中心 244,799）
    print("→ 点发现页 Tab (244,799)")
    pick(244, 799)
    time.sleep(1.5)
    t = tree()
    print("  %d 行, 含 MMMainTableView=%s" % (len(t.splitlines()), 'MMMainTableView' in t))

    # 3) 看有哪些行（这一步给出真实坐标，不靠猜）
    rows()

    # 4) 按文本选中朋友圈
    r = picktxt("朋友圈")
    if not r or not (r.get("info") or {}).get("ok"):
        print("❌ picktxt 失败"); return
    time.sleep(1.5)
    n1 = len(tree("/tmp/go_after.txt").splitlines())
    t = open('/tmp/go_after.txt').read()
    print("→ 结果: %d 行（差 %+d）" % (n1, n1 - n0))
    for kw in ("WCTimelineTableView", "WCTimeLineCellView", "RichTextView", "MMMainTableView"):
        print("   含 '%s': %s" % (kw, kw in t))
    print("✅ 已进朋友圈" if 'WCTimelineTableView' in t else "❌ 没进朋友圈")


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    a = sys.argv[1]
    if a == "doctor":
        doctor()
    elif a == "probe":
        probe(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "tapui":
        tapui(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "tree":
        tree(sys.argv[2] if len(sys.argv) > 2 else None)
    elif a == "find":
        find(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif a == "has":
        print(kw_in_tree(sys.argv[2]))
    elif a == "rows":
        rows()
    elif a == "pick":
        pick(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "picktxt":
        picktxt(sys.argv[2])
    elif a == "go":
        go()
    elif a == "scroll":
        scroll(float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]))
    elif a == "back":
        back()
    elif a == "nav":
        nav()
    elif a == "macro":
        # 例：wayfind.py macro '[{"op":"pick","x":22,"y":69},{"op":"tree"}]'
        macro(json.loads(sys.argv[2]),
              float(sys.argv[3]) if len(sys.argv) > 3 else 700)
    else:
        print(__doc__)


def kw_in_tree(kw):
    t = tree()
    return kw in t


if __name__ == "__main__":
    main()
