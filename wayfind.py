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
import sys, time, json, re
sys.path.insert(0, '/workspace/ios-poc')
from relayctl import post, get

DEV = "68814FAE-730A-42C5-865B-4EB10F445282"


def wait_op(op, t0, timeout=25, after_ts=0):
    # after_ts：本次请求【发出前】服务端上该 op 的最后 ts。
    # 必须要求新结果的 ts 严格大于它，否则会读到上一次的旧数据 ——
    # 实测中连续 probe 出现过 y=86 和 y=142 返回同一个值的串扰。
    while time.time() - t0 < timeout:
        time.sleep(0.35)
        d = (get("/report?dev=%s&op=%s" % (DEV, op)).get("data") or {})
        if d.get("op") == op and d.get("ts", 0) > max(after_ts, t0 - 3):
            return d
    return None


def _last_ts(op):
    d = (get("/report?dev=%s&op=%s" % (DEV, op)).get("data") or {})
    return d.get("ts", 0) if d.get("op") == op else 0


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
    if a == "probe":
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
