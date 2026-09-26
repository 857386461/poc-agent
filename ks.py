#!/usr/bin/env python3
"""快手侧控制：复用 wayfind 的全部能力，只换 dev。

  python3 ks.py text            读界面文字
  python3 ks.py tree            视图树
  python3 ks.py probe x y       看某点命中什么
  python3 ks.py tapui x y       点某点
  python3 ks.py picktxt 签到    按文字点（支持 UICollectionView）
  python3 ks.py rows            看列表行
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wayfind
from relayctl import post, get

wayfind.DEV = "287CD2D8-3281-42F7-9B51-5AE3FF4426D4"
DEV = wayfind.DEV


def _op(op, payload, show, timeout=90):
    """快手侧命令普遍偏慢（text 实测 25s+），超时默认放宽到 90 秒。"""
    time.sleep(0.3)
    prev = wayfind._last_ts(op)
    d = dict(payload); d.update({"dev": DEV, "op": op})
    post("/cmd", d)
    r = wayfind.wait_op(op, time.time(), timeout=timeout, after_ts=prev)
    if not r:
        print("  %s 超时(%ds)" % (op, timeout)); return None
    show(r)
    return r


def ver():
    d = get("/report?dev=%s&op=status" % DEV).get("data") or {}
    print("  status:", json.dumps(d, ensure_ascii=False)[:400])
    return d


def text(kw=None, timeout=90):
    """快手界面大，text 走 runtime 枚举很慢（实测 25s+），超时必须放宽。"""
    time.sleep(0.3)
    prev = wayfind._last_ts("text")
    post("/cmd", {"dev": DEV, "op": "text", **({"kw": kw} if kw else {})})
    d = wayfind.wait_op("text", time.time(), timeout=timeout, after_ts=prev)
    if not d:
        print("  text 超时"); return ""
    return d.get("text", "") or ""


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    a = sys.argv[1]
    if a == "text":
        kw = sys.argv[2] if len(sys.argv) > 2 else None
        t = text(kw)
        print("  text: %d 行" % len([l for l in t.splitlines() if l.strip()]))
        import re
        filt = sys.argv[3] if len(sys.argv) > 3 else None
        for l in t.splitlines():
            if not filt or re.search(filt, l):
                print("   ", l)
    elif a == "status":
        ver()
    elif a == "tree":
        t = wayfind.tree(sys.argv[2] if len(sys.argv) > 2 else None)
        print(t[:4000])
    elif a == "probe":
        wayfind.probe(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "tapui":
        wayfind.tapui(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "pick":
        wayfind.pick(float(sys.argv[2]), float(sys.argv[3]))
    elif a == "picktxt":
        wayfind.picktxt(sys.argv[2])
    elif a == "rows":
        wayfind.rows()
    elif a == "back":
        wayfind.back()
    elif a == "nav":
        wayfind.nav()
    elif a == "dump":
        wayfind.dump(float(sys.argv[2]), float(sys.argv[3]),
                     int(sys.argv[4]) if len(sys.argv) > 4 else 2)
    elif a == "scroll":
        wayfind.scroll(float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]))
    elif a == "ball":
        wayfind.ball(sys.argv[2] != "0")
    elif a == "task":                      # v30：任务态 -> 悬浮球
        wayfind.task(sys.argv[2] if len(sys.argv) > 2 else "",
                     sys.argv[5] if len(sys.argv) > 5 else "",
                     int(sys.argv[3]) if len(sys.argv) > 3 else 0,
                     int(sys.argv[4]) if len(sys.argv) > 4 else 0)
        print("  task -> 已下发（fire-and-forget，需手机 v30+）")
    elif a == "gtap":                      # v23：手势直达（自绘控件唯一的点击通路）
        r = _op("gtap", {"x": float(sys.argv[2]), "y": float(sys.argv[3])},
                lambda r: print("  gtap -> ok=%s how=%s gr=%s up=%s on=%s %s"
                                % (r.get("ok"), r.get("how"), r.get("gr"),
                                   r.get("up"), r.get("on"), r.get("err") or "")))
    elif a == "chain":                     # v23：父链 + 每层挂了什么手势
        _op("chain", {"x": float(sys.argv[2]), "y": float(sys.argv[3])},
            lambda r: print(r.get("text", "")))
    elif a == "wins":                      # v23：列出所有窗口
        _op("wins", {}, lambda r: print(r.get("text", "")))
    elif a == "win":                       # v23：锁定窗口（负数还原自动）
        _op("win", {"i": int(sys.argv[2])}, lambda r: print("  win ->", r.get("txt")))
    elif a == "find":                      # v27：该点上所有「框包含它」的 view（面积升序）
        _op("find", {"x": float(sys.argv[2]), "y": float(sys.argv[3]),
                     **({"n": int(sys.argv[4])} if len(sys.argv) > 4 else {})},
            lambda r: print(r.get("text", "")))
    elif a == "rntap":                     # v27：用精确命中 view 的 reactTag 喂手势
        # 用法: rntap x y [up] [rank]      up=往上走几层  rank=用第几个候选
        r = _op("rntap", {"x": float(sys.argv[2]), "y": float(sys.argv[3]),
                          **({"up": int(sys.argv[4])} if len(sys.argv) > 4 else {}),
                          **({"rank": int(sys.argv[5])} if len(sys.argv) > 5 else {})},
                lambda r: None)
        print("  rntap -> ok=%s tv=%s tag=%s f=%s gv=%s grs=%s errs=%s"
              % (r.get("ok"), r.get("tv"), r.get("tag"), r.get("f"),
                 r.get("gv"), r.get("grs"), r.get("errs") or (r.get("err") or "-")))
    elif a == "dismiss":                  # v28：自动关随机弹窗
        _op("dismiss", {}, lambda r: print("  dismiss -> ok=%s how=%s kw=%s txt=%s pt=%s grs=%s err=%s"
            % (r.get("ok"), r.get("how"), r.get("kw"), r.get("txt"), r.get("pt"), r.get("grs"), r.get("err") or "-")))
    elif a == "uioff":                     # v27：剥遮挡层（关掉命中 view 的交互）
        _op("uioff", {"x": float(sys.argv[2]), "y": float(sys.argv[3])},
            lambda r: print("  uioff ->", r.get("txt")))
    elif a == "uion":                      # v27：还原被剥掉的交互
        _op("uion", {}, lambda r: print("  uion -> n=%s" % r.get("n")))
    elif a == "toast":
        print(post("/cmd", {"dev": DEV, "op": "toast", "text": " ".join(sys.argv[2:])}))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
