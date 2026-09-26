#!/usr/bin/env python3
"""快手侧稳健控制：所有 op 都带“内容变化”判定，避免 ts 串扰读到旧结果。"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from relayctl import post, get

DEV = "287CD2D8-3281-42F7-9B51-5AE3FF4426D4"


def _snap(op):
    d = (get("/report?dev=%s&op=%s" % (DEV, op)).get("data") or {})
    return d


def send(op, **kw):
    post("/cmd", dict(dev=DEV, op=op, **kw))


def wait_new(op, timeout=60, key=("text", "tree")):
    """轮询直到某字段出现非空新内容（用内容指纹判定，不靠 ts）。"""
    old = _snap(op)
    oldfp = tuple(old.get(k, "") for k in key)
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(1.0)
        d = _snap(op)
        fp = tuple(d.get(k, "") for k in key)
        if fp != oldfp:
            return d
    return None


def treelen(timeout=60):
    send("tree")
    d = wait_new("tree", timeout, key=("tree",))
    if not d:
        return None, "timeout"
    t = d.get("tree", "")
    return len(t.splitlines()), t


def fulltext(timeout=90):
    send("text")
    d = wait_new("text", timeout, key=("text",))
    if not d:
        return None
    return d.get("text", "")


if __name__ == "__main__":
    print("用法: ks2.py tree | text | tap x y | raw <op> [k=v...]")
