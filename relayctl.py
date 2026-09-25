#!/usr/bin/env python3
"""中继控制端 —— 我在沙箱这边用它给手机发指令。

    python3 relayctl.py peek                 看哪些设备在线（dev id）
    python3 relayctl.py cmd <dev> status     查状态
    python3 relayctl.py cmd <dev> tree       视图树
    python3 relayctl.py cmd <dev> overlay 0  收起盖屏
    python3 relayctl.py cmd <dev> tap 195 422
    python3 relayctl.py cmd <dev> tapn 195 422 5 0.5
    python3 relayctl.py cmd <dev> swipe 100 500 300 500 12 0.35
    python3 relayctl.py cmd <dev> shot       要截图（base64 回传）
    python3 relayctl.py cmd <dev> log        要日志
    python3 relayctl.py report <dev>         读手机上送的最后一条结果
    python3 relayctl.py shot <dev> out.png   截图并落盘
"""
import base64
import json
import sys
import urllib.request

RELAY = "https://aa0c466b5cdb559bb.app.workbuddy.host"


def post(path, obj):
    req = urllib.request.Request(RELAY + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def get(path):
    return json.loads(urllib.request.urlopen(RELAY + path, timeout=30).read())


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    a = sys.argv[1]

    if a == "peek":
        print(json.dumps(get("/peek"), indent=2)); return

    if a == "report":
        r = get("/report?dev=" + sys.argv[2])
        print(json.dumps(r, indent=2, ensure_ascii=False)[:4000]); return

    if a == "shot":
        dev, out = sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "shot.png")
        post("/cmd", {"dev": dev, "op": "shot"})
        import time; time.sleep(4)
        r = get("/report?dev=" + dev)
        b64 = (r.get("data") or {}).get("b64", "")
        if b64:
            open(out, "wb").write(base64.b64decode(b64))
            print("saved", out, len(b64), "b64 chars")
        else:
            print("no image:", str(r)[:300])
        return

    if a == "toast":
        # 我能主动往手机屏幕上弹一句话 —— 用户只要回「看到了」就够了
        dev = sys.argv[2]
        txt = " ".join(sys.argv[3:]) or "你好，我是 AI，看到请回话"
        print(json.dumps(post("/cmd", {"dev": dev, "op": "toast", "text": txt}),
                         ensure_ascii=False))
        return

    if a == "diag":
        dev = sys.argv[2]
        post("/cmd", {"dev": dev, "op": "diag"})
        import time; time.sleep(7)
        print(json.dumps(get("/report?dev=" + dev), indent=2, ensure_ascii=False)[:3000])
        return

    if a == "wait":
        # 等设备上線：最多 N 秒，每 3 秒看一次，出现就打印 dev id
        lim = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        import time
        t0 = time.time()
        known = set(get("/peek")["devices"].keys())
        while time.time() - t0 < lim:
            time.sleep(3)
            d = get("/peek")["devices"]
            new = [k for k in d if k not in known]
            if new:
                print("上线:", new); return
        print("超时，当前在线:", list(get("/peek")["devices"].keys()))
        return

    if a == "cmd":
        dev = sys.argv[2]
        op = sys.argv[3]
        rest = sys.argv[4:]
        if op == "tap":
            c = {"dev": dev, "op": "tap", "x": float(rest[0]), "y": float(rest[1])}
        elif op == "tapn":
            x, y = float(rest[0]), float(rest[1])
            n = int(rest[2]) if len(rest) > 2 else 1
            gap = float(rest[3]) if len(rest) > 3 else 0.5
            for i in range(n):
                post("/cmd", {"dev": dev, "op": "tap", "x": x, "y": y})
                if i + 1 < n:
                    import time; time.sleep(gap)
            print("queued", n, "taps"); return
        elif op == "swipe":
            c = {"dev": dev, "op": "swipe", "x1": float(rest[0]), "y1": float(rest[1]),
                 "x2": float(rest[2]), "y2": float(rest[3]),
                 "steps": int(rest[4]) if len(rest) > 4 else 12,
                 "dur": float(rest[5]) if len(rest) > 5 else 0.35}
        elif op == "overlay":
            c = {"dev": dev, "op": "overlay", "on": int(rest[0]) if rest else 0}
        else:
            c = {"dev": dev, "op": op}
        print(json.dumps(post("/cmd", c)))
        return

    print("unknown:", a); print(__doc__)


if __name__ == "__main__":
    main()
