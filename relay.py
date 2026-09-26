#!/usr/bin/env python3
"""AgentInject2 反向轮询中继。

为什么需要它：手机在家里 WiFi 里（192.168.x.x），我在云端沙箱里，直连不到。
但手机能主动出网 —— 所以让 dylib 每 3 秒来这里取指令，我在这边下发。
这样"AI 通过对话控制手机"就成立了，不需要用户有电脑。

端点：
    GET  /poll?dev=ID          手机取指令（返回指令数组，取走即清空）
    POST /cmd                  我下发指令 {"dev":"ID","op":"tap","x":195,"y":422}
    POST /report               手机上送结果
    GET  /report?dev=ID        我读手机回传的结果
    GET  /peek                 看队列里还有啥
"""
import threading
import time

from fastapi import FastAPI, Request

app = FastAPI()

LOCK = threading.Lock()
Q = {}          # dev -> [cmd, ...]
REPORTS = {}    # dev -> {"ts":..., "data":...}
SEEN = {}       # dev -> last poll time


@app.get("/")
async def root():
    return {
        "ok": True,
        "service": "AgentInject2 relay",
        "devices": list(SEEN.keys()),
        "help": "GET /poll?dev=ID | POST /cmd | POST /report | GET /report?dev=ID",
    }


@app.get("/poll")
async def poll(dev: str = "?"):
    with LOCK:
        SEEN[dev] = time.time()
        cmds = Q.pop(dev, [])
    return cmds


@app.post("/cmd")
async def cmd(request: Request):
    d = await request.json()
    dev = d.get("dev", "*")
    with LOCK:
        Q.setdefault(dev, []).append(d)
        n = len(Q[dev])
    print(f"[cmd] -> {dev}: {d}")
    return {"ok": True, "queued": n}


@app.post("/report")
async def report(request: Request):
    d = await request.json()
    dev = d.get("dev", "?")
    with LOCK:
        REPORTS[dev] = {"ts": time.time(), "data": d}
    print(f"[report] <- {dev}: {str(d)[:200]}")
    return {"ok": True}


@app.get("/report")
async def get_report(dev: str = "?"):
    with LOCK:
        r = REPORTS.get(dev)
    return r or {"ok": False, "err": "no report from " + dev}


@app.get("/peek")
async def peek():
    with LOCK:
        return {"queues": {k: len(v) for k, v in Q.items()},
                "devices": {k: int(time.time() - v) for k, v in SEEN.items()}}
