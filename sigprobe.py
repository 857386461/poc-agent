#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sigprobe.py —— v53 签名侦察专用客户端

纯只读：只枚举类、只探符号、只旁路记录请求头。不改 App 行为、不发业务请求、不写数据。

用法：
  python3 sigprobe.py status              看钩子状态
  python3 sigprobe.py scan [k=词,词] [app=1]   扫类 + 探符号
  python3 sigprobe.py on                  挂 header 旁路钩子
  python3 sigprobe.py off                 停钩子
  python3 sigprobe.py dump [all=1] [h=域名] [n=条数] [clear=1]
  python3 sigprobe.py browse <次数>       滑视频，触发网络流量
  python3 sigprobe.py run                 一条龙：on → browse → dump(all=1) → hosts 分析
"""
import json, os, sys, time, urllib.request

RELAY = "https://aa0c466b5cdb559bb.app.workbuddy.host"
DEV = os.environ.get("AI_DEV", "287CD2D8-3281-42F7-9B51-5AE3FF4426D4")


def post(path, obj):
    r = urllib.request.Request(RELAY + path, data=json.dumps(obj).encode(),
                               headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(r, timeout=30).read())


def get(path):
    return json.loads(urllib.request.urlopen(RELAY + path, timeout=30).read())


def report():
    return get("/report?dev=" + DEV)["data"]


def send(extra, timeout=40):
    """扁平格式下发（G81）"""
    prev = report().get("ts", 0)
    cmd = {"dev": DEV}
    cmd.update(extra)
    post("/cmd", cmd)
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(1.5)
        d = report()
        if d.get("ts", 0) > prev and d.get("op") == extra.get("op"):
            return d
    return None


def parse_kv(args):
    d = {}
    for a in args:
        if "=" in a:
            k, v = a.split("=", 1)
            d[k] = v
    return d


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    a = sys.argv[1]
    kv = parse_kv(sys.argv[2:])

    if a == "status":
        print(json.dumps(send({"op": "sigprobe", "a": "status"}), ensure_ascii=False, indent=2)); return

    if a == "scan":
        # v56：mm=1 → 按**方法名**扫（找签名函数必须用它，只扫类名永远找不到）
        c = {"op": "sigprobe", "a": "scan"}
        if kv.get("k"): c["k"] = kv["k"]
        if kv.get("app"): c["app"] = int(kv["app"])
        if kv.get("mm"): c["mm"] = int(kv["mm"])
        d = send(c, timeout=60)
        if not d:
            print("超时"); return
        print(f"类候选 {d.get('ncls')} 个")
        print(f"符号命中: {', '.join(d.get('symFound') or [])}")
        json.dump(d, open("/tmp/scan_%d.json" % time.time(), "w"), ensure_ascii=False)
        for c_ in d.get("classes", []):
            print(f"  {c_['cls']}  [{c_.get('by')}]")
            for mn in (c_.get("m") or [])[:20]:
                print(f"      {mn}")
        return

    if a == "on":
        print(json.dumps(send({"op": "sigprobe", "a": "on"}), ensure_ascii=False, indent=2)); return

    if a == "off":
        print(json.dumps(send({"op": "sigprobe", "a": "off"}), ensure_ascii=False, indent=2)); return

    if a == "browse":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
        for i in range(n):
            post("/cmd", {"dev": DEV, "op": "swipe", "x1": 200, "y1": 600, "x2": 200, "y2": 120, "steps": 12, "dur": 0.3})
            time.sleep(2.5)
        print(f"已滑 {n} 条"); return

    if a == "dump":
        # v55：dump 出的是「请求快照」{k,u,m,b,n,h}，不再是头碎片
        c = {"op": "sigprobe", "a": "dump"}
        for k in ("all", "clear"):
            if kv.get(k) is not None: c[k] = int(kv[k])
        for k in ("h", "path"):
            if kv.get(k): c[k] = kv[k]
        for k in ("n", "maxlen", "i"):
            if kv.get(k) is not None: c[k] = int(kv[k])
        d = send(c, timeout=60)
        if not d:
            print("超时"); return
        json.dump(d, open("/tmp/dump_%d.json" % time.time(), "w"), ensure_ascii=False)
        print(f"总请求 {d.get('total')} 个 / 选出 {d.get('nsel')} 个")
        print("\n=== hosts（这些请求属于谁）===")
        hosts = d.get("hosts") or {}
        for h, cnt in sorted(hosts.items(), key=lambda x: -x[1]):
            print(f"  {cnt:4d}  {h}")
        print("\n=== items（请求快照）===")
        for e in d.get("items", []):
            print("─" * 66)
            print(f"  #{e.get('k')}  {e.get('m') or '(无method)'}  头{e.get('n')}个")
            u = str(e.get("u") or "")
            print(f"  URL: {u[:100]}{' …⟨TRUNC⟩' if '⟨TRUNC⟩' in u else ''}  ({len(u)}字符)")
            if e.get("b"): print(f"  BODY({len(e.get('b'))}): {str(e.get('b'))[:100]}")
            for f, v in (e.get("h") or {}).items():
                print(f"      {f}: {str(v)[:66]}")
        return

    if a == "cred":
        # v56：导出会话固定凭据（Cookie/UA/qr-xx-kv/kas/kaw + URL 设备参数）
        d = send({"op": "sigprobe", "a": "cred"}, timeout=60)
        if not d:
            print("超时"); return
        json.dump(d, open("/tmp/ks_cred.json", "w"), ensure_ascii=False)
        print("ok=", d.get("ok"))
        for f in ("ua", "cookie", "qrx", "kas", "kaw", "accept", "acceptLang"):
            if d.get(f): print(f"{f}: {str(d.get(f))[:120]}")
        q = d.get("q") or {}
        print(f"\nURL 参数 {len(q)} 个：")
        for k2, v2 in q.items(): print(f"  {k2} = {str(v2)[:70]}")
        print("\n(已存 /tmp/ks_cred.json)")
        return

    if a == "replay":
        # v55 新增：i=下标（默认最后一条）；dry=1（默认）只回显完整原文，dry=0 真发（过只读白名单）
        if not kv.get("i"):
            print("用法: sigprobe.py replay i=<下标> [dry=0]"); return
        c = {"op": "sigprobe", "a": "replay", "i": int(kv["i"])}
        if kv.get("dry") is not None: c["dry"] = int(kv["dry"])
        if kv.get("maxlen") is not None: c["maxlen"] = int(kv["maxlen"])
        d = send(c, timeout=60)
        if not d:
            print("超时"); return
        if d.get("dry"):
            print(f"=== dry 回显 #{d.get('i')} ===")
            print(f"METHOD: {d.get('m')}")
            print(f"URL({len(d.get('u',''))}): {d.get('u')}")
            if d.get("b"): print(f"BODY({len(d.get('b',''))}): {d.get('b')}")
            print("-- HEADERS --")
            for f, v in (d.get("h") or {}).items(): print(f"  {f}: {v}")
            json.dump(d, open("/tmp/replay_dry.json", "w"), ensure_ascii=False)
            print("\n(已存 /tmp/replay_dry.json)")
            return
        print(f"=== 真发结果 code={d.get('code')} {d.get('ms')}ms {d.get('len')}B ===")
        print(d.get("text") or d.get("err"))
        return

    if a == "call":
        # v57：通用 ObjC 类方法调用
        #   python3 sigprobe.py call cls=KSMWPassportSecurityTools sel=sig3OnURLPath:method:requestParams: \
        #          args='["/rest/nebula/clock/r","GET",{}]'
        #   args 必须是 JSON 数组（字符串/数字/对象/数组/null）
        #   probe=1 → 先只探方法签名（不真调），用于确认参数个数与类型
        if not kv.get("sel") or (not kv.get("cls") and not kv.get("inst")):
            print("用法: sigprobe.py call cls=<类> sel=<选择器> [args='[..]'] [probe=1] [inst=<单例方法>]")
            print("      sigprobe.py probe cls=<类> sel=<选择器>   # 只查签名")
            print()
            print("★ v59 输出参数语法：参数写成可变容器包装，函数回写的最终内容出现在回执 out[] 里")
            print("   {\"$mstr\":\"初值\"}    → NSMutableString")
            print("   {\"$marr\":[...]}      → NSMutableArray")
            print("   {\"$mdict\":{...}}     → NSMutableDictionary")
            print("   例: args='[\"path\",\"POST\",{},{\"$mstr\":\"\"}]'  # 第4参是输出明文")
            print()
            print("★ v60 只读单例实例方法：加 inst=<单例方法名>，先取实例再调实例方法")
            print("   例: sigprobe.py call inst=sharedHTTPCookieStorage cls=NSHTTPCookieStorage sel=cookies")
            print("   白名单: NSHTTPCookieStorage/NSUserDefaults/NSFileManager/")
            print("           NSNotificationCenter/NSURLCache/NSProcessInfo")
            return
        c = {"op": "call", "sel": kv["sel"]}
        if kv.get("cls"): c["cls"] = kv["cls"]
        if kv.get("inst"): c["inst"] = kv["inst"]
        if kv.get("args"):
            try:
                c["args"] = json.loads(kv["args"])
            except Exception as e:
                print("args 不是合法 JSON 数组:", e); return
        if kv.get("probe"): c["probe"] = 1
        d = send(c, timeout=60)
        if not d:
            print("超时"); return
        json.dump(d, open("/tmp/call_last.json", "w"), ensure_ascii=False)
        print(json.dumps(d, ensure_ascii=False, indent=2)[:4000])
        outs = d.get("out") or []
        if outs:
            print("\n=== 输出参数（函数回写的最终内容）===")
            for o in outs:
                print(f"  arg#{o.get('i')} => {str(o.get('v'))[:2000]}")
        print("\n(已存 /tmp/call_last.json)")
        return

    if a == "probe":
        if not kv.get("sel"):
            print("用法: sigprobe.py probe cls=<类> sel=<选择器> [inst=<单例方法>]"); return
        c = {"op": "call", "sel": kv["sel"], "probe": 1}
        if kv.get("cls"): c["cls"] = kv["cls"]
        if kv.get("inst"): c["inst"] = kv["inst"]
        d = send(c, timeout=60)
        if not d:
            print("超时"); return
        json.dump(d, open("/tmp/call_probe.json", "w"), ensure_ascii=False)
        print(json.dumps(d, ensure_ascii=False, indent=2)[:4000])
        return

    if a == "run":
        print("--- 1/4 挂钩子 ---")
        print(send({"op": "sigprobe", "a": "on"}))
        print("--- 2/4 滑 8 条视频 ---")
        for i in range(8):
            post("/cmd", {"dev": DEV, "op": "swipe", "x1": 200, "y1": 600, "x2": 200, "y2": 120, "steps": 12, "dur": 0.3})
            time.sleep(2.5)
        print("--- 3/4 dump ---")
        d = send({"op": "sigprobe", "a": "dump", "all": 1, "n": 80})
        if not d:
            print("超时"); return
        json.dump(d, open("/tmp/run_dump.json", "w"), ensure_ascii=False)
        print(f"总 {d.get('total')} 条")
        print("\n=== hosts ===")
        for h, cnt in sorted((d.get("hosts") or {}).items(), key=lambda x: -x[1]):
            print(f"  {cnt:4d}  {h}")
        print("\n=== 前 50 条明细 ===")
        for e in d.get("items", [])[:50]:
            print(f"  [{e.get('f')}] = {str(e.get('v'))[:60]}")
            print(f"       ⇢ {str(e.get('u'))[:100]}")
        print("--- 4/4 滚 App 首页 amber 触发更多 ---")
        return

    print(__doc__)


if __name__ == "__main__":
    main()
