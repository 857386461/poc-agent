#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快手「真人刷视频」循环 —— v1 (2026-09)

已验证的原子能力（见 /workspace/iOS踩坑清单.md）：
  tapui 点赞/评论/收藏 —— 坐标自适应（不同视频布局工具条位置不同，写死会点空）
  scroll(x=195, y=700, dy=761) 上滑切下一个视频（页高 761，非 844）
  ⚠ 落点必须避开屏幕中部：y=400 会落进「剧集横滑」KSThanosPagesView（左右翻的
    8 集容器），只能 dx 翻，表现为「滑了 6 次画面没换」。y=100 / y=700 才命中
    外层纵向 feed KSGRBrowseTableView（contentSize {390,2283}，offset 复位 761）。
  ⚠ swipe / tap 在视频层被拦截视图吞掉，ok=true 但无效，别用

真人化要点：
  - 观看时长服从混合分布（秒划 / 常规 / 看久 / 沉浸）
  - 不是每个视频都互动：赞 ~30%、藏 ~10%、看评论 ~12%、回滑 ~8%
  - 动作之间插随机小间隔，模拟手指移动与犹豫
"""
import re, time, random, sys
import ks

# ---- 视频层右侧工具条（兜底值；正常走 snap() 自适应） ----
P_LIKE   = (360, 405)   # 点赞
P_CMT    = (360, 475)   # 评论
P_STAR   = (360, 545)   # 收藏
# P_SHARE = (360, 615)  # 分享（真人很少点，默认不开）

# 落点：y=700 命中纵向 feed；y=400 会掉进剧集横滑容器（只能左右翻）
X_FEED, Y_FEED = 195, 700
NEXT = {"x": X_FEED, "y": Y_FEED, "dy": 761,  "dx": 0, "anim": True}   # 上滑下一个
PREV = {"x": X_FEED, "y": Y_FEED, "dy": -761, "dx": 0, "anim": True}   # 回看上一个
CLOSE_CMT = (195, 120)  # 评论面板打开后点上方视频区关闭


def k(op, p):
    try:
        return ks._op(op, p, lambda r: None)
    except Exception as e:
        return {"err": str(e)}


def _task(i=0, n=0, step="", ok=None):
    """v30：任务态 -> 悬浮球（fire-and-forget；v27 手机无 task op 时自动忽略）。"""
    try:
        from relayctl import post as _post
        d = {"dev": ks.DEV, "op": "task", "name": "刷视频", "step": step,
             "idx": i, "total": n}
        if ok is not None:
            d["ok"] = 1 if ok else 0
        _post("/cmd", d)
    except Exception:
        pass


def _sz(s):
    """解析 NSStringFromCGSize / NSStringFromCGRect 里的 {w, h}"""
    m = re.findall(r'\{([-\d\.]+),\s*([-\d\.]+)\}', s or '')
    return (float(m[-1][0]), float(m[-1][1])) if m else (0.0, 0.0)


def page_info(x=X_FEED, y=Y_FEED):
    """探测当前视频容器是横向还是纵向分页，返回 (是否横向, 页尺寸, 当前offset, 上限, 原始info)"""
    r = k("scroll", {"x": x, "y": y, "dx": 0, "dy": 0, "anim": False})
    inf = (r or {}).get("info", {})
    if not inf.get("sv"):
        return None, 0, 0, 0, inf
    cs = _sz(inf.get("contentSize"))          # 内容总尺寸
    fr = _sz(inf.get("frame"))                # 可视尺寸（bounds）
    off = _sz(inf.get("before"))              # 当前 offset
    horiz = cs[0] > fr[0] + 10                # 宽超出可视宽 => 横向分页
    step = fr[0] if horiz else fr[1]          # 一页 = 可视宽/高
    limit = max(0.0, (cs[0] - fr[0]) if horiz else (cs[1] - fr[1]))
    cur = off[0] if horiz else off[1]
    return horiz, step, cur, limit, inf


def flip(back=False, x=X_FEED, y=Y_FEED):
    """上下翻一页（优先纵向 feed）。

    坑：屏幕中部 (195,400) 会命中「剧集横滑」KSThanosPagesView —— 那是左右翻的，
    dy 完全无效（表现为滑了 N 次画面纹丝不动）。所以固定用 y=100/700 这类
    贴边落点打外层纵向 feed；万一真落在横滑容器里，才退化成 dx 左右翻。
    """
    horiz, step, cur, limit, inf = page_info(x, y)
    if horiz is None:                          # 这个落点没找到滚动容器，换个贴边落点
        horiz, step, cur, limit, inf = page_info(x, 100)
        y = 100
    d = -step if back else step
    if cur + d > limit + 1:
        d = -step          # 到底了，往回翻
    elif cur + d < -1:
        d = step           # 到头了，往前翻
    p = {"x": x, "y": y, "anim": True}
    p["dx"] = d if horiz else 0
    p["dy"] = 0 if horiz else d
    k("scroll", p)
    return ("横向" if horiz else "纵向") + ("往回" if d < 0 else "往前"), step


def watch_time():
    """真人观看时长：多数短看，少数久看，偶尔秒划"""
    r = random.random()
    if r < 0.10:
        return random.uniform(3, 7)      # 秒划
    if r < 0.70:
        return random.uniform(9, 22)     # 常规
    if r < 0.93:
        return random.uniform(22, 40)    # 看得久
    return random.uniform(40, 65)        # 沉浸


_ROW = re.compile(r'\((\d+)\)\s+(-?[\d\.]+),(-?[\d\.]+)\s+([\d\.]+)x([\d\.]+)\s+\|\s*(.+)')

# ---- v31：红包奖励进度驱动换视频（会话B 2026-09-27 实测定案）----
# 结论：进度条读不到 —— 它是 TK_VIEW_TKCanvasView2 自绘圆环，文本读不到；
#       想靠截图比对像素也被堵死：快手视频页有截屏保护，shot 返回 1170×2532 纯黑图。
# 但「开奖」有可读信号：圆环走满 → 弹「天降惊喜 / 本圈立得N金币」→ 红包金额
#       从【预告档位】变成【实发额】。实测捕获：+1500 → +1317。
# 所以判据 = 红包金额变化 = 这圈奖励已尽 = 用户说的「进度不动了就可以换视频」。
# 另：红包出现率约 50% 且呈有/无交替（实测 12 连翻 #0无#1有#2无#3有…），
#     无红包视频必须回落随机时长，死等会卡住。
AMOUNT_RE = re.compile(r'\+(\d+)\s*金币')
HARD_CAP  = 60.0      # 单视频硬上限（防沉迷）；与随机时长取 min


def red_amount():
    """读左上角红包的 '+N金币'；无红包（直播/广告 cell）返回 None。

    必须带 kw —— text 全量 25~40s、带 kw 只要 ~4s（坑 G15），
    否则采样间隔被拖垮，会错过只持续约 5 秒的「天降惊喜」开奖弹窗。
    """
    t = ks.text("金币")
    for l in t.splitlines():
        m = _ROW.match(l.strip())
        if not m:
            continue
        x, y, c = float(m.group(2)), float(m.group(3)), m.group(6)
        if c.startswith("<"):
            continue
        if -5 <= x <= 100 and 85 <= y <= 185:      # 红包容器 (0,90)-(90,180)
            mm = AMOUNT_RE.search(c)
            if mm:
                return mm.group(1)
    return None


def _find_row(kw, xr=None, yr=None):
    """屏上找第一行文字含 kw 的可见行，返回 (中心x, 中心y, 文本) / None。
    带 kw 是硬要求（坑 G15：全量 25~40s，带 kw ~4s）。"""
    t = ks.text(kw)
    for l in t.splitlines():
        m = _ROW.match(l.strip())
        if not m:
            continue
        x, y, w, h = (float(m.group(2)), float(m.group(3)),
                      float(m.group(4)), float(m.group(5)))
        c = m.group(6)
        if kw not in c:
            continue
        if xr and not (xr[0] <= x <= xr[1]):
            continue
        if yr and not (yr[0] <= y <= yr[1]):
            continue
        return (x + w / 2, y + h / 2, c)
    return None


def claim_coins(verbose=True):
    """v34：把「待领金币」真的领到手（用户诉求：看完视频就把金币领了）。

    实测链路（2026-09-27，结果侧验证）：
      视频页 → 点左上角红包 (45,135) → 进任务中心
      任务中心 → 「待领2282金币 立即领取」 → 点它
      复验   → 同一位置变成「已领9268金币」= 真领到了（待领归零）

    ⚠ 两个坑（都踩过）：
      1) 这里必须用 rntap，不能用 gtap —— gtap 命中 RCTTextView（RN 文本），
         回执 ok=true 但按钮纹丝不动，待领数字一个都没少。
      2) 「已领 N 金币」是累计值不是本次值，判据只看「待领→已领」这个变化，
         不要拿 N 的前后差当本次收益。

    返回 (ok, 描述)。ok 只看结果侧文字，不信回执。
    """
    # 1) 已经在任务中心就别再点红包了
    row = _find_row("待领")
    if not row:
        k("gtap", {"x": 45, "y": 135})          # 红包容器 (0,90) 90x90 的中心
        time.sleep(2.5)
        row = _find_row("待领")
    if not row:
        return (False, "没找到「待领N金币」（可能无红包/页面不对）")

    cx, cy, txt = row
    before = txt
    if verbose:
        print("  领金币: 点「%s」@(%.0f,%.0f)" % (txt, cx, cy))

    # 2) rntap（gtap 打不中 RCTTextView）
    k("rntap", {"x": cx, "y": cy})
    time.sleep(2.5)

    # 3) 结果侧复验：待领消失 / 出现「已领」
    if _find_row("待领"):
        return (False, "点完仍是「%s」——没领到" % before)
    got = _find_row("已领")
    return (True, "已领 ✓ %s" % (got[2] if got else "(待领已清空)"))


def back_to_feed(max_back=4):
    """从任务中心退回视频页：连按返回，直到屏上重新出现红包或到底。
    返回是否疑似回到 feed（不保证，靠调用方判据）。"""
    for _ in range(max_back):
        k("back", {})
        time.sleep(1.2)
        if _find_row("金币", xr=(0, 100), yr=(85, 185)):
            return True
    return False


def snap():
    """一次 text 拿三样东西（text 很慢，绝不多调）：
       fp   指纹（评论/收藏/分享/点赞数）—— 广告位没有，会返回 {}
       tool 工具条按钮中心坐标（自适应：横滑剧集/普通视频/直播布局各不同）
       vis  屏内可见文字（用来判断是不是换了内容）
    """
    t = ks.text()
    fp, tool, vis = {}, {}, []
    for l in t.splitlines():
        m = _ROW.match(l.rstrip())
        if not m:
            continue
        x, y = float(m.group(2)), float(m.group(3))
        w, h = float(m.group(4)), float(m.group(5))
        c = m.group(6)
        if c.startswith("<"):
            continue
        if -60 <= y <= 900 and x < 390 and x + w > 0:
            vis.append(c[:40])
        mm = re.search(r'(评论|收藏|分享|点赞)([\d\.万亿\+]+)', c)
        if mm and mm.group(1) not in fp:
            fp[mm.group(1)] = mm.group(2)
        cx, cy = x + w / 2, y + h / 2
        if re.match(r'^(未点赞|已点赞|点赞\d)', c) and "like" not in tool:
            tool["like"] = (cx, cy)
        elif re.match(r'^评论\d', c) and "cmt" not in tool:
            tool["cmt"] = (cx, cy)
        elif re.match(r'^(未收藏|已收藏|收藏\d)', c) and "star" not in tool:
            tool["star"] = (cx, cy)
    return fp, tool, vis


def fingerprint():
    """每个视频唯一的指标：评论/收藏/分享数，用来判断是否真换了视频"""
    return snap()[0]


def watch_with_reward(dur, verbose=False):
    """v31：在预算 dur 内观看，若红包开奖（金额变化）就提前收工。

    返回 (实际停留秒数, 是否等到开奖, 红包金额或 None)。
    无红包 → 原样睡满 dur（回落随机时长）。
    """
    a0 = red_amount()
    if not a0:
        time.sleep(dur)
        return dur, False, None
    cap = min(dur, HARD_CAP)
    waited, won = 0.0, False
    while waited < cap:
        t0 = time.time()
        a1 = red_amount()               # 约 4s（带 kw）
        waited += time.time() - t0
        if a1 and a1 != a0:
            won = True                  # 开奖：圆环走满，这圈奖励已尽
            break
        if waited >= cap:
            break
        sl = min(random.uniform(3.0, 5.0), cap - waited)
        time.sleep(sl)
        waited += sl
    if not won and waited < cap:
        time.sleep(cap - waited)
        waited = cap
    return waited, won, a0


def brush(n=7, like=0.30, star=0.10, cmt=0.12, back=0.08, claim_every=0,
          verbose=True):
    """claim_every：每 N 个视频把待领金币领一次（0=不自动领）。
    ⚠ 领一次要离开 feed 进任务中心再回来，实测约 15~20s（导航+读屏），
      N=1（每个视频都领）会把刷视频拖慢一倍以上，默认关着。
      想严格按「每个视频看完就领」就传 claim_every=1。"""
    random.seed()
    _task(0, n, "开始", state="exec", brief="准备刷 %d 个" % n)
    log = []
    for i in range(n):
        acts = []
        fp, tool, vis = snap()          # 读一次界面（text 慢，顺带算观看时间）
        head = " / ".join([v for v in vis if not re.match(r'^[\d\.万亿\+]+$', v)][:2])[:50]
        p_like = tool.get("like", P_LIKE)
        p_cmt = tool.get("cmt", P_CMT)
        p_star = tool.get("star", P_STAR)
        dur = watch_time()
        # v31：红包进度驱动 —— 有红包就等开奖，开奖即换（实际 = min(随机, 开奖时刻)）
        waited, won, a0 = watch_with_reward(dur)
        if a0:
            _task(i + 1, n, "等红包开奖", state="exec", brief="待开奖 %s" % a0)
            acts.append("开奖" if won else "看完")
        if verbose:
            print("  #%d 停留%.0fs %s" % (i + 1, waited,
                  ("开奖✓ %s→%s" % (a0, red_amount())) if won else
                  (("等红包 %s 未开" % a0) if a0 else "无红包·随机")), flush=True)

        # 点赞（真人不是每条都赞）
        if random.random() < like:
            time.sleep(random.uniform(0.4, 1.6))
            k("tapui", {"x": p_like[0], "y": p_like[1]})
            acts.append("赞")
            time.sleep(random.uniform(0.6, 1.8))

        # 收藏（低频）
        if random.random() < star:
            time.sleep(random.uniform(0.4, 1.5))
            k("tapui", {"x": p_star[0], "y": p_star[1]})
            acts.append("藏")
            time.sleep(random.uniform(0.6, 1.8))

        # 看评论（开面板 → 浏览 → 关）
        if random.random() < cmt:
            time.sleep(random.uniform(0.5, 1.5))
            k("tapui", {"x": p_cmt[0], "y": p_cmt[1]})
            time.sleep(random.uniform(3, 8))          # 翻两下评论
            k("tapui", {"x": CLOSE_CMT[0], "y": CLOSE_CMT[1]})
            acts.append("评")
            time.sleep(random.uniform(0.8, 2.0))

        # 偶尔回滑重看上一个
        if random.random() < back:
            flip(back=True)
            acts.append("回滑")
            time.sleep(random.uniform(4, 10))

        # 切下一个
        d, step = flip()
        time.sleep(random.uniform(1.5, 3.5))

        # v34：到点就把待领金币领了（离开 feed → 任务中心 → 回来）
        if claim_every and ((i + 1) % claim_every == 0 or i == n - 1):
            okc, msg = claim_coins(verbose=verbose)
            acts.append("领✓" if okc else "领✗")
            if verbose:
                print("  领金币: %s" % msg, flush=True)
            back_to_feed()
            time.sleep(random.uniform(1.0, 2.5))

        log.append("{:>4.0f}s {} | {} | {} {}".format(
            dur, ",".join(acts) or "划走", head, d, fp))
        _task(i + 1, n, ",".join(acts) or "划走", ok=True)   # v30：进度上悬浮球
        if verbose:
            print("  #%d  %s" % (i + 1, log[-1]), flush=True)
    _task(0, 0, "")                          # v30：清空任务态
    return log


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    print("=== 真人刷视频 %d 个（上下滑）===" % n)
    fp0, _, _ = snap()
    print("起始指纹:", fp0, flush=True)
    brush(n=n)
    time.sleep(2)
    fp1, _, vis1 = snap()
    print("结束指纹:", fp1)
    print("判定:", "已换视频 ✓" if fp0 != fp1 else "指纹未变（可能是广告/直播位）")
    print("结果侧关键词：")
    for v in vis1:
        if re.search(r'任务完成|继续赚钱|看视频赚金币|已领|待领|立即领取|到账|金币', v):
            print("  ", v[:110])
    t = ks.text()
    print("--- 结果侧 ---")
    for l in t.splitlines():
        if re.search(r'点赞|评论|收藏|分享|任务完成|继续赚钱|关闭弹窗|看视频赚金币|已领|待领|立即领取|到账', l):
            print("  ", l[:110])
