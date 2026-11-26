#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报名表 xlsx → 校运会积分系统 JSON 转换器（v1.9.0 新增）。

⚠️ 本脚本**只进源码包**，绝不进发行包（与 tools/issue_license.py 同级）。
   它只做"读表 → 转 JSON"（可选代发到服务器），没有任何秘密。

为什么用 Python 转一道
---------------------
Rust 版二进制**不解析 xlsx**（不为一个导入引入几 MB 的依赖）。
流程：老师拿学校发的报名表 xlsx → 本脚本转成系统认识的 JSON →
（可选）直接 POST 进正在运行的系统，或把 JSON 文件交给网页端导入。

报名表格式（按学校实际模板，容错设计）
------------------------------------
    第 1 行    大标题（忽略）
    第 2 行    表头：序号 | 姓名（男） | 班别 | 100米 | 200米 | ... | 备注
    第 3 行起  数据：姓名、班别（如"奥创七7"）、项目列打勾（√）

    * 表头自动定位：**每个**含"姓名"的行都是一节表头（学校模板常见
      一张表里男女两节，列布局不同，逐节分别处理）；
    * 项目列 = 表头里除 序号/姓名/班别/班级/性别/备注 外的所有列；
    * 项目列单元格是**勾选标记**才算报名（√ ✓ ✔ ● ○ Y y 是 1 / 报名 /
      参加 / 参赛；× 不算——它更像"划掉"）；
    * 姓名含"示例"的行自动跳过（模板自带的两行示范数据）；
    * 性别：优先取"姓名（男）"括号里的提示，其次"性别"列，
      都没有则留空（系统不会按性别拦它）。

班别解析
--------
    "奥创七7"      → 年级=奥创七   班号=7
    "初一（7）班"  → 年级=初一     班号=7
    "初一7班"      → 年级=初一     班号=7
    解析不了的行进报告，不猜。

项目名匹配（--server 时）
------------------------
拿系统里的项目列表（GET /api/events）逐列匹配：
    1. 名称完全一致；
    2. 归一化一致：去空白、去「男子/女子/男/女」前缀、× 统一为 x、
       去尾部「接力」—— 覆盖"100米"对"男子100米"、"4×100米"对
       "4×100米接力"这类写法；
    3. 多个候选时按学生性别优选（男生→男子项，女生→女子项，再通用）。
匹配上的项目把 id 写进 JSON（event_id），系统端直接用；
没匹配上的列在报告里列出来，不会静默丢弃。

用法
----
    # 1) 只转 JSON（不联网）
    python3 tools/baoming_import.py --xlsx 报名表.xlsx --out 报名表.json

    # 2) 转换并直接导入正在运行的系统（自动匹配项目 id）
    python3 tools/baoming_import.py --xlsx 报名表.xlsx \
        --server http://127.0.0.1:8765 --password 管理口令 --post

    # 3) 自定义项目名映射（列名=项目名，分号隔开）
    python3 tools/baoming_import.py --xlsx 报名表.xlsx \
        --event-map "100米=男子100米;4×100米=4×100米接力" --post ...

依赖：openpyxl（pip install openpyxl）。不装也能跑 --help。
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

# 表头里这些列不是项目列
NON_EVENT_HEADERS = {"序号", "no", "no.", "编号", "姓名", "名字", "学生", "姓名（男）", "姓名（女）"}
CLASS_HEADERS = {"班别", "班级", "班"}
GENDER_HEADERS = {"性别"}
NOTE_HEADERS = {"备注", "说明"}
# 项目列里的这些值算"报名"（×/x 刻意不收：它更像"划掉"而不是"选中"）
MARK_RE = re.compile(r"^(?:[√✓✔●○Yy是1]|报名|参加|参赛)$")


def die(msg: str, code: int = 1):
    sys.stderr.write(f"错误：{msg}\n")
    sys.exit(code)


# ---------------------------------------------------------------------------
# xlsx 读取
# ---------------------------------------------------------------------------

def read_rows(xlsx_path: str):
    """读出所有行（list[list[str|None]]），空单元格统一成 None。"""
    try:
        import openpyxl
    except ImportError:
        die("需要 openpyxl：pip install openpyxl", 2)
    try:
        wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    except Exception as e:  # 文件损坏/格式不对
        die(f"打不开 xlsx：{e}", 2)
    ws = wb.worksheets[0]
    rows = []
    for row in ws.iter_rows(values_only=True):
        rows.append(["" if v is None else str(v).strip() for v in row])
    return rows


def cell(v) -> str:
    return "" if v is None else str(v).strip()


# ---------------------------------------------------------------------------
# 表头定位与列识别
# ---------------------------------------------------------------------------

def classify_columns(header):
    """把表头列分成：姓名/班别/性别/备注/项目列。返回 dict。"""
    name_col = class_col = gender_col = note_col = None
    event_cols = []  # (列下标, 项目名)
    for i, h in enumerate(header):
        h = cell(h)
        if not h:
            continue
        if h.startswith("姓名"):
            name_col = i
        elif h in CLASS_HEADERS:
            class_col = i
        elif h in GENDER_HEADERS:
            gender_col = i
        elif h in NOTE_HEADERS:
            note_col = i
        elif h.lower() in {"序号", "no", "no.", "编号"}:
            continue
        else:
            event_cols.append((i, h))
    if name_col is None:
        die("表头里没有「姓名」列", 2)
    if not event_cols:
        die("表头里没有识别出任何项目列", 2)
    return name_col, class_col, gender_col, note_col, event_cols


def gender_from_name_header(name_header: str) -> str:
    """"姓名（男）" → "男"；没有提示 → ""。"""
    m = re.search(r"[（(]\s*([男女])\s*[）)]", name_header)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# 班别解析
# ---------------------------------------------------------------------------

def parse_class(text: str):
    """'奥创七7' → ('奥创七', 7)；解析不了 → (None, None)。"""
    t = cell(text)
    if not t:
        return None, None
    # 初一（7）班 / 初一(7)班
    m = re.match(r"^(.+?)[（(](\d+)[）)]班?$", t)
    if m:
        return m.group(1).strip(), int(m.group(2))
    # 初一7班 / 初一 7 班 / 初一7
    m = re.match(r"^(\D+?)\s*(\d+)\s*班?$", t)
    if m and m.group(1).strip():
        return m.group(1).strip(), int(m.group(2))
    return None, None


# ---------------------------------------------------------------------------
# 项目匹配
# ---------------------------------------------------------------------------

def norm_event(s: str) -> str:
    """归一化项目名：去空白/性别前缀、× 统一、去尾部「接力」。"""
    s = re.sub(r"\s+", "", s)
    for p in ("男子", "女子"):
        if s.startswith(p):
            s = s[len(p):]
            break
    else:
        for p in ("男", "女"):
            if s.startswith(p):
                s = s[len(p):]
                break
    s = s.replace("×", "x").replace("X", "x")
    for suf in ("接力", "比赛", "赛"):
        if s.endswith(suf) and len(s) > len(suf):
            s = s[: -len(suf)]
            break
    return s


def match_event(column: str, gender: str, events, event_map):
    """在系统项目列表里为「表头列」找项目。返回 (event_id, event_name) 或 (None, None)。"""
    # 0) 显式映射优先（--event-map 或同名字段）
    if column in event_map:
        want = event_map[column]
        for ev in events:
            if ev["name"] == want:
                return ev["id"], ev["name"]
        return None, None
    # 1) 完全一致
    for ev in events:
        if ev["name"] == column:
            return ev["id"], ev["name"]
    # 2) 归一化一致，按性别优选
    cands = [ev for ev in events if norm_event(ev["name"]) == norm_event(column)]
    if cands:
        want_gender = {"男": "男子", "女": "女子"}.get(gender)
        for ev in cands:
            if ev.get("gender") == want_gender:
                return ev["id"], ev["name"]
        for ev in cands:
            if ev.get("gender") == "通用":
                return ev["id"], ev["name"]
        return cands[0]["id"], cands[0]["name"]
    return None, None


# ---------------------------------------------------------------------------
# 服务器交互
# ---------------------------------------------------------------------------

def http_json(method: str, url: str, body=None, bearer: str = ""):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        die(f"服务器返回 {e.code}：{detail[:300]}", 3)
    except urllib.error.URLError as e:
        die(f"连不上服务器 {url}：{e.reason}", 3)


def fetch_events(server: str, bearer: str):
    """取系统项目列表。兼容 {data:{events:[]}} / {events:[]} / [ ... ] 三种形状。"""
    d = http_json("GET", f"{server.rstrip('/')}/api/events", bearer=bearer)
    if isinstance(d.get("data"), dict):
        evs = d["data"].get("events")
    elif isinstance(d.get("data"), list):
        evs = d["data"]
    else:
        evs = d.get("events")
    if not isinstance(evs, list):
        die("/api/events 返回格式异常", 3)
    return evs


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def is_header_row(row) -> bool:
    """是不是表头行：有单元格以「姓名」开头，且行内容足够丰富。

    学校模板常见**一张表里男女两节**（如"姓名（男）"一节、"姓名(女）"一节），
    每节有各自的列布局（男生 1000米/引体向上，女生 800米/仰卧起坐）——
    所以不能只找第一个表头，要把每一节都认出来。
    """
    has_name = any(cell(c).startswith("姓名") for c in row)
    filled = sum(1 for c in row if cell(c))
    return has_name and filled >= 3


def convert(xlsx_path: str, gender_override: str, events, event_map):
    """读表 → (payload, report)。events 为空列表表示离线模式。"""
    rows = read_rows(xlsx_path)
    # 1) 找出所有表头行（可能有多节）
    sections = [(i, row) for i, row in enumerate(rows) if is_header_row(row)]
    if not sections:
        die("找不到表头（需要有一行包含「姓名」）", 2)

    students = []
    registrations = []
    bad_class = []      # 班别解析失败
    skipped_example = 0
    unmatched_cols = {} # 列名 → 次数（仅在线模式）
    student_key = {}    # (grade, class_no, name) → True，跨节去重

    # 2) 逐节处理：本节数据 = 表头行的下一行到下一个表头行之前
    for si, (hi, header) in enumerate(sections):
        end = sections[si + 1][0] if si + 1 < len(sections) else len(rows)
        name_col, class_col, gender_col, note_col, event_cols = classify_columns(header)
        header_gender = gender_from_name_header(cell(header[name_col]))
        for row in rows[hi + 1:end]:
            name = cell(row[name_col]) if name_col < len(row) else ""
            if not name:
                continue
            if "示例" in name:
                skipped_example += 1
                continue
            # 性别：覆盖参数 > 姓名表头提示 > 性别列
            if gender_override:
                gender = gender_override
            elif header_gender:
                gender = header_gender
            elif gender_col is not None and gender_col < len(row):
                g = cell(row[gender_col])
                gender = g if g in ("男", "女") else ""
            else:
                gender = ""
            # 班别
            raw_class = cell(row[class_col]) if class_col is not None and class_col < len(row) else ""
            grade, class_no = parse_class(raw_class)
            if not grade or not class_no:
                bad_class.append((name, raw_class))
                continue
            note = cell(row[note_col]) if note_col is not None and note_col < len(row) else ""
            key = (grade, class_no, name)
            if key not in student_key:
                student_key[key] = True
                students.append(
                    {"name": name, "grade": grade, "class_no": class_no, "gender": gender}
                )
            # 项目列：非空且是勾选标记才算报名
            for ci, col_name in event_cols:
                mark = cell(row[ci]) if ci < len(row) else ""
                if not mark or not MARK_RE.match(mark):
                    continue
                entry = {
                    "name": name,
                    "grade": grade,
                    "class_no": class_no,
                    "event": col_name,
                    "note": note,
                }
                if events:
                    eid, ename = match_event(col_name, gender, events, event_map)
                    if eid is None:
                        unmatched_cols[col_name] = unmatched_cols.get(col_name, 0) + 1
                        continue
                    entry["event_id"] = eid
                    entry["event"] = ename
                registrations.append(entry)

    grades = []
    for s in students:
        if s["grade"] not in grades:
            grades.append(s["grade"])
    payload = {
        "source": os.path.basename(xlsx_path),
        "generated_by": "baoming_import.py (v1.9.0)",
        "ensure_grades": True,
        "grades": grades,
        "students": students,
        "registrations": registrations,
    }
    report = {
        "students": len(students),
        "registrations": len(registrations),
        "skipped_example": skipped_example,
        "bad_class": bad_class,
        "unmatched_cols": unmatched_cols,
        "grades": grades,
        "offline": not events,
    }
    return payload, report


def parse_event_map(text: str):
    """"100米=男子100米;4×100米=4×100米接力" → dict。"""
    out = {}
    for part in re.split(r"[;；]", text or ""):
        part = part.strip()
        if not part or "=" not in part and "＝" not in part:
            continue
        k, _, v = part.partition("=") if "=" in part else part.partition("＝")
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


def print_report(report):
    print(f"学生 {report['students']} 人，报名 {report['registrations']} 人次"
          + ("（离线模式：未匹配项目 id，靠系统端按名称匹配）" if report["offline"] else ""))
    if report["skipped_example"]:
        print(f"  跳过示例行 {report['skipped_example']} 行（姓名含「示例」）")
    if report["bad_class"]:
        print(f"  ⚠ 班别解析失败 {len(report['bad_class'])} 行（未导入）：")
        for name, raw in report["bad_class"][:10]:
            print(f"    - {name}：班别「{raw or '（未填）'}」")
    if report["unmatched_cols"]:
        print("  ⚠ 以下项目列在系统里找不到对应项目（相关报名未生成）：")
        for col, n in report["unmatched_cols"].items():
            print(f"    - {col}（{n} 人次）—— 请先在系统里建同名项目，或用 --event-map 指定")


def main():
    ap = argparse.ArgumentParser(
        description="报名表 xlsx → 校运会积分系统 JSON（v1.9.0；只进源码包）"
    )
    ap.add_argument("--xlsx", required=True, help="报名表 xlsx 路径")
    ap.add_argument("--out", default=None, help="输出 JSON 路径（默认与 xlsx 同名的 .json）")
    ap.add_argument("--gender", default="", choices=["", "男", "女"], help="强制性别（默认从表头推断）")
    ap.add_argument("--server", default="", help="系统地址，如 http://127.0.0.1:8765（给了才能匹配项目 id）")
    ap.add_argument("--password", default="", help="管理口令（系统设了口令时必填；作为 Bearer 发送）")
    ap.add_argument("--event-map", default="", help='项目名映射，如 "100米=男子100米;4×100米=4×100米接力"')
    ap.add_argument("--post", action="store_true", help="转换后直接 POST 到 --server（需先能连上）")
    args = ap.parse_args()

    if not os.path.exists(args.xlsx):
        die(f"文件不存在：{args.xlsx}", 2)
    out = args.out or os.path.splitext(args.xlsx)[0] + ".json"

    bearer = args.password
    events = []
    if args.server:
        events = fetch_events(args.server, bearer)
        print(f"已从 {args.server} 取到 {len(events)} 个项目")
    elif args.post:
        die("--post 需要同时给出 --server", 2)

    event_map = parse_event_map(args.event_map)
    payload, report = convert(args.xlsx, args.gender, events, event_map)

    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"已生成 {out}")
    print_report(report)

    if args.post:
        url = f"{args.server.rstrip('/')}/api/import/baoming"
        d = http_json("POST", url, payload, bearer=bearer)
        data = d.get("data", d)
        print()
        print(f"导入完成：学生 +{data.get('added', 0)}，报名 +{data.get('registrations_added', 0)}")
        if data.get("grades_added"):
            print(f"  自动添加年级：{'、'.join(data['grades_added'])}")
        skipped = data.get("skipped") or []
        if skipped:
            print(f"  跳过 {len(skipped)} 条：")
            for e in skipped[:15]:
                print(f"    - {e.get('name', '?')}：{e.get('reason', '?')}")
            if len(skipped) > 15:
                print(f"    ……另有 {len(skipped) - 15} 条")


if __name__ == "__main__":
    main()
