#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整性自校验盖章工具（v1.9.0 手段 2 的构建期环节）。

⚠️ 本脚本**只进源码包**，绝不进发行包。
   它给二进制"盖章"（写入期望哈希）；没有它，发行构建停在基线模式
   （自校验只算不判）。攻击者拿到它也没有意义 —— 它只能读二进制、
   算哈希、写缓存，不能伪造任何东西。

原理（对应 src/core/aim/integrity.rs）
------------------------------------
二进制里内嵌一段 160 字节数据区（build.rs 从
target/integrity_cache.bin 组装）：

    [0..8)     起始魔数 "SMI1DATA"（运行期搜索锚）
    [8..136)   8 段期望哈希（每段 SHA-512 前 16 字节）
    [136..144) 8 个交叉指纹（第 i 段与第 i+1 段异或后的字节和）
    [144)      盖章标志：1 = 已盖章（真实期望值），0 = 基线（占位符）
    [145..152) 保留（零）
    [152..160) 结束魔数 "DATA1SMI"

运行期校验时，先把数据区**掩码归零**，再对全文件均分 8 段算哈希。
因为"期望值"与"被掩码掉的内容"是同一段字节，嵌入真实期望值
不改变掩码后的内容 —— 两遍构建达到**不动点**：

    第一遍（无缓存）：BLOB 占位符 + 标志 0 → 基线模式，不算真实期望值
    本脚本盖章      ：对第一遍产物掩码后算期望值 → 写缓存
    第二遍（有缓存）：嵌入真实期望值 + 标志 1 → 掩码后内容与第一遍相同
    本脚本 --verify ：复算 + 与缓存/内嵌值三方比对

定位数据区时逐个候选校验「结束魔数 + 交叉指纹」—— 假候选通过
概率 2^-64（与运行期 mask_blob 的策略完全一致）。

同时把 GNU build-id 笔记的 desc 归零：它是链接器对**全部节内容**
算的哈希，BLOB 内容两遍构建间不同 → build-id 不同 → 只掩码 BLOB
仍达不到不动点（v1.9.0 实测：段 0 复算永远不符，报错完全不提示
真正原因）。笔记头（namesz/descsz/type/name）静态，只归零 desc。

用法
----
    # 盖章（在两遍构建之间执行）
    python3 integrity_stamp.py --binary target/release/sports-meet

    # 复算比对（第二遍构建后执行，必须全部一致）
    python3 integrity_stamp.py --binary target/release/sports-meet --verify

    # 显式指定缓存路径（默认取二进制同级目录的 ../integrity_cache.bin，
    # 即 target/integrity_cache.bin —— build.rs 读的就是它）
    python3 integrity_stamp.py --binary target/release/sports-meet \
        --cache target/integrity_cache.bin
"""

import argparse
import hashlib
import os
import sys

MAGIC_START = b"SMI1DATA"
MAGIC_END = b"DATA1SMI"
BLOB_LEN = 160
OFF_HASHES = 8
OFF_CROSS = 136
OFF_FLAG = 144
OFF_END = 152
FLAG_STAMPED = 1
SEGMENTS = 8
SEG_LEN = 16
CACHE_LEN = SEGMENTS * SEG_LEN + SEGMENTS  # 136


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def cross_consistent(hashes: bytes, cross: bytes) -> bool:
    """交叉指纹是否与段哈希自洽（排除"恰好出现的假数据区"）。"""
    if len(hashes) != SEGMENTS * SEG_LEN or len(cross) != SEGMENTS:
        return False
    segs = [hashes[i * SEG_LEN : (i + 1) * SEG_LEN] for i in range(SEGMENTS)]
    for i in range(SEGMENTS):
        a, b = segs[i], segs[(i + 1) % SEGMENTS]
        acc = 0
        for k in range(SEG_LEN):
            acc = (acc + (a[k] ^ b[k])) & 0xFF
        if acc != cross[i]:
            return False
    return True


def locate_blob(data: bytes):
    """在二进制里定位数据区（起始魔数 + 结束魔数 + 交叉指纹三重确认）。

    返回 (pos, stamped)：stamped=False 表示这是基线构建（占位符 +
    标志 0）。数据区由 build.rs 保证只在二进制中出现一次（搜索锚
    取自 BLOB 自身，运行期同理）；这里仍逐个候选校验，防巧合命中。
    """
    pos = data.find(MAGIC_START)
    while pos >= 0:
        end = pos + BLOB_LEN
        if end <= len(data) and data[pos + OFF_END : pos + OFF_END + 8] == MAGIC_END:
            hashes = data[pos + OFF_HASHES : pos + OFF_HASHES + SEGMENTS * SEG_LEN]
            cross = data[pos + OFF_CROSS : pos + OFF_CROSS + SEGMENTS]
            if cross_consistent(hashes, cross):
                return pos, data[pos + OFF_FLAG] == FLAG_STAMPED
        pos = data.find(MAGIC_START, pos + 1)
    return None, False


def compute_expected(data: bytes):
    """对（已掩码的）二进制算 8 段期望哈希 + 交叉指纹。

    data 必须是**已经掩码过**的内容；调用方负责把数据区归零。
    """
    n = len(data)
    segs = []
    for i in range(SEGMENTS):
        s = i * n // SEGMENTS
        e = (i + 1) * n // SEGMENTS
        segs.append(sha512(data[s:e])[:SEG_LEN])
    cross = []
    for i in range(SEGMENTS):
        a = segs[i]
        b = segs[(i + 1) % SEGMENTS]
        acc = 0
        for k in range(SEG_LEN):
            acc = (acc + (a[k] ^ b[k])) & 0xFF
        cross.append(acc)
    return segs, cross


def mask_build_id(buf: bytearray) -> None:
    """把 GNU build-id 笔记的 desc 归零（内容派生，破坏不动点）。

    笔记布局（小端）：[namesz=4][descsz][type=3]["GNU\\0"][desc...]。
    只归零 desc；头是静态的（两遍构建相同）不用动。
    匹配收紧（namesz==4 且 0<descsz<=64）：假阳性会顺带掩盖一段内容 →
    哈希不符 → --verify 响亮失败，不会静默放过。
    与 integrity.rs 的 mask_build_id 逐字节同策略。
    """
    pat = b"\x03\x00\x00\x00GNU\x00"
    pos = buf.find(pat)
    while pos >= 0:
        if pos >= 8:
            namesz = int.from_bytes(buf[pos - 8 : pos - 4], "little")
            descsz = int.from_bytes(buf[pos - 4 : pos], "little")
            if namesz == 4 and 0 < descsz <= 64:
                end = min(pos + 8 + descsz, len(buf))
                for i in range(pos + 8, end):
                    buf[i] = 0
        pos = buf.find(pat, pos + 1)


def masked_copy(data: bytes, pos: int) -> bytearray:
    """复制一份并把数据区 + build-id desc 归零（不修改原数据）。"""
    buf = bytearray(data)
    for i in range(pos, pos + BLOB_LEN):
        buf[i] = 0
    mask_build_id(buf)
    return buf


def default_cache_path(binary: str) -> str:
    """默认缓存路径：<target>/integrity_cache.bin。

    二进制在 target/release/ 下 → 上两级即 target/。
    """
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(binary))), "integrity_cache.bin")


# ---------------------------------------------------------------------------
# Windows/PE：把「第二遍重新链接」换成「原地打补丁」
# ---------------------------------------------------------------------------
#
# 为什么必须这样（v1.9.0 Windows 实测，2026-10-28）：
# Linux 的 ELF 两遍构建能做到"除数据区外逐字节相同"，所以第二次 cargo
# build 嵌入期望值即可达到不动点。PE 做不到 —— 同样的源码、同样的链接，
# 两遍产物一共有 2 个字节不同：
#
#   偏移 e_lfanew+8  COFF 头 TimeDateStamp   链接器每次取当前时间（相差几十秒）
#   可选头 CheckSum                          GNU ld 按内容重算，随上面那个变
#
# 结果：盖章时算的期望值，第二遍一定对不上（8 段全红，报"二进制被改过？"）。
# 关掉时间戳（链接器 --no-insert-timestamp）又会引入新的构建参数分叉，
# 且不影响 CheckSum 的行为差异。
#
# 因此 Windows 改为：**只构建一遍 → 盖章 → 直接把期望值补进数据区**。
# 数据区 160 字节在 `sm_integ` 独立节里（不参与任何重定位/校验和语义），
# 原地改写它既不影响程序运行，也不需要重新链接；`--verify` 随后复算
# 仍是同一份文件的同一份掩码内容，三方比对必然一致 —— 不动点由
# "文件不变" 直接保证，比依赖链接器确定性更稳。
#
# 交付物仍是一个完整、可真机运行的 .exe（运行期掩码逻辑与 Linux 完全一致）。

def pe_blob_offset(data: bytes):
    """返回 PE 文件里 sm_integ 节的文件偏移范围 (start, end)；非 PE 返回 None。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    nsec = int.from_bytes(data[e_lfanew + 6 : e_lfanew + 8], "little")
    optsz = int.from_bytes(data[e_lfanew + 20 : e_lfanew + 22], "little")
    sec = e_lfanew + 24 + optsz
    for i in range(nsec):
        ent = sec + i * 40
        if ent + 40 > len(data):
            return None
        name = data[ent : ent + 8].rstrip(b"\0").decode("latin-1")
        if name == "sm_integ":
            raw_off = int.from_bytes(data[ent + 20 : ent + 24], "little")
            raw_sz = int.from_bytes(data[ent + 16 : ent + 20], "little")
            return raw_off, raw_off + raw_sz
    return None


def patch_pe_blob(binary: str, cache_path: str) -> int:
    """把缓存里的期望值原地写进 PE 的 sm_integ 数据区。"""
    try:
        with open(cache_path, "rb") as f:
            payload = f.read()
    except FileNotFoundError:
        sys.stderr.write(f"找不到缓存文件：{cache_path}（先执行盖章）\n")
        return 1
    if len(payload) != CACHE_LEN:
        sys.stderr.write(f"缓存长度异常：应 {CACHE_LEN}，实 {len(payload)}\n")
        return 1
    with open(binary, "rb") as f:
        data = f.read()
    rng = pe_blob_offset(data)
    if rng is None:
        sys.stderr.write("不是 PE 文件或找不到 sm_integ 节\n")
        return 1
    pos, stamped = locate_blob(data)
    if pos is None:
        sys.stderr.write("数据区里找不到完整性魔数（BLOB 未注入？）\n")
        return 1
    if pos + BLOB_LEN > rng[1]:
        sys.stderr.write(f"数据区越出 sm_integ 节范围（{pos}+{BLOB_LEN} > {rng[1]}）\n")
        return 1
    buf = bytearray(data)
    buf[pos + OFF_HASHES : pos + OFF_HASHES + SEGMENTS * SEG_LEN] = payload[: SEGMENTS * SEG_LEN]
    buf[pos + OFF_CROSS : pos + OFF_CROSS + SEGMENTS] = payload[SEGMENTS * SEG_LEN :]
    buf[pos + OFF_FLAG] = FLAG_STAMPED
    with open(binary, "wb") as f:
        f.write(buf)
    print(f"已把期望值原地写入 PE 数据区（偏移 {pos}，节 {rng[0]}..{rng[1]}）")
    print("  说明：Windows 走「一遍构建 + 原地打补丁」，不再重新链接")
    print("        （PE 头有构建时间戳，两遍构建做不到逐字节相同）。")
    return 0


def cmd_stamp(binary: str, cache_path: str) -> int:
    with open(binary, "rb") as f:
        data = f.read()
    pos, stamped = locate_blob(data)
    if pos is None:
        sys.stderr.write(
            "二进制里找不到完整性数据区（魔数缺失）。\n"
            "这说明 build.rs 未注入数据区 —— 请先执行一次普通 "
            "`cargo build --release` 再盖章。\n"
            "（历史坑：const 数组会被 LTO 折叠消除，数据区必须由 "
            "`#[used] #[link_section] static` 承载，见 build.rs 注释。）\n"
        )
        return 1
    if stamped:
        sys.stderr.write(
            "注意：该二进制已盖章（数据区含真实期望值）。\n"
            "重复盖章没有意义（结果相同）；若改了源码请重新走两遍构建。\n"
        )
    buf = masked_copy(data, pos)
    segs, cross = compute_expected(buf)
    payload = b"".join(segs) + bytes(cross)
    assert len(payload) == CACHE_LEN
    os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(payload)
    print(f"已盖章 → {cache_path}（{CACHE_LEN} 字节）")
    print(f"  数据区位置：文件偏移 {pos}（二进制总长 {len(data)}）")
    print(f"  段哈希数  ：{SEGMENTS} × {SEG_LEN} 字节；交叉指纹 {SEGMENTS} 字节")
    print()
    print("下一步（第二遍构建，嵌入真实期望值）：")
    print("  touch build.rs && cargo build --release")
    print("然后复算比对：")
    print(f"  python3 {os.path.basename(__file__)} --binary {binary} --verify")
    return 0


def cmd_verify(binary: str, cache_path: str) -> int:
    with open(binary, "rb") as f:
        data = f.read()
    pos, stamped = locate_blob(data)
    if pos is None:
        sys.stderr.write("二进制里找不到完整性数据区（魔数缺失）——未盖章或构建异常。\n")
        return 1
    if not stamped:
        sys.stderr.write(
            "该二进制处于基线模式（数据区为占位符、标志 0）——未嵌入期望值。\n"
            "发行包不应处于此状态：请检查两遍构建流程是否完整执行。\n"
        )
        return 1
    # 1) 缓存文件
    try:
        with open(cache_path, "rb") as f:
            cached = f.read()
    except FileNotFoundError:
        sys.stderr.write(f"找不到缓存文件：{cache_path}（先执行盖章）\n")
        return 1
    if len(cached) != CACHE_LEN:
        sys.stderr.write(f"缓存长度异常：应 {CACHE_LEN}，实 {len(cached)}\n")
        return 1
    cache_segs = [cached[i * SEG_LEN : (i + 1) * SEG_LEN] for i in range(SEGMENTS)]
    cache_cross = list(cached[SEGMENTS * SEG_LEN :])
    # 2) 复算（掩码后应与盖章时完全一致 —— 不动点）
    buf = masked_copy(data, pos)
    segs, cross = compute_expected(buf)
    # 3) 二进制内嵌值
    embed_segs = [
        data[pos + OFF_HASHES + i * SEG_LEN : pos + OFF_HASHES + (i + 1) * SEG_LEN]
        for i in range(SEGMENTS)
    ]
    embed_cross = list(data[pos + OFF_CROSS : pos + OFF_CROSS + SEGMENTS])

    ok = True
    for i in range(SEGMENTS):
        if segs[i] != cache_segs[i]:
            print(f"❌ 段 {i}：复算值与缓存不符")
            ok = False
        if segs[i] != embed_segs[i]:
            print(f"❌ 段 {i}：复算值与二进制内嵌值不符（二进制被改过？）")
            ok = False
        if embed_segs[i] != cache_segs[i]:
            print(f"❌ 段 {i}：内嵌值与缓存不符（第二遍构建没拿到缓存？）")
            ok = False
    for i in range(SEGMENTS):
        if cross[i] != cache_cross[i]:
            print(f"❌ 交叉指纹 {i}：复算值与缓存不符")
            ok = False
        if embed_cross[i] != cache_cross[i]:
            print(f"❌ 交叉指纹 {i}：内嵌值与缓存不符")
            ok = False
    if ok:
        print("✅ 完整性三方比对一致（复算 == 缓存 == 二进制内嵌）。")
        print(f"  数据区位置：文件偏移 {pos}；二进制总长 {len(data)}")
        print("  运行期 verify_self() 将通过；改动二进制任一字节都会让它变红。")
        return 0
    return 1


def main():
    ap = argparse.ArgumentParser(description="完整性自校验盖章工具（v1.9.0 手段 2）")
    ap.add_argument(
        "--binary",
        default="target/release/sports-meet",
        help="待盖章/待校验的二进制路径",
    )
    ap.add_argument(
        "--cache",
        default=None,
        help="缓存文件路径（默认 <target>/integrity_cache.bin，build.rs 读取它）",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="复算比对模式（第二遍构建后执行）",
    )
    ap.add_argument(
        "--patch-pe",
        action="store_true",
        help="Windows：用缓存里的期望值原地写入 PE 数据区（替代第二遍重新链接）",
    )
    args = ap.parse_args()
    cache = args.cache or default_cache_path(args.binary)
    if not os.path.exists(args.binary):
        sys.stderr.write(f"二进制不存在：{args.binary}\n")
        sys.exit(1)
    if args.verify:
        sys.exit(cmd_verify(args.binary, cache))
    if args.patch_pe:
        sys.exit(patch_pe_blob(args.binary, cache))
    sys.exit(cmd_stamp(args.binary, cache))


if __name__ == "__main__":
    main()
