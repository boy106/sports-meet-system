#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
授权签发工具（手段 1：非对称离线许可 + v1.9.0：48 位激活密钥）。

⚠️ 本脚本**只进源码包**，绝不进发行包。
   它含私钥 / 主密钥的读写逻辑；发行包（用户拿到的）只有编译进
   二进制的公钥与主密钥（均不可逆向出签发能力）。

用法
----
A) Ed25519 离线许可（license.lic，不可伪造性最强）

1) 首次生成密钥对（私钥留在你手上，公钥嵌入客户端）：

       python3 issue_license.py keygen --out ./keys

   产出：
     keys/issuer.key   私钥（32 字节 hex）—— 绝不可外泄
     keys/issuer.pub   公钥（32 字节 hex）—— 需要编译进客户端

2) 给某台机器签发许可（需要该机器的 hwid，客户端「诊断」页可查）：

       python3 issue_license.py issue \
           --key ./keys/issuer.key \
           --hwid ab12cd34ef567890... \
           --days 365 \
           --kind persistent \
           --out license.lic

   产出 license.lic（JSON），用户放到客户端 data/ 目录即可离线激活。

3) 校验一份许可（自检，不修改任何东西）：

       python3 issue_license.py verify \
           --pub ./keys/issuer.pub \
           --file license.lic

B) 48 位激活密钥（v1.9.0，数字/字母/符号/汉字交替，纯离线）

1) 生成密钥主密钥（32 字节 hex；与 issuer.key 同一保管级别）：

       python3 issue_license.py keygen-secret --out ./keys

   产出 keys/aim.secret（权限 600）。把它交给 build.rs：
   构建发行包时它会被掩码注入二进制（源码与发行包中均无明文）。

2) 给某台机器签发一枚 48 位密钥：

       python3 issue_license.py issue-key \
           --secret ./keys/aim.secret \
           --hwid ab12cd34ef567890... \
           --days 365 \
           --kind pro \
           --uses 500 \
           --seconds 36000 \
           --features all

   参数即密钥内嵌的限制（全部加密后编入 48 位字符）：
     --days     有效天数（<=0 = 永久）
     --from-days N 天后生效（默认 0 = 立即）
     --kind     trial/standard/pro/edu/demo
     --uses     使用次数上限（0 = 不限）
     --seconds  累计使用时长上限，秒（0 = 不限）
     --features 功能位：basic,export,smart,schedule,print,multi,all
     --key-id   密钥编号（24 位；缺省随机，便于事后追溯是哪一批）

   产出即 48 位密钥文本（屏幕打印 + 可选 --out 存文件），
   用户在客户端「诊断/授权」页粘贴激活。

3) 校验一枚密钥（自检：格式、CRC、标签、时效、内嵌限制）：

       python3 issue_license.py verify-key \
           --secret ./keys/aim.secret \
           --hwid ab12cd34ef567890... \
           --key "0aA!一..."

字段与 Rust 端 `src/core/aim/keyfmt.rs` 必须**逐字节一致**：
   明文(26B) = 魔数 ‖ 版本/类型 ‖ 指纹48 ‖ 生效日 ‖ 到期日 ‖
               时长上限(u24) ‖ 次数上限(u16) ‖ 功能位(u16) ‖ 编号(u24)
   封装(38B) = 明文(26B) ‖ 认证标签(10B) ‖ CRC16(2B)
   48 字符  = 38 字节按混合进位制（数字×字母×符号×汉字，12 组）展开
改动此处需同步改 Rust 端，否则全部历史密钥失效。
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time
from hashlib import sha512

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.stderr.write(
        "缺少依赖：cryptography。请先安装：\n"
        "  pip install cryptography\n"
    )
    sys.exit(2)

LICENSE_VERSION = 1
SEP = "\x1f"
MAGIC = "SM1"


def license_message(hwid: str, exp: int, kind: str, version: int) -> bytes:
    """与 Rust 端 license_message() 完全一致的规范化消息串。"""
    return f"{MAGIC}{SEP}{version}{SEP}{hwid}{SEP}{exp}{SEP}{kind}".encode("utf-8")


def cmd_keygen(args):
    out = args.out
    os.makedirs(out, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_path = os.path.join(out, "issuer.key")
    pub_path = os.path.join(out, "issuer.pub")

    if os.path.exists(key_path) and not args.force:
        sys.stderr.write(
            f"私钥已存在：{key_path}\n"
            "若确实要重新生成（**会使已签发的所有许可失效**），加 --force。\n"
        )
        sys.exit(1)

    with open(key_path, "w") as f:
        f.write(sk_bytes.hex())
    os.chmod(key_path, 0o600)
    with open(pub_path, "w") as f:
        f.write(pk_bytes.hex())

    print(f"私钥 → {key_path}  (权限 600，务必离线保管)")
    print(f"公钥 → {pub_path}")
    print()
    print("把公钥编译进客户端：")
    print(f"  src/core/aim/asym.rs 的 ISSUER_PUBLIC_KEY = b\"{pk_bytes.hex()}\"")
    print()
    print(f"公钥 hex: {pk_bytes.hex()}")


def cmd_issue(args):
    with open(args.key) as f:
        sk_hex = f.read().strip()
    sk_bytes = bytes.fromhex(sk_hex)
    if len(sk_bytes) != 32:
        sys.stderr.write(f"私钥长度应为 32 字节，实为 {len(sk_bytes)}\n")
        sys.exit(1)
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)

    exp = 0 if args.days <= 0 else int(time.time()) + args.days * 86400
    kind = args.kind
    if kind not in ("persistent", "temporary"):
        sys.stderr.write("kind 只能是 persistent 或 temporary\n")
        sys.exit(1)

    msg = license_message(args.hwid, exp, kind, LICENSE_VERSION)
    sig = sk.sign(msg)
    assert len(sig) == 64

    lic = {
        "v": LICENSE_VERSION,
        "hwid": args.hwid,
        "exp": exp,
        "kind": kind,
        # 掩码仅用于"不让肉眼直接读出到期时间"，不参与安全
        "mask": secrets.randbits(48),
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    text = json.dumps(lic, ensure_ascii=False, indent=2)
    with open(args.out, "w") as f:
        f.write(text)
    exp_desc = "永久" if exp == 0 else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
    print(f"许可已签发 → {args.out}")
    print(f"  机器指纹: {args.hwid}")
    print(f"  类型    : {kind}")
    print(f"  到期    : {exp_desc}")


def cmd_verify(args):
    with open(args.pub) as f:
        pk_bytes = bytes.fromhex(f.read().strip())
    with open(args.file) as f:
        lic = json.load(f)

    pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    msg = license_message(lic["hwid"], lic["exp"], lic["kind"], lic["v"])
    sig = base64.b64decode(lic["sig"])
    try:
        pk.verify(sig, msg)
        ok = True
    except Exception:
        ok = False
    if ok:
        exp_desc = "永久" if lic["exp"] == 0 else time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(lic["exp"])
        )
        print(f"✅ 签名有效。机器={lic['hwid']} 类型={lic['kind']} 到期={exp_desc}")
    else:
        print("❌ 签名无效（文件被篡改，或公钥不对）。")
        sys.exit(1)


# ===========================================================================
# 48 位激活密钥（v1.9.0）
#
# 与 Rust 端 src/core/aim/keyfmt.rs 逐字节对应的实现。
# 任何字段宽度/字节序/派生标签的改动都必须两边同步。
# ===========================================================================

KEY_LEN = 48
CLASSES = 4
CYCLES = KEY_LEN // CLASSES  # 12
DIGITS = "0123456789"
LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
# 与 keyfmt.rs 的 SYMBOLS 完全一致：! @ # $ % ^ & * ( ) - _ = +
#   [ ] { } ; : ' " , . < > / ? \ | ~ `
SYMBOLS = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|~`"
HANZI_BASE = 0x4E00
HANZI_COUNT = 3500
RADIX = len(DIGITS) * len(LETTERS) * len(SYMBOLS) * HANZI_COUNT  # 58,240,000
DATA_BYTES = 38
PLAIN_LEN = 26
TAG_LEN = 10
PLAIN_MAGIC = 0xA7
FORMAT_VERSION = 1
DAY_PERPETUAL = 0xFFFFFFFF

FEATURES = {
    "basic": 1 << 0,
    "export": 1 << 1,
    "smart": 1 << 2,
    "schedule": 1 << 3,
    "print": 1 << 4,
    "multi": 1 << 5,
}
FEATURE_NAMES = {v: k for k, v in FEATURES.items()}
FEATURE_LABELS = {
    "basic": "基础积分",
    "export": "导出",
    "smart": "智能解析",
    "schedule": "赛程编排",
    "print": "打印",
    "multi": "批量",
}
KIND_BY_NAME = {
    "trial": 0,
    "standard": 1,
    "pro": 2,
    "edu": 3,
    "demo": 4,
}
KIND_NAME_BY_ID = {v: k for k, v in KIND_BY_NAME.items()}
KIND_LABELS = {
    "trial": "试用版",
    "standard": "标准版",
    "pro": "专业版",
    "edu": "教育版",
    "demo": "体验版",
}

# 自检：字符表与 Rust 端必须同尺寸（错一位则全部密钥不兼容）
assert len(DIGITS) == 10, "数字表应为 10 项"
assert len(LETTERS) == 52, "字母表应为 52 项"
assert len(SYMBOLS) == 32, f"符号表应为 32 项，实为 {len(SYMBOLS)}"


def _crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE（poly 0x1021, init 0xFFFF）。"""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def hwid48(hwid: str) -> bytes:
    """机器指纹摘要（48 位，与 keyfmt.rs 一致）。"""
    return sha512(hwid.encode("utf-8")).digest()[:6]


def _derive(tag: bytes, secret: bytes, hwid: str) -> bytes:
    """用途密钥派生：SHA512(tag ‖ secret ‖ hwid48)[..32]。"""
    return sha512(tag + secret + hwid48(hwid)).digest()[:32]


def _keystream(key: bytes, length: int) -> bytes:
    """SHA-512 计数器模式密钥流（块 = key ‖ "KS" ‖ counter_be8）。"""
    out = b""
    counter = 0
    while len(out) < length:
        out += sha512(key + b"KS" + counter.to_bytes(8, "big")).digest()
        counter += 1
    return out[:length]


def _mac(key: bytes, ciphertext: bytes, hwid: str) -> bytes:
    """认证标签：SHA512("SM1TAG" ‖ k_mac ‖ 密文 ‖ hwid48)[..10]。"""
    return sha512(b"SM1TAG" + key + ciphertext + hwid48(hwid)).digest()[:TAG_LEN]


def encode_key(data: bytes) -> str:
    """38 字节 → 48 位混合字符密钥（混合进位制，12 组循环）。"""
    assert len(data) == DATA_BYTES
    v = int.from_bytes(data, "little")
    cycles = []
    for _ in range(CYCLES):
        v, cv = divmod(v, RADIX)
        cycles.append(cv)
    cycles.reverse()  # cycles[0] 为最高有效组
    chars = []
    for cv in cycles:
        dv = cv % 10
        lv = (cv // 10) % 52
        sv = (cv // (10 * 52)) % 32
        hv = cv // (10 * 52 * 32)
        chars.append(DIGITS[dv])
        chars.append(LETTERS[lv])
        chars.append(SYMBOLS[sv])
        chars.append(chr(HANZI_BASE + hv))
    return "".join(chars)


def decode_key(text: str):
    """48 位混合字符密钥 → 38 字节。失败返回错误信息（指定位号）。"""
    chars = list(text.strip())
    if len(chars) != KEY_LEN:
        return None, (
            f"密钥位数不正确：应为 {KEY_LEN} 位（数字/字母/符号/汉字交替），"
            f"实为 {len(chars)} 位"
        )
    v = 0
    for c in range(CYCLES):
        parts = []
        for k, table in ((0, DIGITS), (1, LETTERS), (2, SYMBOLS)):
            ch = chars[c * CLASSES + k]
            idx = table.find(ch)
            if idx < 0:
                return None, (
                    f"第 {c * CLASSES + k + 1} 位应为"
                    f"{['数字', '英文字母', '符号', '汉字'][k]}："
                    f"收到「{ch}」不在字符表内（请检查是否抄错）"
                )
            parts.append(idx)
        cp = ord(chars[c * CLASSES + 3])
        if not (HANZI_BASE <= cp < HANZI_BASE + HANZI_COUNT):
            return None, (
                f"第 {c * CLASSES + 4} 位应为汉字："
                f"收到「{chars[c * CLASSES + 3]}」不在字符表内（请检查是否抄错）"
            )
        parts.append(cp - HANZI_BASE)
        cv = parts[0] + 10 * (parts[1] + 52 * (parts[2] + 32 * parts[3]))
        v = v * RADIX + cv
    if v >= (1 << (DATA_BYTES * 8)):
        return None, "密钥内容超出有效范围（格式校验失败）"
    return v.to_bytes(DATA_BYTES, "little"), None


def day_to_ymd(day: int):
    """Unix 天 → (年, 月, 日)（Howard Hinnant 算法，与 Rust 端一致）。"""
    z = day + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return (y + 1 if m <= 2 else y, m, d)


def today_day(now_secs: int) -> int:
    return now_secs // 86400


def pack_plain(p: dict, hwid: str) -> bytes:
    """KeyParams → 26 字节明文（布局与 keyfmt.rs 一致）。"""
    b = bytearray(PLAIN_LEN)
    b[0] = PLAIN_MAGIC
    b[1] = (FORMAT_VERSION << 4) | (p["kind"] & 0x0F)
    b[2:8] = hwid48(hwid)
    b[8:12] = p["valid_from_day"].to_bytes(4, "big")
    b[12:16] = p["valid_until_day"].to_bytes(4, "big")
    b[16:19] = p["usage_seconds_limit"].to_bytes(4, "big")[1:]
    b[19:21] = p["usage_count_limit"].to_bytes(2, "big")
    b[21:23] = p["feature_flags"].to_bytes(2, "big")
    b[23:26] = (p["key_id"] & 0xFFFFFF).to_bytes(4, "big")[1:]
    return bytes(b)


def unpack_plain(b: bytes) -> dict:
    """26 字节明文 → KeyParams（不解时效，仅结构）。"""
    if b[0] != PLAIN_MAGIC:
        raise ValueError("密钥内容无法识别（魔数不符）")
    fmt = b[1] >> 4
    if fmt != FORMAT_VERSION:
        raise ValueError(f"密钥格式版本不受支持：v{fmt}")
    kind = b[1] & 0x0F
    if kind not in KIND_NAME_BY_ID:
        raise ValueError("密钥授权类型无法识别")
    return {
        "kind": kind,
        "valid_from_day": int.from_bytes(b[8:12], "big"),
        "valid_until_day": int.from_bytes(b[12:16], "big"),
        "usage_seconds_limit": int.from_bytes(b[16:19], "big"),
        "usage_count_limit": int.from_bytes(b[19:21], "big"),
        "feature_flags": int.from_bytes(b[21:23], "big"),
        "key_id": int.from_bytes(b[23:26], "big"),
        "hwid48": b[2:8],
    }


def issue_key(secret: bytes, hwid: str, p: dict) -> str:
    """签发一枚 48 位密钥（与 keyfmt.rs::issue_key 一致）。"""
    assert len(secret) == 32
    plain = pack_plain(p, hwid)
    k_enc = _derive(b"SM1K1", secret, hwid)
    ks = _keystream(k_enc, PLAIN_LEN)
    cipher = bytes(a ^ b for a, b in zip(plain, ks))
    k_mac = _derive(b"SM1K2", secret, hwid)
    tag = _mac(k_mac, cipher, hwid)
    data = cipher + tag + _crc16(cipher + tag).to_bytes(2, "big")
    assert len(data) == DATA_BYTES
    return encode_key(data)


def open_key_with_secret(secret: bytes, text: str, hwid: str, now_secs: int):
    """解析并验证一枚密钥。返回 (KeyParams, None) 或 (None, 错误信息)。"""
    assert len(secret) == 32
    data, err = decode_key(text)
    if err:
        return None, err
    cipher, tag = data[:PLAIN_LEN], data[PLAIN_LEN : PLAIN_LEN + TAG_LEN]
    crc_stored = int.from_bytes(data[PLAIN_LEN + TAG_LEN :], "big")
    if crc_stored != _crc16(data[: PLAIN_LEN + TAG_LEN]):
        return None, "密钥校验位不符：可能抄录有误（请核对每一位字符）"
    k_mac = _derive(b"SM1K2", secret, hwid)
    if _mac(k_mac, cipher, hwid) != tag:
        return None, "密钥验签未通过：密钥可能被篡改，或不是由本产品签发体系签发的"
    k_enc = _derive(b"SM1K1", secret, hwid)
    ks = _keystream(k_enc, PLAIN_LEN)
    plain = bytes(a ^ b for a, b in zip(cipher, ks))
    try:
        p = unpack_plain(plain)
    except ValueError as e:
        return None, str(e)
    today = today_day(now_secs)
    if p["valid_from_day"] > 0 and today < p["valid_from_day"]:
        y, m, d = day_to_ymd(p["valid_from_day"])
        return None, f"密钥尚未生效（生效日期：{y:04d}-{m:02d}-{d:02d}）"
    if p["valid_until_day"] != DAY_PERPETUAL and today > p["valid_until_day"]:
        y, m, d = day_to_ymd(p["valid_until_day"])
        return None, f"密钥已过期（有效期至：{y:04d}-{m:02d}-{d:02d}）"
    return p, None


def _load_secret(path: str) -> bytes:
    with open(path) as f:
        s = bytes.fromhex(f.read().strip())
    if len(s) != 32:
        sys.stderr.write(f"主密钥长度应为 32 字节，实为 {len(s)}\n")
        sys.exit(1)
    return s


def _parse_features(spec: str) -> int:
    flags = 0
    for name in spec.split(","):
        name = name.strip().lower()
        if not name:
            continue
        if name == "all":
            return sum(FEATURES.values())
        if name not in FEATURES:
            sys.stderr.write(
                f"未知功能位：{name}（可选：{','.join(sorted(FEATURES))},all）\n"
            )
            sys.exit(1)
        flags |= FEATURES[name]
    return flags


def _fmt_features(flags: int) -> str:
    names = [FEATURE_LABELS[n] for n, b in sorted(FEATURES.items(), key=lambda kv: kv[1]) if flags & b]
    return "、".join(names) if names else "（无）"


def _fmt_day(day: int) -> str:
    if day == DAY_PERPETUAL:
        return "永久"
    y, m, d = day_to_ymd(day)
    return f"{y:04d}-{m:02d}-{d:02d}"


def cmd_unlock_code(args):
    """打印排障解锁码（配合 --aim-allow-unlicensed 使用）。

    发行构建里 `--aim-allow-unlicensed` 必须同时提供这个码，否则拒绝启动。
    码由主密钥派生，与 48 位密钥同一保管级别：**只给内部运维，不外发**。
    """
    secret = _load_secret(args.secret)
    k = _derive(b"SM1ULK", secret, "")
    tag = _mac(k, b"unlicensed-gate", "")
    print(tag[:8].hex())


def cmd_keygen_secret(args):
    out = args.out
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "aim.secret")
    if os.path.exists(path) and not args.force:
        sys.stderr.write(
            f"主密钥已存在：{path}\n"
            "若确实要重新生成（**会使已签发的所有 48 位密钥失效**），加 --force。\n"
        )
        sys.exit(1)
    s = secrets.token_bytes(32)
    with open(path, "w") as f:
        f.write(s.hex())
    os.chmod(path, 0o600)
    print(f"主密钥 → {path}  (权限 600，与 issuer.key 同一保管级别)")
    print()
    print("构建发行包时 build.rs 会自动读取它并掩码注入二进制；")
    print("源码包与发行包中均不出现明文。切勿提交到版本库或随包分发。")


def cmd_issue_key(args):
    secret = _load_secret(args.secret)
    if args.kind not in KIND_BY_NAME:
        sys.stderr.write(
            f"kind 只能是 {'/'.join(KIND_BY_NAME)}\n"
        )
        sys.exit(1)
    features = _parse_features(args.features)
    if not 0 <= args.uses <= 0xFFFF:
        sys.stderr.write("--uses 应在 0..65535（0 = 不限）\n")
        sys.exit(1)
    if not 0 <= args.seconds <= 0xFFFFFFFF:
        sys.stderr.write("--seconds 应在 0..4294967295（0 = 不限）\n")
        sys.exit(1)

    now = int(time.time())
    today = today_day(now)
    valid_from = today + max(0, args.from_days)
    valid_until = DAY_PERPETUAL if args.days <= 0 else today + args.days

    for i in range(max(1, args.count)):
        key_id = args.key_id if args.key_id is not None else secrets.randbits(24)
        p = {
            "kind": KIND_BY_NAME[args.kind],
            "valid_from_day": valid_from,
            "valid_until_day": valid_until,
            "usage_seconds_limit": args.seconds,
            "usage_count_limit": args.uses,
            "feature_flags": features,
            "key_id": key_id & 0xFFFFFF,
        }
        text = issue_key(secret, args.hwid, p)
        print(f"── 密钥 {i + 1}{f'/{args.count}' if args.count > 1 else ''}（编号 {key_id & 0xFFFFFF}）")
        print(text)
        if args.out and args.count == 1:
            with open(args.out, "w") as f:
                f.write(text + "\n")
            os.chmod(args.out, 0o600)
    if args.count > 1:
        print(f"（已签发 {args.count} 枚，编号随机；逐行复制发给用户）")
    print()
    print(f"  机器指纹 : {args.hwid}")
    print(f"  类型     : {args.kind}（{KIND_LABELS[args.kind]}）")
    print(f"  有效期   : {_fmt_day(valid_from)} → {_fmt_day(valid_until)}")
    print(f"  次数上限 : {'不限' if args.uses == 0 else args.uses}")
    print(f"  时长上限 : {'不限' if args.seconds == 0 else f'{args.seconds} 秒（约 {args.seconds // 3600} 小时）'}")
    print(f"  功能     : {_fmt_features(features)}")
    if args.out and args.count == 1:
        print(f"\n已写入 {args.out}（权限 600）。用户在客户端「诊断/授权」页粘贴激活。")


def cmd_verify_key(args):
    secret = _load_secret(args.secret)
    p, err = open_key_with_secret(secret, args.key, args.hwid, int(time.time()))
    if err:
        print(f"❌ {err}")
        sys.exit(1)
    print("✅ 密钥有效。")
    print(f"  类型     : {KIND_NAME_BY_ID[p['kind']]}（{KIND_LABELS[KIND_NAME_BY_ID[p['kind']]]}）")
    print(f"  编号     : {p['key_id']}")
    print(f"  有效期   : {_fmt_day(p['valid_from_day'])} → {_fmt_day(p['valid_until_day'])}")
    print(f"  次数上限 : {'不限' if p['usage_count_limit'] == 0 else p['usage_count_limit']}")
    secs_limit = p["usage_seconds_limit"]
    print(f"  时长上限 : {'不限' if secs_limit == 0 else f'{secs_limit} 秒（约 {secs_limit // 3600} 小时）'}")
    print(f"  功能     : {_fmt_features(p['feature_flags'])}")
    embedded = p["hwid48"].hex()
    expected = hwid48(args.hwid).hex()
    print(f"  绑定指纹 : {embedded}（本机 {expected}）{'一致' if embedded == expected else '不一致'}")


def main():
    ap = argparse.ArgumentParser(
        description="授权签发工具（Ed25519 离线许可 + 48 位激活密钥）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("keygen", help="生成 Ed25519 密钥对")
    p1.add_argument("--out", default="./keys", help="输出目录（默认 ./keys）")
    p1.add_argument("--force", action="store_true", help="覆盖已存在的私钥")
    p1.set_defaults(func=cmd_keygen)

    p2 = sub.add_parser("issue", help="签发 Ed25519 离线许可")
    p2.add_argument("--key", required=True, help="私钥文件路径")
    p2.add_argument("--hwid", required=True, help="目标机器指纹")
    p2.add_argument("--days", type=int, default=365, help="有效天数（<=0 表示永久）")
    p2.add_argument("--kind", default="persistent", help="persistent | temporary")
    p2.add_argument("--out", default="license.lic", help="输出文件")
    p2.set_defaults(func=cmd_issue)

    p3 = sub.add_parser("verify", help="校验 Ed25519 离线许可（自检）")
    p3.add_argument("--pub", required=True, help="公钥文件路径")
    p3.add_argument("--file", required=True, help="许可文件路径")
    p3.set_defaults(func=cmd_verify)

    p4 = sub.add_parser(
        "keygen-secret", help="生成 48 位密钥的主密钥（keys/aim.secret）"
    )
    p4.add_argument("--out", default="./keys", help="输出目录（默认 ./keys）")
    p4.add_argument("--force", action="store_true", help="覆盖已存在的主密钥")
    p4.set_defaults(func=cmd_keygen_secret)

    p5 = sub.add_parser("issue-key", help="签发 48 位激活密钥")
    p5.add_argument("--secret", required=True, help="主密钥文件（keys/aim.secret）")
    p5.add_argument("--hwid", required=True, help="目标机器指纹（客户端诊断页可查）")
    p5.add_argument("--days", type=int, default=365, help="有效天数（<=0 表示永久）")
    p5.add_argument(
        "--from-days",
        type=int,
        default=0,
        dest="from_days",
        help="多少天后生效（默认 0 = 立即生效）",
    )
    p5.add_argument(
        "--kind",
        default="pro",
        help="授权类型：trial/standard/pro/edu/demo（默认 pro）",
    )
    p5.add_argument("--uses", type=int, default=0, help="使用次数上限（0 = 不限）")
    p5.add_argument(
        "--seconds", type=int, default=0, help="累计使用时长上限，秒（0 = 不限）"
    )
    p5.add_argument(
        "--features",
        default="all",
        help="功能位，逗号分隔：basic,export,smart,schedule,print,multi,all",
    )
    p5.add_argument(
        "--key-id",
        type=lambda x: int(x, 0),
        default=None,
        dest="key_id",
        help="密钥编号（24 位；缺省随机，便于事后追溯批次）",
    )
    p5.add_argument("--count", type=int, default=1, help="一次签发多枚（批量发售）")
    p5.add_argument("--out", default=None, help="单枚时输出到文件（权限 600）")
    p5.set_defaults(func=cmd_issue_key)

    p6 = sub.add_parser("verify-key", help="校验 48 位激活密钥（自检）")
    p6.add_argument("--secret", required=True, help="主密钥文件（keys/aim.secret）")
    p6.add_argument("--hwid", required=True, help="目标机器指纹")
    p6.add_argument("--key", required=True, help="48 位密钥文本")
    p6.set_defaults(func=cmd_verify_key)

    p7 = sub.add_parser(
        "unlock-code", help="打印排障解锁码（配合 --aim-allow-unlicensed）"
    )
    p7.add_argument("--secret", required=True, help="主密钥文件（keys/aim.secret）")
    p7.set_defaults(func=cmd_unlock_code)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
