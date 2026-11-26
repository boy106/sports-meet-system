#!/usr/bin/env bash
# ===========================================================================
# 发行构建脚本（v1.9.0）
#
# 产出：dist/sports-meet —— **只含 Rust 版**（web 资源已 include_str! 内嵌，
# 无需随包分发任何文件；Python 版与 tools/ 一律不进发行包）。
#
# 两遍完整性盖章（手段 2）：
#   ① cargo build --release        BLOB 全零 → 基线模式
#   ② integrity_stamp.py           算期望值写 target/integrity_cache.bin
#   ③ touch build.rs && 再构建     嵌入真实期望值（掩码后内容不变 → 不动点）
#   ④ integrity_stamp.py --verify  复算三方比对，必须全部一致
#
# 前置条件（缺失时明确报错退出，不产出"看似正常"的发行包）：
#   keys/aim.secret   48 位密钥主密钥（tools/issue_license.py keygen-secret）
#   keys/issuer.pub   Ed25519 签发公钥（tools/issue_license.py keygen）
#   keys/devkey.fp    开发者密钥指纹（可选；缺失则发行版锁死开发者模式）
# 三者只在构建机上存在；源码包与发行包中均无明文。
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

BIN="target/release/sports-meet"
DIST="dist"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 前置检查 --------------------------------------------------------------
say "检查签发材料……"
missing=0
[ -f keys/aim.secret ] || { echo "  ✗ keys/aim.secret 缺失（48 位密钥校验将停用）"; missing=1; }
[ -f keys/issuer.pub ] || { echo "  ✗ keys/issuer.pub 缺失（离线许可校验将停用）"; missing=1; }
if [ "$missing" -ne 0 ]; then
    die "请先在构建机上执行：
    python3 tools/issue_license.py keygen-secret --out ./keys
    python3 tools/issue_license.py keygen --out ./keys
  （公钥/主密钥绝不可随包分发）"
fi
command -v python3 >/dev/null 2>&1 || die "需要 python3（盖章与校验步骤）"
echo "  ✓ keys/aim.secret / keys/issuer.pub 就绪"
# v1.9.1：开发者密钥指纹可选——缺失时发行版锁死开发者模式（不报错）
if [ -f keys/devkey.fp ]; then
    echo "  ✓ keys/devkey.fp 就绪（开发者模式按此指纹解锁）"
else
    say "注意：keys/devkey.fp 缺失 → 本发行版将锁死开发者模式（如需保留请参照 docs/12 §2.3）"
fi

# ---- ① 第一遍：基线构建 ----------------------------------------------------
say "第一遍发行构建（基线模式）……"
rm -f target/integrity_cache.bin   # 旧缓存会让第一遍就嵌入过期期望值
cargo build --release

# ---- ② 盖章 ----------------------------------------------------------------
say "计算完整性期望值并盖章……"
python3 tools/integrity_stamp.py --binary "$BIN"

# ---- ③ 第二遍：嵌入真实期望值 ----------------------------------------------
say "第二遍发行构建（嵌入期望值）……"
touch build.rs
cargo build --release

# ---- ④ 复算校验 -------------------------------------------------------------
say "复算比对（篡改任一字节都会在这里暴露）……"
python3 tools/integrity_stamp.py --binary "$BIN" --verify

# ---- 打包：只装 Rust 版 ------------------------------------------------------
say "打包发行目录 $DIST/ ……"
rm -rf "$DIST"
mkdir -p "$DIST"
cp "$BIN" "$DIST/sports-meet"
chmod 755 "$DIST/sports-meet"
# 使用说明随包（纯文本，无秘密）；tools/、keys/、源码一律不进
[ -f 使用说明.txt ] && cp 使用说明.txt "$DIST/使用说明.txt"

# 打包前最后一道确认：二进制必须已是"已盖章"状态
python3 - "$DIST/sports-meet" <<'PY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("stamp", "tools/integrity_stamp.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with open(sys.argv[1], "rb") as f:
    data = f.read()
pos, stamped = m.locate_blob(data)
assert pos is not None, "发行二进制缺少完整性数据区"
assert stamped, "发行二进制处于基线模式（未嵌入期望值）"
print(f"  ✓ 数据区位于偏移 {pos}，已盖章")
PY

say "完成：$DIST/sports-meet（$(du -h "$DIST/sports-meet" | cut -f1)）"
say "提醒：发行前请把 keys/ 从构建机妥善保管；dist/ 内不含任何秘密。"
