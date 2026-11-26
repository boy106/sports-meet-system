#!/usr/bin/env bash
# ===========================================================================
# 开源版一键发版脚本（v1.9.11）
#
# 作用：把「改版本号 → 编译 → 打 tag → 创建 GitHub Release → 上传二进制」
#       串成一条命令，配合前端的「检查更新」机制形成闭环。
#
# 用法：
#   bash release.sh 1.9.12 "修复了成绩录入的若干问题"
#
# 前置条件：
#   - 已安装 gh CLI 并登录（gh auth login，需 repo 权限）
#     或已设置 GITHUB_TOKEN 环境变量
#   - 已安装 Rust 1.70+（cargo）
#   - 工作树干净（git status 无未提交改动）
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

NEW_VER="${1:?用法: bash release.sh <版本号，如 1.9.12> [更新说明]}"
NOTES="${2:-版本 ${NEW_VER} 更新}"
TAG="v${NEW_VER}"
OWNER="boy106"
REPO="sports-meet-system"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 前置检查 --------------------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "需要 Rust / cargo"
command -v gh >/dev/null 2>&1 || die "需要 GitHub CLI（gh），或改用 GITHUB_TOKEN + 手动创建 Release"
[ -z "$(git status --porcelain)" ] || die "工作树不干净，请先提交或暂存本地改动"

if [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="$GITHUB_TOKEN"
fi
gh auth status >/dev/null 2>&1 || die "GitHub 未登录：请先 gh auth login，或设置 GITHUB_TOKEN"

OLD_VER=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')
say "版本升级：${OLD_VER} -> ${NEW_VER}"

# ---- 1. 同步所有版本号 ------------------------------------------------------
say "同步版本号到 Cargo.toml / main.rs / 前端 ..."
sed -i -E "0,/^version = /s/^version = \"[^\"]+\"/version = \"${NEW_VER}\"/" Cargo.toml
sed -i -E "s/const VERSION: &str = \"v[^\"]+\"/const VERSION: \&str = \"v${NEW_VER}\"/" src/main.rs
# 前端有 3 处静态版本文本（会被 /api/meta 动态覆盖，但首屏与离线时用到）
sed -i -E "s/(id=\"start-ver\">)v[0-9.]+/\1v${NEW_VER}/g" web/index.html
sed -i -E "s/(id=\"about-ver\">Version )[0-9.]+/\1${NEW_VER}/g" web/index.html
sed -i -E "s/(id=\"side-ver\">)v[0-9.]+/\1v${NEW_VER}/g" web/index.html

# ---- 2. 测试 ----------------------------------------------------------------
say "运行测试 ..."
cargo test --all-targets

# ---- 3. 编译发行二进制 ------------------------------------------------------
say "编译 release 二进制 ..."
cargo build --release
BIN="target/release/sports-meet"
[ -f "$BIN" ] || die "未找到构建产物 $BIN"

# ---- 4. 提交并打 tag --------------------------------------------------------
say "提交版本号改动并打 tag ${TAG} ..."
git add Cargo.toml Cargo.lock src/main.rs web/index.html
git commit -m "chore: 发布 ${TAG}"
git tag -a "$TAG" -m "Release ${TAG}"

# ---- 5. 创建 Release 并上传二进制 ------------------------------------------
say "创建 GitHub Release ${TAG} ..."
if gh release view "$TAG" >/dev/null 2>&1; then
  die "Release ${TAG} 已存在，请先删除（gh release delete ${TAG}）"
fi
gh release create "$TAG" "$BIN#sports-meet (Linux x86_64)" \
  --title "$TAG" \
  --notes "$NOTES"

# ---- 6. 推送 ----------------------------------------------------------------
say "推送提交与 tag 到 GitHub ..."
git push origin HEAD
git push origin "$TAG"

say "完成！Release 地址：https://github.com/${OWNER}/${REPO}/releases/tag/${TAG}"
say "提醒：前端会在下次启动时检测到新版本并提示用户。"
