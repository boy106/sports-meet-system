#!/usr/bin/env bash
# ===========================================================================
# 开源版一键发版脚本（v1.9.13 起）
#
# 流程：改版本号 → 跑测试 → 提交 → 打 tag → 创建 Release → 推送
# Windows / Linux 双平台二进制由 .github/workflows/release.yml 在云端自动
# 交叉编译并挂到 Release 上（无需本机装 mingw-w64）。
#
# 用法：
#   bash release.sh 1.9.13 "修复了成绩录入的若干问题"
#
# 前置：gh CLI 已登录（gh auth login，需 repo 权限），cargo 可用，工作树干净。
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

NEW_VER="${1:?用法: bash release.sh <版本号，如 1.9.13> [更新说明]}"
NOTES="${2:-版本 ${NEW_VER} 更新}"
TAG="v${NEW_VER}"
OWNER="boy106"
REPO="sports-meet-system"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || die "需要 Rust / cargo"
command -v gh >/dev/null 2>&1 || die "需要 GitHub CLI（gh）"
[ -z "$(git status --porcelain)" ] || die "工作树不干净，请先提交或暂存本地改动"
gh auth status >/dev/null 2>&1 || die "GitHub 未登录：请先 gh auth login"

OLD_VER=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')
say "版本升级：${OLD_VER} -> ${NEW_VER}"

# ---- 1. 同步版本号 ----------------------------------------------------------
say "同步版本号到 Cargo.toml / main.rs / 前端 ..."
sed -i -E "0,/^version = /s/^version = \"[^\"]+\"/version = \"${NEW_VER}\"/" Cargo.toml
sed -i -E "s/const VERSION: &str = \"v[^\"]+\"/const VERSION: \&str = \"v${NEW_VER}\"/" src/main.rs
sed -i -E "s/(id=\"start-ver\">)v[0-9.]+/\1v${NEW_VER}/g" web/index.html
sed -i -E "s/(id=\"about-ver\">Version )[0-9.]+/\1${NEW_VER}/g" web/index.html
sed -i -E "s/(id=\"side-ver\">)v[0-9.]+/\1v${NEW_VER}/g" web/index.html

# ---- 2. 测试 ----------------------------------------------------------------
say "运行测试 ..."
cargo test --all-targets

# ---- 3. 提交并打 tag --------------------------------------------------------
say "提交版本号改动并打 tag ${TAG} ..."
git add Cargo.toml Cargo.lock src/main.rs web/index.html
git commit -m "chore: 发布 ${TAG}"
git tag -a "$TAG" -m "Release ${TAG}"

# ---- 4. 先创建 Release（带说明），Actions 随后上传双平台二进制 ---------------
say "创建 GitHub Release ${TAG} ..."
if gh release view "$TAG" >/dev/null 2>&1; then
  say "Release ${TAG} 已存在，跳过创建（Actions 仍会补传二进制）"
else
  gh release create "$TAG" --title "$TAG" --notes "$NOTES"
fi

# ---- 5. 推送（tag 推送会触发 release.yml 云端编译）-------------------------
say "推送提交与 tag 到 GitHub（触发云端双平台编译）..."
git push origin HEAD
git push origin "$TAG"

say "完成！Release 地址：https://github.com/${OWNER}/${REPO}/releases/tag/${TAG}"
say "稍等几分钟，GitHub Actions 会自动上传 Windows 与 Linux 二进制。"
