#!/usr/bin/env bash
# 一键开源脚本：将本项目推送到 boy106/sports-meet-system（公开仓库）
# 用法：在本项目目录执行  bash push-to-github.sh
set -euo pipefail

OWNER="boy106"
REPO="sports-meet-system"
DESC="同和中学校运会积分系统 - Rust 单文件开源版 v1.9.10 (MIT)"

echo "==> 检查 GitHub CLI 登录状态"
if ! gh auth status >/dev/null 2>&1; then
  echo "尚未登录，请先执行：gh auth login"
  echo "（按提示选择 GitHub.com -> HTTPS -> 用浏览器登录，需勾选 repo 权限）"
  exit 1
fi

echo "==> 检查仓库是否已存在"
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  echo "仓库 $OWNER/$REPO 已存在，将直接推送"
else
  echo "创建公开仓库 $OWNER/$REPO ..."
  gh repo create "$OWNER/$REPO" --public --description "$DESC"
fi

echo "==> 配置 remote 并推送"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$OWNER/$REPO.git"
git branch -M main
git push -u origin main

echo "==> 完成：https://github.com/$OWNER/$REPO"
