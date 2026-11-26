@echo off
chcp 65001 >nul
rem ============================================================
rem  同和中学校运会积分系统 v1.9.0 - Windows 安装脚本
rem  注意：v1.9.0 起发行包只含 Rust 版单二进制，Windows exe 需在
rem  构建机上交叉编译产出（见 README「Windows 交叉编译」一节），
rem  并放入 bin\ 目录后再运行本脚本。
rem  用法（参数控制）:
rem    install.bat                     安装到默认目录
rem    install.bat "D:\运动会系统"     安装到指定目录
rem    install.bat "D:\运动会系统" 8788  指定目录和服务端口
rem ============================================================
setlocal enabledelayedexpansion

set "SRC=%~dp0.."
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=%LOCALAPPDATA%\SportsMeet"
set "PORT=%~2"
if "%PORT%"=="" set "PORT=8765"

echo ============================================
echo   同和中学校运会积分系统 v1.9.0 安装程序
echo ============================================
echo  安装目录: %TARGET%
echo  服务端口: %PORT%
echo.

if not exist "%SRC%\bin\同和中学校运会积分系统.exe" (
  echo [错误] 未找到 bin\同和中学校运会积分系统.exe，请确认安装包完整。
  pause & exit /b 1
)

echo [1/4] 创建目录...
mkdir "%TARGET%" 2>nul
mkdir "%TARGET%\data" 2>nul

echo [2/4] 复制程序与网页...
copy /y "%SRC%\bin\同和中学校运会积分系统.exe" "%TARGET%\" >nul
xcopy /e /i /y "%SRC%\web" "%TARGET%\web" >nul

echo [3/4] 生成配置文件 config.json...
> "%TARGET%\config.json" (
  echo {
  echo   "port": %PORT%,
  echo   "dir":  "data",
  echo   "web":  "web"
  echo ^}
)
echo   配置说明：可直接编辑 config.json 修改端口/数据目录；
echo   命令行参数 --port 等优先级高于配置文件。

echo [4/4] 创建桌面快捷方式...
powershell -NoProfile -Command ^
 "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\同和运动会积分系统.lnk'); $s.TargetPath = '%TARGET%\同和中学校运会积分系统.exe'; $s.WorkingDirectory = '%TARGET%'; $s.Save()" >nul 2>&1
if %errorlevel%==0 (echo   桌面快捷方式已创建) else (echo   快捷方式创建失败，可手动运行 exe)

echo.
echo 安装完成！双击桌面快捷方式或运行：
echo   "%TARGET%\同和中学校运会积分系统.exe"
echo 浏览器访问: http://127.0.0.1:%PORT%
pause
