@echo off
chcp 65001 >nul
rem ============================================================
rem  同和中学校运会积分系统 v1.5 - 卸载脚本
rem  用法: uninstall.bat [安装目录]（默认 %LOCALAPPDATA%\SportsMeet）
rem  注意：卸载不会删除 data 数据目录，如需清空请手动删除。
rem ============================================================
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=%LOCALAPPDATA%\SportsMeet"

echo 将卸载 "%TARGET%"（数据目录 data 保留）。
set /p CONF=确认继续？(y/N):
if /i not "%CONF%"=="y" exit /b 0

del "%TARGET%\同和中学校运会积分系统.exe" 2>nul
rmdir /s /q "%TARGET%\web" 2>nul
del "%TARGET%\config.json" 2>nul
del "%LOCALAPPDATA%\..\Desktop\同和运动会积分系统.lnk" 2>nul
powershell -NoProfile -Command "Remove-Item -Path ([Environment]::GetFolderPath('Desktop') + '\同和运动会积分系统.lnk') -ErrorAction SilentlyContinue" >nul 2>&1
echo 卸载完成。数据保留在 "%TARGET%\data"。
pause
