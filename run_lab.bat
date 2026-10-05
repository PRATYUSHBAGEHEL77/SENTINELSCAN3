@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONUTF8=1"
if not defined SENTINELSCAN_DATA set "SENTINELSCAN_DATA=%LOCALAPPDATA%\SentinelScan"
if not exist "%SENTINELSCAN_DATA%" mkdir "%SENTINELSCAN_DATA%" >nul 2>&1
where py >nul 2>&1
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
echo [SentinelScan] Starting controlled Assessment Lab on http://127.0.0.1:8100 ...
%PY% lab\vulnerable_app.py
pause
