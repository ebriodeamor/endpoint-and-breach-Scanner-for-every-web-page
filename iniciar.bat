@echo off
chcp 65001 >nul
title NadieScan v2.2
cd /d "%~dp0"
python nadie_scan.py --no-warp
pause
