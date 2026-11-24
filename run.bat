@echo off
rem Offline permission proof - native Windows / Python 3.12 / stdlib only.
chcp 65001 >nul
cd /d "%~dp0"
python run.py
exit /b %ERRORLEVEL%
