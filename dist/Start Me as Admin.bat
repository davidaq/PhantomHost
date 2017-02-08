@echo off
setlocal enableextensions
cd /d "%~dp0"

PhantomHost 445=127.0.0.1:8445 --host aq.host

SET ERROR=%ERRORLEVEL%
if %ERROR% EQU 2 echo 请以管理员身份执行此文件
if %ERROR% NEQ 0 pause
