@echo off
setlocal enableextensions
cd /d "%~dp0"

PhantomHost 445=127.0.0.1:8445 --host aq.host

SET ERROR=%ERRORLEVEL%
if %ERROR% EQU 2 echo ���Թ���Ա���ִ�д��ļ�
if %ERROR% NEQ 0 pause
