@echo off
setlocal enableextensions
cd /d "%~dp0"

rem ������Թ���Ա���ִ�д��ļ�
rem ���·������ﰴ����Ҫ�������������Ķ˿�·�ɹ���

PhantomHost ^
    80=127.0.0.1:8080 ^
    22=127.0.0.1:22 ^
    --domain myghost.iwm.name
    

SET ERROR=%ERRORLEVEL%
if %ERROR% EQU 2 echo ���Թ���Ա���ִ�д��ļ�
if %ERROR% NEQ 0 pause
