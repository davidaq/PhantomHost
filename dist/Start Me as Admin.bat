@echo off
setlocal enableextensions
cd /d "%~dp0"

rem 请务必以管理员身份执行此文件
rem 在下方命令里按照需要配置幽灵主机的端口路由规则

PhantomHost ^
    80=127.0.0.1:8080 ^
    22=127.0.0.1:22 ^
    --domain myghost.iwm.name
    

SET ERROR=%ERRORLEVEL%
if %ERROR% EQU 2 echo 请以管理员身份执行此文件
if %ERROR% NEQ 0 pause
