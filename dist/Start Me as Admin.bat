@echo off
setlocal enableextensions
cd /d "%~dp0"

PhantomHost 445=gzhxy-waimai-dcloud48.gzhxy.iwm.name:8010 --domain orion.name

SET ERROR=%ERRORLEVEL%
if %ERROR% EQU 2 echo Please Run as Administrator
if %ERROR% NEQ 0 pause
