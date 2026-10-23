@echo off
rem Geciti baslatir. Bu pencere acik kaldigi surece engeller asilir; kapatinca her sey eski haline doner.
title Gecit
cd /d "%~dp0"
python gecit.py %*
pause
