@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0toggle.ps1" -Status
pause
