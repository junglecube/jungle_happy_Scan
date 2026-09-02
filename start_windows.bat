@echo off
setlocal
cd /d "%~dp0"
set "HAPPYSCAN_EXE=%~dp0jungle_happy_Scan-windows-amd64.exe"
if exist "%~dp0jungle_happy_Scan-windows-arm64.exe" set "HAPPYSCAN_EXE=%~dp0jungle_happy_Scan-windows-arm64.exe"
if not exist "%HAPPYSCAN_EXE%" (
  echo HappyScan executable was not found.
  pause
  exit /b 1
)
echo Starting jungle_happy_Scan...
echo Web UI: http://127.0.0.1:8888
echo Press Ctrl+C to stop.
echo.
"%HAPPYSCAN_EXE%" -listen 127.0.0.1:8888
echo.
echo jungle_happy_Scan has stopped.
pause
