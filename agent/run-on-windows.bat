@echo off
setlocal EnableDelayedExpansion
title SideWire agent - close this window to stop
cd /d "%~dp0"

set "PORT=7900"
set "CFGDIR=%USERPROFILE%\.sidewire"
set "KEYFILE=%CFGDIR%\agent.key"

echo.
echo   SideWire agent
echo   ----------------------------------------------------------
echo   Close this window to stop it. Nothing is left running.
echo   ----------------------------------------------------------
echo.

rem ---- locate python ---------------------------------------------------
set "PY="
where python >nul 2>&1
if not errorlevel 1 set "PY=python"
if not defined PY (
  where py >nul 2>&1
  if not errorlevel 1 set "PY=py"
)
if not defined PY (
  echo   Python was not found on this machine.
  echo   Install Python 3.8 or newer, tick "Add to PATH", then run again.
  echo.
  pause
  exit /b 1
)

rem ---- find the Radmin address (26.x.x.x) ------------------------------
set "RADMIN_IP="
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /C:"IPv4"') do (
  set "CAND=%%A"
  set "CAND=!CAND: =!"
  if "!CAND:~0,3!"=="26." set "RADMIN_IP=!CAND!"
)

if not defined RADMIN_IP (
  echo   Radmin VPN does not have an address yet.
  echo.
  echo   Open Radmin VPN, join the network, wait until it shows an
  echo   address like 26.x.x.x, then run this file again.
  echo.
  echo   The agent deliberately listens only on the Radmin interface,
  echo   so closing Radmin really does cut the connection.
  echo.
  pause
  exit /b 1
)

echo   Radmin address : %RADMIN_IP%
echo   Port           : %PORT%

rem ---- shared key ------------------------------------------------------
if not exist "%CFGDIR%" mkdir "%CFGDIR%" >nul 2>&1
if not exist "%KEYFILE%" (
  %PY% sidewire_agentd.py --keygen --out "%KEYFILE%" >nul 2>&1
  echo   Key            : generated, saved to %KEYFILE%
)
set "KEY="
for /f "usebackq delims=" %%K in ("%KEYFILE%") do (
  if not defined KEY set "KEY=%%K"
)

echo.
echo   ----------------------------------------------------------
echo   On the machine you are operating FROM, run this once:
echo.
echo     python sw.py add far %RADMIN_IP% --key %KEY% --default
echo   ----------------------------------------------------------
echo.
echo   Listening on %RADMIN_IP% only. Closing this window stops it.
echo.

%PY% sidewire_agentd.py --bind %RADMIN_IP% --port %PORT% --key-file "%KEYFILE%" --allow-cidr 26.0.0.0/8 --allow-root "%SystemDrive%\\" --verbose

echo.
echo   Agent stopped. Nothing is listening now.
pause
