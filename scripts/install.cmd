@echo off
rem Copy the built plugin into the current user's personal Wireshark plugin
rem folder. No admin rights needed. Restart Wireshark afterwards.
setlocal
if not defined SMARTSHARK_DEV set "SMARTSHARK_DEV=D:\SmartShark-dev"
if not defined SMARTSHARK_WS_BUILD set "SMARTSHARK_WS_BUILD=%SMARTSHARK_DEV%\build"

set "DLL="
for /r "%SMARTSHARK_WS_BUILD%\run" %%F in (smartshark.dll) do if exist "%%F" set "DLL=%%F"
if not defined DLL (echo smartshark.dll not found under %SMARTSHARK_WS_BUILD%\run. Run scripts\build.cmd first. & exit /b 1)

set "DEST=%APPDATA%\Wireshark\plugins\4.6\epan"
if not exist "%DEST%" mkdir "%DEST%"
copy /y "%DLL%" "%DEST%\" >nul || exit /b 1
echo Installed %DLL%
echo        to %DEST%
