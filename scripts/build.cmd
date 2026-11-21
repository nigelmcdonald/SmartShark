@echo off
rem Build SmartShark. The first run also builds the Wireshark libraries it links
rem against (slow, once). Pass "all" to build everything, including Wireshark.exe.
setlocal
call "%~dp0dev-env.cmd" || exit /b 1

if /i "%~1"=="all" (
  cmake --build "%SMARTSHARK_WS_BUILD%"
) else (
  cmake --build "%SMARTSHARK_WS_BUILD%" --target smartshark
)
