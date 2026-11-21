@echo off
rem SmartShark developer environment for Windows.
rem Sets up MSVC (x64) and the paths the Wireshark build needs.
rem Override any of these by setting them before calling this script.

if not defined SMARTSHARK_DEV set "SMARTSHARK_DEV=D:\SmartShark-dev"
if not defined SMARTSHARK_QT  set "SMARTSHARK_QT=%SMARTSHARK_DEV%\Qt\6.9.3\msvc2022_64"
if not defined SMARTSHARK_WS_SRC   set "SMARTSHARK_WS_SRC=%SMARTSHARK_DEV%\wireshark"
if not defined SMARTSHARK_WS_BUILD set "SMARTSHARK_WS_BUILD=%SMARTSHARK_DEV%\build"
if not defined SMARTSHARK_VCVARS set "SMARTSHARK_VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

set "WIRESHARK_BASE_DIR=%SMARTSHARK_DEV%\wslibs"
set "WIRESHARK_QT6_PREFIX_PATH=%SMARTSHARK_QT%"

rem Git Bash sets MSYSTEM. Wireshark's CMake then assumes an MSYS2 build and
rem skips downloading its Windows libraries, so clear it.
set "MSYSTEM="
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"

rem WinFlexBison (portable) generates Wireshark's display filter parser.
if not defined SMARTSHARK_WINFLEXBISON set "SMARTSHARK_WINFLEXBISON=%SMARTSHARK_DEV%\tools\winflexbison"
set "PATH=%SMARTSHARK_WINFLEXBISON%;%PATH%"

rem Keep build temp files off the system drive.
if not exist "%SMARTSHARK_DEV%\tmp" mkdir "%SMARTSHARK_DEV%\tmp"
set "TEMP=%SMARTSHARK_DEV%\tmp"
set "TMP=%SMARTSHARK_DEV%\tmp"

call "%SMARTSHARK_VCVARS%" >nul || (echo vcvars64.bat failed & exit /b 1)
