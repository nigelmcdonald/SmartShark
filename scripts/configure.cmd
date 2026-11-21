@echo off
rem Configure the Wireshark source build with SmartShark linked in as a plugin.
rem Run once, or again after changing plugin/CMakeLists.txt.
setlocal
call "%~dp0dev-env.cmd" || exit /b 1

rem Link plugin/ into the Wireshark tree. CMake's add_subdirectory needs the
rem plugin inside the source tree, and a junction needs no admin rights.
set "PLUGIN_JUNCTION=%SMARTSHARK_WS_SRC%\plugins\epan\smartshark"
if not exist "%PLUGIN_JUNCTION%" mklink /J "%PLUGIN_JUNCTION%" "%~dp0..\plugin" || exit /b 1

cmake -G Ninja -S "%SMARTSHARK_WS_SRC%" -B "%SMARTSHARK_WS_BUILD%" ^
  -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/smartshark ^
  -DBUILD_androiddump=OFF -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF ^
  -DBUILD_dpauxmon=OFF -DBUILD_randpktdump=OFF -DBUILD_wifidump=OFF ^
  -DBUILD_udpdump=OFF -DBUILD_sharkd=OFF -DBUILD_randpkt=OFF ^
  -DBUILD_dcerpcidl2wrs=OFF -DBUILD_mmdbresolve=OFF
