@echo off
rem Build and run the unit tests for plugin/core. Needs Qt only.
setlocal
call "%~dp0dev-env.cmd" || exit /b 1
set "TEST_BUILD=%SMARTSHARK_DEV%\build-tests"

cmake -G Ninja -S "%~dp0..\tests" -B "%TEST_BUILD%" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_PREFIX_PATH="%SMARTSHARK_QT%" >nul || exit /b 1
cmake --build "%TEST_BUILD%" || exit /b 1

rem Qt DLLs for the test executable.
set "PATH=%SMARTSHARK_QT%\bin;%PATH%"
ctest --test-dir "%TEST_BUILD%" --output-on-failure %*
