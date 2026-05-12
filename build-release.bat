@echo off
REM ============================================================================
REM build-release.bat
REM   Configures and builds NetLens as Release x64.
REM   Requires: CMake 3.20+, Visual Studio 2022 Build Tools (or full IDE).
REM ============================================================================
setlocal EnableExtensions EnableDelayedExpansion

set ROOT=%~dp0
set BUILD=%ROOT%build

echo.
echo [NetLens] Configuring CMake (Release x64)...
cmake -S "%ROOT%" -B "%BUILD%" -A x64
if errorlevel 1 (
    echo.
    echo [NetLens] CMake configuration FAILED.
    exit /b 1
)

echo.
echo [NetLens] Building...
cmake --build "%BUILD%" --config Release --parallel
if errorlevel 1 (
    echo.
    echo [NetLens] Build FAILED.
    exit /b 1
)

echo.
echo [NetLens] Build complete.
echo Executable: %BUILD%\Release\NetLens.exe
exit /b 0
