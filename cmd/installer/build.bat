@echo off
REM Build the CertHound Windows installer.
REM Requires: Go, GCC (MinGW-w64)

cd /d "%~dp0"

echo Compiling resource file...
windres -o installer_res.syso installer.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: windres failed. Is MinGW-w64 in your PATH?
    exit /b 1
)

echo Building installer...
go build -ldflags="-H windowsgui" -o ..\..\dist\certhound-installer-windows-amd64.exe .
if %ERRORLEVEL% neq 0 (
    echo ERROR: go build failed.
    exit /b 1
)

echo Done: dist\certhound-installer-windows-amd64.exe
