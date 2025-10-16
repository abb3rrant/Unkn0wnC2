@echo off
setlocal

REM Build script for standalone DNS C2 client
REM This script embeds configuration at build time for a standalone executable

echo Building standalone DNS C2 client...

REM Check if build_config.json exists
if not exist "build_config.json" (
    echo ERROR: build_config.json not found!
    echo Please create build_config.json with your configuration.
    exit /b 1
)

REM Generate embedded config
echo Generating embedded configuration...
cd tools
go run generate_config.go
cd ..

REM Build the client
echo Compiling client...
go build -ldflags="-s -w" -o dns-client.exe .

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Build successful! 
    echo ✓ Standalone client: dns-client.exe
    echo ✓ Configuration embedded at build time
    echo.
    echo The client is now standalone and does not require external config files.
) else (
    echo.
    echo ✗ Build failed!
    exit /b 1
)

endlocal