@echo off
setlocal enabledelayedexpansion

:: Unkn0wnC2 Build Script for Windows
:: Builds all components for deployment

echo === Unkn0wnC2 Build System ===
echo.

:: Check if Go is installed
go version >nul 2>&1
if !errorlevel! neq 0 (
    echo Error: Go is not installed or not in PATH
    exit /b 1
)

echo Go version:
go version
echo.

:: Check if build_config.json exists
if not exist "build_config.json" (
    echo Error: build_config.json not found in current directory
    echo Make sure you're running this from the project root
    exit /b 1
)

:: Build the build tool first
echo Building build tool...
cd tools\builder
go build -o ..\..\build-tool.exe .
cd ..\..

if not exist "build-tool.exe" (
    echo Error: Failed to build build tool
    exit /b 1
)

echo ✓ Build tool created successfully
echo.

:: Run the build tool
echo Running build process...
build-tool.exe

echo.
echo === Build Complete ===

:: Show build contents
if exist "build\" (
    echo.
    echo Build output:
    dir build\ /b
    echo.
    
    :: Show deployment info if it exists
    if exist "build\deployment_info.json" (
        echo Deployment information:
        type build\deployment_info.json | more +1
        echo.
    )
    
    echo Build artifacts are ready in the 'build' directory
) else (
    echo Warning: Build directory not found
)

:: Clean up build tool
if exist "build-tool.exe" (
    del build-tool.exe
)

echo Done!
pause