@echo off
REM Docker Startup Script for WAF Application (Windows)
REM This script builds and starts all services using Docker Compose

setlocal enabledelayedexpansion

echo ===================================
echo WAF Docker Startup Script
echo ===================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not in PATH
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

echo [+] Docker is installed
docker --version
echo.

REM Check if Docker daemon is running
docker ps >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker daemon is not running
    echo Please start Docker Desktop
    pause
    exit /b 1
)

echo [+] Docker daemon is running
echo.

REM Set compose file
set COMPOSE_FILE=docker-compose-new.yml

echo [*] Using compose file: %COMPOSE_FILE%
echo.

REM Menu
echo Select an option:
echo 1) Start services (build + up)
echo 2) Start services (no rebuild)
echo 3) Stop services
echo 4) View logs
echo 5) Remove services and volumes
echo 6) View service status
echo 7) Exit
echo.

set /p choice="Enter your choice (1-7): "

if "%choice%"=="1" (
    echo.
    echo [*] Building and starting services...
    docker-compose -f %COMPOSE_FILE% up --build
    goto end
)

if "%choice%"=="2" (
    echo.
    echo [*] Starting services...
    docker-compose -f %COMPOSE_FILE% up
    goto end
)

if "%choice%"=="3" (
    echo.
    echo [*] Stopping services...
    docker-compose -f %COMPOSE_FILE% down
    echo [+] Services stopped
    goto end
)

if "%choice%"=="4" (
    echo.
    echo [*] Viewing logs (Ctrl+C to exit)...
    docker-compose -f %COMPOSE_FILE% logs -f
    goto end
)

if "%choice%"=="5" (
    echo.
    echo [!] This will remove all containers and volumes
    set /p confirm="Continue? (y/n): "
    if /i "%confirm%"=="y" (
        echo [*] Removing services and volumes...
        docker-compose -f %COMPOSE_FILE% down -v
        echo [+] Services and volumes removed
    )
    goto end
)

if "%choice%"=="6" (
    echo.
    echo [*] Service status:
    docker-compose -f %COMPOSE_FILE% ps
    goto end
)

if "%choice%"=="7" (
    goto end
)

echo Invalid choice
pause

:end
endlocal
