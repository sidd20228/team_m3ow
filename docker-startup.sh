#!/bin/bash

# Docker Startup Script for WAF Application (Linux/Mac)
# This script builds and starts all services using Docker Compose

set -e

COMPOSE_FILE="docker-compose-new.yml"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "==================================="
echo "WAF Docker Startup Script"
echo "==================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: Docker is not installed${NC}"
    echo "Please install Docker from https://www.docker.com/get-started"
    exit 1
fi

echo -e "${GREEN}[+] Docker is installed${NC}"
docker --version
echo ""

# Check if Docker daemon is running
if ! docker ps &> /dev/null; then
    echo -e "${RED}ERROR: Docker daemon is not running${NC}"
    echo "Please start Docker"
    exit 1
fi

echo -e "${GREEN}[+] Docker daemon is running${NC}"
echo ""

echo "[*] Using compose file: $COMPOSE_FILE"
echo ""

# Menu
echo "Select an option:"
echo "1) Start services (build + up)"
echo "2) Start services (no rebuild)"
echo "3) Stop services"
echo "4) View logs"
echo "5) Remove services and volumes"
echo "6) View service status"
echo "7) Exit"
echo ""

read -p "Enter your choice (1-7): " choice

case $choice in
    1)
        echo ""
        echo "[*] Building and starting services..."
        docker-compose -f "$COMPOSE_FILE" up --build
        ;;
    2)
        echo ""
        echo "[*] Starting services..."
        docker-compose -f "$COMPOSE_FILE" up
        ;;
    3)
        echo ""
        echo "[*] Stopping services..."
        docker-compose -f "$COMPOSE_FILE" down
        echo -e "${GREEN}[+] Services stopped${NC}"
        ;;
    4)
        echo ""
        echo "[*] Viewing logs (Ctrl+C to exit)..."
        docker-compose -f "$COMPOSE_FILE" logs -f
        ;;
    5)
        echo ""
        echo -e "${YELLOW}[!] This will remove all containers and volumes${NC}"
        read -p "Continue? (y/n): " confirm
        if [[ $confirm == [yY] ]]; then
            echo "[*] Removing services and volumes..."
            docker-compose -f "$COMPOSE_FILE" down -v
            echo -e "${GREEN}[+] Services and volumes removed${NC}"
        fi
        ;;
    6)
        echo ""
        echo "[*] Service status:"
        docker-compose -f "$COMPOSE_FILE" ps
        ;;
    7)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac
