#!/bin/bash

# MyProxy Docker Deployment Script
# Supports both development testing and Pi production deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐳 MyProxy Docker Deployment${NC}"
echo "================================"

# Detect platform
PLATFORM=$(uname -m)
IS_PI=false

if [[ "$PLATFORM" == "aarch64" ]] || [[ "$PLATFORM" == "armv7l" ]]; then
    IS_PI=true
    echo -e "${GREEN}📍 Detected: Raspberry Pi ($PLATFORM)${NC}"
else
    echo -e "${YELLOW}📍 Detected: Development machine ($PLATFORM)${NC}"
fi

# Parse arguments
DEPLOYMENT_TYPE=""
FORCE_REBUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dev|--development)
            DEPLOYMENT_TYPE="development"
            shift
            ;;
        --pi|--production)
            DEPLOYMENT_TYPE="production"
            shift
            ;;
        --rebuild)
            FORCE_REBUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev, --development    Force development mode with network simulation"
            echo "  --pi, --production      Force Pi production mode"
            echo "  --rebuild               Force rebuild of Docker images"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Auto-detection:"
            echo "  - Pi hardware → Production mode"
            echo "  - Other hardware → Development mode"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Auto-detect deployment type if not specified
if [[ -z "$DEPLOYMENT_TYPE" ]]; then
    if [[ "$IS_PI" == true ]]; then
        DEPLOYMENT_TYPE="production"
    else
        DEPLOYMENT_TYPE="development"
    fi
fi

echo -e "${BLUE}🚀 Deployment type: $DEPLOYMENT_TYPE${NC}"

# Check prerequisites
echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not available${NC}"
    echo "Install Docker Compose or update Docker to a version with 'docker compose'"
    exit 1
fi

# Use docker compose or docker-compose based on availability
DOCKER_COMPOSE_CMD="docker-compose"
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
fi

echo -e "${GREEN}✅ Docker prerequisites met${NC}"

# Select compose file
COMPOSE_FILE=""
if [[ "$DEPLOYMENT_TYPE" == "production" ]]; then
    COMPOSE_FILE="docker-compose.pi.yml"
    echo -e "${GREEN}📋 Using Pi production configuration${NC}"
else
    COMPOSE_FILE="docker-compose.yml"
    echo -e "${YELLOW}📋 Using development configuration with network simulation${NC}"
fi

# Stop existing containers
echo -e "${YELLOW}🛑 Stopping existing containers...${NC}"
$DOCKER_COMPOSE_CMD -f "$COMPOSE_FILE" down --remove-orphans || true

# Rebuild if requested
if [[ "$FORCE_REBUILD" == true ]]; then
    echo -e "${YELLOW}🔨 Rebuilding Docker images...${NC}"
    $DOCKER_COMPOSE_CMD -f "$COMPOSE_FILE" build --no-cache
fi

# Start services
echo -e "${GREEN}🚀 Starting MyProxy services...${NC}"
$DOCKER_COMPOSE_CMD -f "$COMPOSE_FILE" up -d

# Wait for services to be ready
echo -e "${YELLOW}⏳ Waiting for services to start...${NC}"
sleep 10

# Show status
echo -e "${BLUE}📊 Service Status:${NC}"
$DOCKER_COMPOSE_CMD -f "$COMPOSE_FILE" ps

# Health check
echo -e "${YELLOW}🏥 Checking service health...${NC}"
sleep 5

if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ MyProxy is healthy and responding${NC}"
else
    echo -e "${YELLOW}⚠️  MyProxy may still be starting up...${NC}"
fi

# Get IP addresses
if [[ "$DEPLOYMENT_TYPE" == "production" ]]; then
    PI_IP=$(hostname -I | cut -d' ' -f1)
    echo -e "${GREEN}🌐 Access MyProxy at:${NC}"
    echo "   http://$PI_IP (standard HTTP)"
    echo "   http://$PI_IP:8080 (admin access)"
else
    echo -e "${GREEN}🌐 Development environment ready:${NC}"
    echo "   MyProxy Gateway: http://localhost:8080"
    echo "   Network Monitor: docker exec -it network-monitor /bin/bash"
fi

echo ""
echo -e "${BLUE}📱 Management Commands:${NC}"
echo "   View logs:    $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE logs -f"
echo "   Stop:         $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE down"
echo "   Restart:      $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE restart"
echo "   Status:       $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE ps"

if [[ "$DEPLOYMENT_TYPE" == "development" ]]; then
    echo ""
    echo -e "${YELLOW}🧪 Test Clients:${NC}"
    echo "   Mobile logs:  $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE logs -f client-mobile"
    echo "   Laptop logs:  $DOCKER_COMPOSE_CMD -f $COMPOSE_FILE logs -f client-laptop"
fi

echo ""
echo -e "${GREEN}✅ Deployment complete!${NC}"