#!/bin/bash

# OAuth2 Demo Start Script
# สคริปต์สำหรับรัน OAuth2 Server และ Client พร้อมกันในโหมด development

echo "🚀 Starting OAuth2 Demo..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        echo -e "${RED}❌ Port $1 is already in use${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Port $1 is available${NC}"
        return 0
    fi
}

# Function to stop background processes
cleanup() {
    echo -e "\n${YELLOW}🛑 Stopping OAuth2 Demo...${NC}"
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null
        echo -e "${GREEN}✅ OAuth2 Server stopped${NC}"
    fi
    if [ ! -z "$CLIENT_PID" ]; then
        kill $CLIENT_PID 2>/dev/null
        echo -e "${GREEN}✅ OAuth2 Client stopped${NC}"
    fi
    exit 0
}

# Trap to cleanup on exit
trap cleanup INT TERM EXIT

# Check if ports are available
echo "🔍 Checking ports..."
check_port 8080 || exit 1
check_port 3000 || exit 1

# Start OAuth2 Server
echo -e "\n${BLUE}🔧 Starting OAuth2 Server...${NC}"
cd /Users/kp.sing/_workspace/github.com/sing3demons/_go_/ex1-oauth
go run main.go &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for OAuth2 Server to start..."
sleep 3

# Check if server is running
if ! curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo -e "${RED}❌ OAuth2 Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✅ OAuth2 Server is running on http://localhost:8080${NC}"

# Start OAuth2 Client
echo -e "\n${BLUE}🔧 Starting OAuth2 Client...${NC}"
cd /Users/kp.sing/_workspace/github.com/sing3demons/_go_/ex1-oauth/client
go run main.go &
CLIENT_PID=$!

# Wait for client to start
echo "⏳ Waiting for OAuth2 Client to start..."
sleep 3

# Check if client is running
if ! curl -s http://localhost:3000 >/dev/null 2>&1; then
    echo -e "${RED}❌ OAuth2 Client failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✅ OAuth2 Client is running on http://localhost:3000${NC}"

echo -e "\n${GREEN}🎉 OAuth2 Demo is ready!${NC}"
echo -e "${BLUE}📝 Open your browser and go to:${NC}"
echo -e "   🌐 OAuth2 Client: ${YELLOW}http://localhost:3000${NC}"
echo -e "   🔧 OAuth2 Server: ${YELLOW}http://localhost:8080${NC}"
echo -e "\n${YELLOW}💡 Instructions:${NC}"
echo -e "   1. Go to http://localhost:3000"
echo -e "   2. Click 'เข้าสู่ระบบด้วย OAuth2'"
echo -e "   3. Register/Login on the OAuth2 server"
echo -e "   4. Authorize the client application"
echo -e "   5. View your profile information"
echo -e "\n${RED}🛑 Press Ctrl+C to stop both applications${NC}"

# Keep script running
while true; do
    sleep 1
done
