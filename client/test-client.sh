#!/bin/bash

# OAuth2 Client Test Script
# สคริปต์สำหรับทดสอบ OAuth2 Client endpoints

echo "🧪 Testing OAuth2 Client..."

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Client URL
CLIENT_URL="http://localhost:3000"

# Test function
test_endpoint() {
    local endpoint=$1
    local expected_status=$2
    local description=$3
    
    echo -n "Testing $description... "
    
    status=$(curl -s -o /dev/null -w "%{http_code}" "$CLIENT_URL$endpoint")
    
    if [ "$status" -eq "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS (HTTP $status)${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL (Expected HTTP $expected_status, got HTTP $status)${NC}"
        return 1
    fi
}

# Check if client is running
echo "🔍 Checking if OAuth2 Client is running..."
if ! curl -s "$CLIENT_URL" >/dev/null 2>&1; then
    echo -e "${RED}❌ OAuth2 Client is not running on $CLIENT_URL${NC}"
    echo "Please start the client with: cd client && go run main.go"
    exit 1
fi

echo -e "${GREEN}✅ OAuth2 Client is running${NC}\n"

# Test endpoints
echo "🧪 Running endpoint tests..."

test_endpoint "/" 200 "Home page"
test_endpoint "/login" 302 "Login redirect (should redirect to OAuth2 server)"
test_endpoint "/profile" 302 "Profile page (should redirect to login when not authenticated)"
test_endpoint "/nonexistent" 404 "Non-existent page"

echo -e "\n🎯 Manual Test Instructions:"
echo -e "${YELLOW}1. Open browser: $CLIENT_URL${NC}"
echo -e "${YELLOW}2. Click 'เข้าสู่ระบบด้วย OAuth2'${NC}"
echo -e "${YELLOW}3. Complete OAuth2 flow${NC}"
echo -e "${YELLOW}4. Check profile page${NC}"

echo -e "\n✅ Client test completed!"
