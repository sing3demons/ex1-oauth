#!/bin/bash

# OAuth2 API Testing Script

BASE_URL="http://localhost:8080/api/v1"

echo "=== OAuth2 API Testing Script ==="
echo "Base URL: $BASE_URL"
echo

# Test 1: Register a new user
echo "1. Registering a new user..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "password123",
    "first_name": "Test",
    "last_name": "User"
  }')

echo "Register Response: $REGISTER_RESPONSE"
echo

# Test 2: Login with the user
echo "2. Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }')

echo "Login Response: $LOGIN_RESPONSE"

# Extract access token from login response
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "Access Token: $ACCESS_TOKEN"
echo

# Test 3: Get user profile
echo "3. Getting user profile..."
PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Profile Response: $PROFILE_RESPONSE"
echo

# Test 4: OAuth2 Authorization (will redirect)
echo "4. Testing OAuth2 authorization..."
AUTH_URL="$BASE_URL/oauth/authorize?client_id=test-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read&state=test123"
echo "Authorization URL: $AUTH_URL"

# Note: This will redirect, so we're just showing the URL
echo "Note: This endpoint will redirect with authorization code"
echo

# Test 5: Get user info using OAuth endpoint
echo "5. Getting user info via OAuth endpoint..."
USERINFO_RESPONSE=$(curl -s -X GET "$BASE_URL/oauth/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "UserInfo Response: $USERINFO_RESPONSE"
echo

# Test 6: Update profile
echo "6. Updating user profile..."
UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated Test",
    "last_name": "Updated User"
  }')

echo "Update Response: $UPDATE_RESPONSE"
echo

# Test 7: Logout
echo "7. Logging out..."
LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Logout Response: $LOGOUT_RESPONSE"
echo

echo "=== Testing Complete ==="
