# OAuth2 API Usage Examples

## Quick Start

1. **Start the server:**
```bash
go run main.go
```

2. **Register a new user:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "password123",
    "first_name": "Test",
    "last_name": "User"
  }'
```

3. **Login to get tokens:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

4. **Use access token for protected endpoints:**
```bash
# Replace YOUR_ACCESS_TOKEN with the token from login response
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## OAuth2 Flow Examples

### Authorization Code Flow

1. **Get authorization code (visit in browser):**
```
http://localhost:8080/api/v1/oauth/authorize?client_id=test-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read&state=test123
```

2. **Exchange code for tokens:**
```bash
curl -X POST http://localhost:8080/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTHORIZATION_CODE&client_id=test-client-id&client_secret=test-client-secret&redirect_uri=http://localhost:3000/callback"
```

3. **Get user info with OAuth token:**
```bash
curl -X GET http://localhost:8080/api/v1/oauth/userinfo \
  -H "Authorization: Bearer OAUTH_ACCESS_TOKEN"
```

## Example Response

### Registration Response:
```json
{
  "message": "User created successfully",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "testuser",
    "first_name": "Test",
    "last_name": "User",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

### Login Response:
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "testuser",
    "first_name": "Test",
    "last_name": "User",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### OAuth Token Response:
```json
{
  "access_token": "at_randomTokenString",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "scope": "read"
}
```

## Testing Script

Run the provided test script:
```bash
./test_api.sh
```

Or use the Go client test:
```bash
cd test && go run client.go
```
