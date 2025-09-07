# 📚 API Documentation

Complete API reference for OAuth2 Authorization Server

## 🌍 Base URL

```
Production: https://your-domain.com/api/v1
Development: http://localhost:8080/api/v1
```

## 🔐 Authentication

This API uses two types of authentication:

1. **JWT Bearer Tokens** - For direct API access
2. **OAuth2 Bearer Tokens** - For third-party application access

### JWT Authentication
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### OAuth2 Authentication
```http
Authorization: Bearer at_randomTokenString123
```

## 📋 HTTP Status Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 204 | No Content | Request successful, no response body |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |

## 🚀 Authentication Endpoints

### POST /auth/register

Create a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "securepassword123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Validation Rules:**
- `email`: Valid email format, unique
- `username`: Minimum 3 characters, unique
- `password`: Minimum 6 characters
- `first_name`: Optional
- `last_name`: Optional

**Response (201 Created):**
```json
{
  "message": "User created successfully",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

**Error Responses:**
```json
// 400 Bad Request - Invalid data
{
  "error": "Invalid request data",
  "details": "Email is required"
}

// 409 Conflict - Email already exists
{
  "error": "User with this email already exists"
}
```

### POST /auth/login

Authenticate user and receive tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200 OK):**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Error Responses:**
```json
// 401 Unauthorized - Invalid credentials
{
  "error": "invalid credentials"
}

// 401 Unauthorized - Account deactivated
{
  "error": "account is deactivated"
}
```

### POST /auth/refresh

Generate new access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "your_refresh_token_here"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "new_refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### POST /auth/logout

Revoke user session and invalidate tokens.

**Headers:**
```
Authorization: Bearer your_access_token_here
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

## 🔑 OAuth2 Endpoints

### GET /oauth/authorize

Initiate OAuth2 authorization code flow.

**Query Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | OAuth2 client identifier |
| `redirect_uri` | Yes | Callback URL after authorization |
| `response_type` | Yes | Must be "code" |
| `scope` | No | Requested permissions (space-separated) |
| `state` | Recommended | CSRF protection token |

**Example Request:**
```
GET /oauth/authorize?client_id=test-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read&state=random_string
```

**Response (302 Found):**
```
Location: http://localhost:3000/callback?code=generated_auth_code&state=random_string
```

**Error Responses:**
```json
// 400 Bad Request - Missing parameters
{
  "error": "Missing required parameters"
}

// 400 Bad Request - Invalid response type
{
  "error": "Unsupported response type"
}

// 400 Bad Request - Invalid redirect URI
{
  "error": "invalid redirect URI"
}
```

### POST /oauth/token

Exchange authorization code for access tokens.

**Content-Type:** `application/x-www-form-urlencoded`

#### Authorization Code Grant

**Request Body:**
```
grant_type=authorization_code&
code=generated_auth_code&
client_id=test-client-id&
client_secret=test-client-secret&
redirect_uri=http://localhost:3000/callback
```

#### Refresh Token Grant

**Request Body:**
```
grant_type=refresh_token&
refresh_token=your_refresh_token&
client_id=test-client-id&
client_secret=test-client-secret
```

**Response (200 OK):**
```json
{
  "access_token": "at_randomTokenString",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "scope": "read"
}
```

**Error Responses:**
```json
// 400 Bad Request - Unsupported grant type
{
  "error": "unsupported_grant_type"
}

// 401 Unauthorized - Invalid client
{
  "error": "invalid_client"
}

// 400 Bad Request - Invalid authorization code
{
  "error": "invalid_grant"
}
```

### GET /oauth/userinfo

Get authenticated user information (OAuth2 standard).

**Headers:**
```
Authorization: Bearer your_oauth_access_token
```

**Response (200 OK):**
```json
{
  "sub": "1",
  "email": "user@example.com",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user"
}
```

## 👤 User Management Endpoints

### GET /profile

Get current user's profile information.

**Headers:**
```
Authorization: Bearer your_access_token
```

**Response (200 OK):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user",
  "is_active": true,
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

### PUT /profile

Update current user's profile information.

**Headers:**
```
Authorization: Bearer your_access_token
```

**Request Body:**
```json
{
  "first_name": "Updated John",
  "last_name": "Updated Doe",
  "username": "newusername"
}
```

**Response (200 OK):**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "newusername",
    "first_name": "Updated John",
    "last_name": "Updated Doe",
    "role": "user",
    "is_active": true,
    "updated_at": "2023-01-01T01:00:00Z"
  }
}
```

**Error Responses:**
```json
// 409 Conflict - Username already taken
{
  "error": "Username already taken"
}
```

### GET /users

Get paginated list of all users (admin only).

**Headers:**
```
Authorization: Bearer admin_access_token
```

**Query Parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | 1 | Page number |
| `limit` | 10 | Items per page (max 100) |

**Example Request:**
```
GET /users?page=1&limit=10
```

**Response (200 OK):**
```json
{
  "users": [
    {
      "id": 1,
      "email": "user1@example.com",
      "username": "user1",
      "first_name": "User",
      "last_name": "One",
      "role": "user",
      "is_active": true,
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 50,
  "page": 1,
  "limit": 10,
  "total_pages": 5
}
```

**Error Responses:**
```json
// 403 Forbidden - Non-admin access
{
  "error": "Insufficient permissions"
}
```

## 🔄 OAuth2 Flow Examples

### Complete Authorization Code Flow

```bash
# Step 1: Get authorization code (redirect in browser)
curl -L "http://localhost:8080/api/v1/oauth/authorize?client_id=test-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read&state=test123"

# Step 2: Extract code from redirect URL
# Example: http://localhost:3000/callback?code=abc123&state=test123

# Step 3: Exchange code for tokens
curl -X POST http://localhost:8080/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=abc123&client_id=test-client-id&client_secret=test-client-secret&redirect_uri=http://localhost:3000/callback"

# Step 4: Use access token
curl -X GET http://localhost:8080/api/v1/oauth/userinfo \
  -H "Authorization: Bearer at_your_access_token"
```

### Token Refresh Flow

```bash
# Refresh expired access token
curl -X POST http://localhost:8080/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=your_refresh_token&client_id=test-client-id&client_secret=test-client-secret"
```

## 🛡️ Security Considerations

### Token Security
- **Access Token Lifetime**: 1 hour
- **Authorization Code Lifetime**: 10 minutes
- **Refresh Token**: Long-lived, can be revoked
- **Token Storage**: Store securely, never in localStorage for web apps

### Rate Limiting
Consider implementing rate limiting for production:
- Login attempts: 5 per minute per IP
- Token requests: 10 per minute per client
- API calls: 100 per minute per user

### CORS Configuration
Configure CORS origins for production:
```go
// In production, replace "*" with specific origins
c.Header("Access-Control-Allow-Origin", "https://yourdomain.com")
```

## 📝 Examples in Different Languages

### JavaScript (Node.js)

```javascript
// OAuth2 client example
const axios = require('axios');

class OAuth2Client {
  constructor(clientId, clientSecret, redirectUri) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.baseURL = 'http://localhost:8080/api/v1';
  }
  
  getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: 'read',
      state: state
    });
    
    return `${this.baseURL}/oauth/authorize?${params}`;
  }
  
  async exchangeCodeForTokens(code) {
    const response = await axios.post(`${this.baseURL}/oauth/token`, {
      grant_type: 'authorization_code',
      code: code,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: this.redirectUri
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    return response.data;
  }
  
  async getUserInfo(accessToken) {
    const response = await axios.get(`${this.baseURL}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    
    return response.data;
  }
}
```

### Python

```python
import requests
from urllib.parse import urlencode

class OAuth2Client:
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.base_url = 'http://localhost:8080/api/v1'
    
    def get_authorization_url(self, state):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'read',
            'state': state
        }
        return f"{self.base_url}/oauth/authorize?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code):
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri
        }
        
        response = requests.post(
            f"{self.base_url}/oauth/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        return response.json()
    
    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(f"{self.base_url}/oauth/userinfo", headers=headers)
        return response.json()
```

## 🐛 Error Handling

### Error Response Format

All error responses follow this format:
```json
{
  "error": "error_code_or_message",
  "details": "Additional error details (optional)"
}
```

### Common Error Scenarios

1. **Invalid JSON**: Malformed request body
2. **Missing Fields**: Required fields not provided
3. **Invalid Credentials**: Wrong email/password combination
4. **Token Expired**: Access token has expired
5. **Insufficient Permissions**: User lacks required role
6. **Rate Limited**: Too many requests from client
7. **Server Error**: Internal server error occurred

---

For more examples and testing, see [test.http](test.http) file.
