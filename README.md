# OAuth2 Authorization Server & Client Demo

> 🚀 Complete OAuth2 Implementation with Authorization Server & Client Application

A production-ready OAuth2 system consisting of an Authorization Server and a Client Application built with Go. This implementation follows RFC 6749 standards and demonstrates the complete OAuth2 authorization code flow.

## 📦 Project Structure

```
oauth2-demo/
├── main.go                    # OAuth2 Authorization Server
├── internal/                  # Server internal packages
├── client/                    # OAuth2 Client Application
│   ├── main.go               # Client application
│   ├── templates/            # HTML templates  
│   └── README.md             # Client documentation
├── docs/                     # Complete documentation
├── start-demo.sh             # Start both apps script
├── docker-compose.yml        # Docker orchestration
└── README.md                 # This file
```

## 🌟 Components

### 🔧 OAuth2 Authorization Server (Port 8080)
- ✅ **OAuth2 Authorization Code Flow** - RFC 6749 compliant implementation
- ✅ **Token Endpoint** - Access token and refresh token generation
- ✅ **User Info Endpoint** - Standard OAuth2 user information endpoint
- ✅ **Client Management** - OAuth2 client registration and validation
- ✅ **Scope Management** - Granular permission control

### 🌐 OAuth2 Client Application (Port 3000)
- ✅ **Web-based OAuth2 Client** - Complete client implementation
- ✅ **Authorization Code Flow** - End-to-end OAuth2 flow demonstration
- ✅ **User Profile Display** - Shows user information after authorization
- ✅ **Session Management** - Secure session handling
- ✅ **CSRF Protection** - State parameter validation
- ✅ **Thai Language UI** - Beautiful Thai user interface

## 🚀 Quick Start

### Option 1: Start Script (Recommended)
Run both applications with a single command:
```bash
./start-demo.sh
```

### Option 2: Docker Compose
```bash
docker-compose up --build
```

### Option 3: Manual Start
Start each application separately:

**Terminal 1 - OAuth2 Server:**
```bash
go run main.go
# Server runs on http://localhost:8080
```

**Terminal 2 - OAuth2 Client:**
```bash
cd client
go run main.go  
# Client runs on http://localhost:3000
```

## 🎯 Demo Flow

1. **เปิดเบราว์เซอร์:** http://localhost:3000
2. **คลิก "เข้าสู่ระบบด้วย OAuth2"**
3. **สมัครสมาชิกหรือเข้าสู่ระบบ** ที่ OAuth2 server
4. **อนุญาต client application** เข้าถึงข้อมูล
5. **ดูข้อมูลโปรไฟล์** ของคุณใน client

## 🌟 Features

### Core OAuth2 Features
- ✅ **OAuth2 Authorization Code Flow** - RFC 6749 compliant implementation
- ✅ **Token Endpoint** - Access token and refresh token generation
- ✅ **User Info Endpoint** - Standard OAuth2 user information endpoint
- ✅ **Client Management** - OAuth2 client registration and validation
- ✅ **Scope Management** - Granular permission control

### Authentication & Security
- 🔐 **JWT Authentication** - Secure JWT-based API authentication
- 🔒 **bcrypt Password Hashing** - Industry-standard password security
- 🛡️ **CORS Support** - Cross-origin resource sharing enabled
- 🔄 **Token Refresh** - Automatic token renewal mechanism
- ⏱️ **Token Expiration** - Configurable token lifetime

### User Management
- 👤 **User Registration** - Secure user account creation
- 🔑 **User Login** - Email/password authentication
- 📝 **Profile Management** - User profile CRUD operations
- 👨‍💼 **Role-based Access Control** - User and admin roles

### Technical Features
- 🗄️ **SQLite Database** - Lightweight, embedded database
- 🏗️ **GORM ORM** - Go Object-Relational Mapping
- 🌐 **RESTful API** - Clean REST endpoint design
- 🔄 **Auto Migration** - Database schema auto-migration
- 📊 **Structured Logging** - Comprehensive request logging

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │  Authorization  │    │  Resource API   │
│                 │    │     Server      │    │                 │
│  - Frontend     │◄──►│  - OAuth2 Flow  │◄──►│  - Protected    │
│  - Mobile App   │    │  - JWT Tokens   │    │    Endpoints    │
│  - Third Party  │    │  - User Auth    │    │  - User Data    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Components

| Component | Description | Technology |
|-----------|-------------|------------|
| **HTTP Server** | Gin web framework | `gin-gonic/gin` |
| **Database** | SQLite with GORM ORM | `gorm.io/sqlite` |
| **Authentication** | JWT token management | `golang-jwt/jwt` |
| **Password Security** | bcrypt hashing | `golang.org/x/crypto` |
| **UUID Generation** | Unique identifiers | `google/uuid` |

## 📋 API Endpoints

### 🔐 Authentication Endpoints

#### Register User
Creates a new user account with email verification.

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "securepassword123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
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

#### User Login
Authenticates user and returns JWT tokens.

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Refresh Token
Generates new access token using refresh token.

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "your_refresh_token_here"
}
```

#### Logout
Revokes user session and invalidates tokens.

```http
POST /api/v1/auth/logout
Authorization: Bearer your_access_token_here
```

### 🔑 OAuth2 Endpoints

#### Authorization Endpoint
Initiates OAuth2 authorization code flow.

```http
GET /api/v1/oauth/authorize?client_id=test-client-id&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read&state=random_string
```

**Parameters:**
- `client_id`: OAuth2 client identifier
- `redirect_uri`: Callback URL after authorization
- `response_type`: Must be "code" for authorization code flow
- `scope`: Requested permissions (space-separated)
- `state`: CSRF protection token (recommended)

**Response:**
```http
HTTP/1.1 302 Found
Location: http://localhost:3000/callback?code=auth_code_here&state=random_string
```

#### Token Endpoint
Exchanges authorization code for access tokens.

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=auth_code&client_id=test-client-id&client_secret=test-client-secret&redirect_uri=http://localhost:3000/callback
```

**Response:**
```json
{
  "access_token": "at_randomTokenString",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "scope": "read"
}
```

#### User Info Endpoint
Returns authenticated user information.

```http
GET /api/v1/oauth/userinfo
Authorization: Bearer your_access_token_here
```

**Response:**
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

### 👤 Protected User Endpoints

#### Get User Profile
Returns current user's profile information.

```http
GET /api/v1/profile
Authorization: Bearer your_access_token_here
```

#### Update User Profile
Updates current user's profile information.

```http
PUT /api/v1/profile
Authorization: Bearer your_access_token_here
Content-Type: application/json

{
  "first_name": "Updated Name",
  "last_name": "Updated Last Name",
  "username": "newusername"
}
```

#### Get All Users (Admin Only)
Returns paginated list of all users (admin access required).

```http
GET /api/v1/users?page=1&limit=10
Authorization: Bearer admin_access_token_here
```

## 🚀 Quick Start

### Prerequisites
- Go 1.21 or higher
- Git

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd oauth2-api
```

2. **Install dependencies:**
```bash
go mod tidy
```

3. **Create environment file:**
```bash
cp .env.example .env
```

4. **Start the server:**
```bash
go run main.go
```

The server will start on `http://localhost:8080`

### Using Make Commands

```bash
make help        # Show available commands
make deps        # Install dependencies
make build       # Build the application
make run         # Start the server
make test        # Run tests
make test-api    # Run API integration tests
make clean       # Clean build artifacts
```

## 🧪 Testing

### Manual Testing with cURL

1. **Register a new user:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "password123",
    "first_name": "Test",
    "last_name": "User"
  }'
```

2. **Login to get tokens:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

3. **Access protected endpoint:**
```bash
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Automated Testing

```bash
# Run bash test script
./test_api.sh

# Run Go client test
cd test && go run client.go

# Use HTTP test file
# Open test.http in VS Code with REST Client extension
```

## 🔄 OAuth2 Flow Implementation

### Authorization Code Flow Sequence

```mermaid
sequenceDiagram
    participant User as Resource Owner
    participant Client as Client App
    participant Auth as Authorization Server
    participant Resource as Resource Server
    
    User->>Client: 1. Access application
    Client->>Auth: 2. Authorization request
    Auth->>User: 3. Login prompt
    User->>Auth: 4. Authenticate & authorize
    Auth->>Client: 5. Authorization code
    Client->>Auth: 6. Token request
    Auth->>Client: 7. Access token
    Client->>Resource: 8. Resource request
    Resource->>Client: 9. Protected resource
```

### Flow Steps Explained

1. **Authorization Request**: Client redirects user to authorization endpoint
2. **User Authentication**: User logs in and grants permissions
3. **Authorization Grant**: Server redirects back with authorization code
4. **Token Request**: Client exchanges code for access token
5. **Resource Access**: Client uses access token to access protected resources

## 📊 Database Schema

### Tables Overview

| Table | Description | Key Fields |
|-------|-------------|------------|
| `users` | User accounts | id, email, username, password, role |
| `oauth_clients` | OAuth2 client apps | id, secret, name, redirect_uris |
| `oauth_tokens` | Access/refresh tokens | access_token, refresh_token, expires_at |
| `authorization_codes` | Auth codes | code, user_id, client_id, expires_at |

### Entity Relationships

```
users (1) ──── (n) oauth_tokens
users (1) ──── (n) authorization_codes
oauth_clients (1) ──── (n) oauth_tokens
oauth_clients (1) ──── (n) authorization_codes
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port | `8080` | No |
| `DATABASE_URL` | SQLite database file | `oauth.db` | No |
| `JWT_SECRET` | JWT signing secret | `your-super-secret-jwt-key...` | Yes |

### Default OAuth Client

The application automatically creates a test OAuth client:

| Property | Value |
|----------|-------|
| **Client ID** | `test-client-id` |
| **Client Secret** | `test-client-secret` |
| **Name** | `Test OAuth Client` |
| **Redirect URIs** | `http://localhost:3000/callback`<br>`http://localhost:8080/callback` |
| **Scopes** | `read write` |

## 🛡️ Security Features

### Authentication Security
- **Password Hashing**: bcrypt with default cost (10 rounds)
- **JWT Tokens**: HS256 algorithm with configurable secret
- **Token Expiration**: 1 hour for access tokens
- **Refresh Tokens**: Long-lived tokens for token renewal

### OAuth2 Security
- **Authorization Code Expiry**: 10 minutes
- **Single-Use Codes**: Authorization codes can only be used once
- **Client Validation**: Client ID and secret verification
- **Redirect URI Validation**: Prevents authorization code interception
- **State Parameter**: CSRF protection support

### API Security
- **CORS Configuration**: Configurable cross-origin requests
- **Input Validation**: Request data validation with Gin binding
- **SQL Injection Protection**: GORM ORM provides protection
- **Rate Limiting**: Ready for rate limiting middleware integration

## 🏗️ Project Structure

```
oauth2-api/
├── main.go                    # Application entry point
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── Dockerfile                 # Container configuration
├── Makefile                   # Build automation
├── README.md                  # Project documentation
├── USAGE.md                   # Usage examples
├── test.http                  # HTTP test requests
├── test_api.sh               # Bash test script
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
├── internal/                 # Private application code
│   ├── config/
│   │   └── config.go         # Configuration management
│   ├── database/
│   │   └── database.go       # Database setup & migrations
│   ├── models/
│   │   └── models.go         # Data models & structs
│   ├── services/
│   │   ├── user_service.go   # User business logic
│   │   └── oauth_service.go  # OAuth2 business logic
│   ├── handlers/
│   │   ├── auth_handler.go   # Authentication endpoints
│   │   └── user_handler.go   # User management endpoints
│   └── middleware/
│       └── auth.go           # Authentication middleware
└── test/                     # Test utilities
    ├── go.mod                # Test module
    └── client.go             # HTTP client test
```

## 🚢 Deployment

### Using Docker

1. **Build Docker image:**
```bash
docker build -t oauth2-api .
```

2. **Run container:**
```bash
docker run -p 8080:8080 \
  -e JWT_SECRET=your-production-secret \
  oauth2-api
```

### Production Considerations

#### Environment Configuration
```bash
export PORT=8080
export DATABASE_URL=/data/oauth.db
export JWT_SECRET=your-super-secure-production-secret-key
export GIN_MODE=release
```

#### Security Hardening
- Use a strong, random JWT secret (minimum 32 characters)
- Configure proper CORS origins for production
- Set up HTTPS/TLS termination
- Implement rate limiting
- Enable request logging and monitoring
- Use a production database (PostgreSQL/MySQL)

#### Database Migration
For production, consider using a more robust database:
```go
// Example PostgreSQL configuration
import "gorm.io/driver/postgres"

dsn := "host=localhost user=oauth password=secret dbname=oauth_db sslmode=disable"
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
```

## 🔧 Development

### Adding New OAuth Clients

```go
// In database/database.go
func seedOAuthClients(db *gorm.DB) {
    clients := []models.OAuthClient{
        {
            ID:           "web-app-client",
            Secret:       "web-app-secret",
            Name:         "Web Application",
            RedirectURIs: `["https://webapp.example.com/callback"]`,
            Scopes:       "read write profile",
        },
        {
            ID:           "mobile-app-client",
            Secret:       "mobile-app-secret",
            Name:         "Mobile Application",
            RedirectURIs: `["https://mobile.example.com/callback"]`,
            Scopes:       "read profile",
        },
    }
    
    for _, client := range clients {
        var existing models.OAuthClient
        if db.Where("id = ?", client.ID).First(&existing).Error != nil {
            db.Create(&client)
        }
    }
}
```

### Adding New Scopes

```go
// In models/models.go - extend OAuth client validation
func (c *OAuthClient) ValidateScope(requestedScope string) bool {
    allowedScopes := strings.Fields(c.Scopes)
    requestedScopes := strings.Fields(requestedScope)
    
    for _, requested := range requestedScopes {
        found := false
        for _, allowed := range allowedScopes {
            if requested == allowed {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }
    return true
}
```

### Custom Middleware

```go
// Example rate limiting middleware
func RateLimit() gin.HandlerFunc {
    // Implement rate limiting logic
    return gin.HandlerFunc(func(c *gin.Context) {
        // Rate limiting implementation
        c.Next()
    })
}

// Add to router setup
router.Use(RateLimit())
```

## 📚 API Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete API endpoint documentation |
| [Architecture Guide](docs/ARCHITECTURE.md) | Technical architecture and implementation details |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment instructions |
| [Usage Examples](USAGE.md) | Quick start and usage examples |

## 🧪 Testing Files

| File | Description |
|------|-------------|
| `test.http` | VS Code REST Client test requests |
| `test_api.sh` | Bash script for API testing |
| `test/client.go` | Go HTTP client integration test |

## 🔍 Troubleshooting

### Common Issues

#### Server Won't Start
```bash
# Check if port is already in use
lsof -i :8080

# Kill process using the port
kill -9 <PID>
```

#### Database Issues
```bash
# Remove database file to reset
rm oauth.db

# Restart server to recreate database
go run main.go
```

#### Token Issues
```bash
# Verify JWT secret is set correctly
echo $JWT_SECRET

# Check token expiration in JWT debugger
# Visit: https://jwt.io
```

### Debug Mode

Enable debug logging:
```bash
export GIN_MODE=debug
go run main.go
```

## 📖 Further Reading

### OAuth2 Specifications
- [RFC 6749: OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7636: PKCE for OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

### JWT Resources
- [JWT.io](https://jwt.io/) - JWT debugger and information
- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

### Go Resources
- [Gin Web Framework](https://gin-gonic.com/)
- [GORM Documentation](https://gorm.io/)
- [Go Security Guidelines](https://github.com/Checkmarx/Go-SCP)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request

### Development Guidelines
- Follow Go conventions and best practices
- Add tests for new features
- Update documentation when adding new endpoints
- Ensure security considerations for OAuth2 compliance

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin Web Framework](https://github.com/gin-gonic/gin) for the HTTP router
- [GORM](https://github.com/go-gorm/gorm) for the ORM
- [golang-jwt](https://github.com/golang-jwt/jwt) for JWT implementation
- OAuth2 community for specifications and best practices

---

**Built with ❤️ in Go**
