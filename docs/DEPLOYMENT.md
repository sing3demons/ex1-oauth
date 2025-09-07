# 🚢 Deployment Guide

Complete deployment guide for OAuth2 Authorization Server across different environments

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Development Deployment](#development-deployment)
- [Production Deployment](#production-deployment)
- [Docker Deployment](#docker-deployment)
- [Cloud Deployment](#cloud-deployment)
- [Environment Configuration](#environment-configuration)
- [Database Migration](#database-migration)
- [Security Hardening](#security-hardening)
- [Monitoring Setup](#monitoring-setup)
- [Troubleshooting](#troubleshooting)

## 🛠️ Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 1 Core | 2+ Cores |
| **Memory** | 512MB | 1GB+ |
| **Storage** | 1GB | 5GB+ |
| **Go Version** | 1.21+ | Latest |

### Dependencies

- Go 1.21 or higher
- Git
- SQLite3 (development)
- PostgreSQL/MySQL (production)
- Docker (optional)
- Reverse proxy (nginx/traefik)

## 🧪 Development Deployment

### Local Development

1. **Clone repository:**
```bash
git clone <repository-url>
cd oauth2-api
```

2. **Install dependencies:**
```bash
go mod tidy
```

3. **Set environment variables:**
```bash
export PORT=8080
export DATABASE_URL=oauth.db
export JWT_SECRET=dev-secret-key-change-in-production
export GIN_MODE=debug
```

4. **Run the application:**
```bash
go run main.go
```

5. **Verify installation:**
```bash
curl http://localhost:8080/api/v1/profile
# Should return 401 Unauthorized (expected without token)
```

### Development with Make

```bash
make deps    # Install dependencies
make run     # Start development server
make test    # Run tests
```

### Development with Docker

```bash
# Build development image
docker build -t oauth2-api:dev .

# Run development container
docker run -p 8080:8080 \
  -e GIN_MODE=debug \
  -e JWT_SECRET=dev-secret \
  oauth2-api:dev
```

## 🏭 Production Deployment

### Binary Deployment

1. **Build production binary:**
```bash
# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o oauth2-api main.go

# Or use Make
make build
```

2. **Create production directory:**
```bash
sudo mkdir -p /opt/oauth2-api
sudo chown app:app /opt/oauth2-api
```

3. **Deploy binary:**
```bash
scp oauth2-api user@server:/opt/oauth2-api/
scp .env.production user@server:/opt/oauth2-api/.env
```

4. **Create systemd service:**
```bash
sudo tee /etc/systemd/system/oauth2-api.service > /dev/null <<EOF
[Unit]
Description=OAuth2 Authorization Server
After=network.target

[Service]
Type=simple
User=app
Group=app
WorkingDirectory=/opt/oauth2-api
ExecStart=/opt/oauth2-api/oauth2-api
Restart=always
RestartSec=5
Environment=GIN_MODE=release
EnvironmentFile=/opt/oauth2-api/.env

[Install]
WantedBy=multi-user.target
EOF
```

5. **Start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable oauth2-api
sudo systemctl start oauth2-api
sudo systemctl status oauth2-api
```

### Database Setup (PostgreSQL)

1. **Install PostgreSQL:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install postgresql-server postgresql-contrib
```

2. **Create database and user:**
```sql
sudo -u postgres psql

CREATE DATABASE oauth2_db;
CREATE USER oauth2_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE oauth2_db TO oauth2_user;
\q
```

3. **Update connection string:**
```bash
export DATABASE_URL="postgres://oauth2_user:secure_password@localhost/oauth2_db?sslmode=disable"
```

### Reverse Proxy Setup (Nginx)

1. **Install Nginx:**
```bash
sudo apt install nginx
```

2. **Create site configuration:**
```bash
sudo tee /etc/nginx/sites-available/oauth2-api > /dev/null <<EOF
server {
    listen 80;
    server_name oauth.yourdomain.com;
    
    # Redirect to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name oauth.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/oauth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oauth.yourdomain.com/privkey.pem;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Proxy Configuration
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    # Rate Limiting
    limit_req_zone \$binary_remote_addr zone=oauth_login:10m rate=5r/m;
    
    location /api/v1/auth/login {
        limit_req zone=oauth_login burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080;
    }
}
EOF
```

3. **Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/oauth2-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d oauth.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 🐳 Docker Deployment

### Docker Compose (Recommended)

1. **Create docker-compose.yml:**
```yaml
version: '3.8'

services:
  oauth2-api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - DATABASE_URL=postgres://oauth2:password@db:5432/oauth2_db?sslmode=disable
      - JWT_SECRET=${JWT_SECRET}
      - GIN_MODE=release
    depends_on:
      - db
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs
    networks:
      - oauth2-network

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=oauth2_db
      - POSTGRES_USER=oauth2
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - oauth2-network
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - oauth2-api
    networks:
      - oauth2-network
    restart: unless-stopped

volumes:
  postgres_data:

networks:
  oauth2-network:
    driver: bridge
```

2. **Create environment file:**
```bash
# .env
JWT_SECRET=your-super-secure-production-jwt-secret-key-here
POSTGRES_PASSWORD=your-secure-database-password
```

3. **Deploy with Docker Compose:**
```bash
docker-compose up -d
docker-compose logs -f oauth2-api
```

### Production Docker Setup

1. **Multi-stage Dockerfile (optimized):**
```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o main .

# Production stage
FROM alpine:3.18

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 1001 app && \
    adduser -u 1001 -G app -s /bin/sh -D app

WORKDIR /app

COPY --from=builder /app/main .
COPY --chown=app:app .env.example .env

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./main"]
```

2. **Build production image:**
```bash
docker build -t oauth2-api:latest .
docker tag oauth2-api:latest your-registry/oauth2-api:v1.0.0
docker push your-registry/oauth2-api:v1.0.0
```

## ☁️ Cloud Deployment

### AWS Deployment

#### EC2 Deployment

1. **Launch EC2 instance:**
```bash
# Use Ubuntu 22.04 LTS
# t3.micro for development, t3.small+ for production
```

2. **Security Group Rules:**
```
Type: HTTP, Port: 80, Source: 0.0.0.0/0
Type: HTTPS, Port: 443, Source: 0.0.0.0/0
Type: SSH, Port: 22, Source: Your IP
```

3. **Deploy using User Data:**
```bash
#!/bin/bash
apt update
apt install -y docker.io docker-compose

# Clone and deploy your application
git clone <your-repo>
cd oauth2-api
docker-compose up -d
```

#### ECS Deployment

1. **Create task definition:**
```json
{
  "family": "oauth2-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "oauth2-api",
      "image": "your-registry/oauth2-api:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "PORT",
          "value": "8080"
        },
        {
          "name": "GIN_MODE",
          "value": "release"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:oauth2/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/oauth2-api",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Platform

#### Cloud Run Deployment

1. **Build and push image:**
```bash
# Enable required APIs
gcloud services enable cloudbuild.googleapis.com run.googleapis.com

# Build image
gcloud builds submit --tag gcr.io/PROJECT_ID/oauth2-api

# Deploy to Cloud Run
gcloud run deploy oauth2-api \
  --image gcr.io/PROJECT_ID/oauth2-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars GIN_MODE=release \
  --set-env-vars PORT=8080
```

2. **Set secrets:**
```bash
# Create secret
echo "your-jwt-secret" | gcloud secrets create jwt-secret --data-file=-

# Update service with secret
gcloud run services update oauth2-api \
  --update-secrets JWT_SECRET=jwt-secret:latest
```

### Kubernetes Deployment

1. **Create namespace:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: oauth2-system
```

2. **Create deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-api
  namespace: oauth2-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oauth2-api
  template:
    metadata:
      labels:
        app: oauth2-api
    spec:
      containers:
      - name: oauth2-api
        image: your-registry/oauth2-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: PORT
          value: "8080"
        - name: GIN_MODE
          value: "release"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth2-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-api-service
  namespace: oauth2-system
spec:
  selector:
    app: oauth2-api
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-api-ingress
  namespace: oauth2-system
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - oauth.yourdomain.com
    secretName: oauth2-tls
  rules:
  - host: oauth.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: oauth2-api-service
            port:
              number: 80
```

## ⚙️ Environment Configuration

### Production Environment Variables

```bash
# .env.production
PORT=8080
GIN_MODE=release

# Database
DATABASE_URL=postgres://oauth2_user:secure_password@localhost:5432/oauth2_db?sslmode=require

# Security
JWT_SECRET=your-super-secure-64-character-jwt-secret-key-for-production-use
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# Features
ENABLE_REGISTRATION=true
ENABLE_PASSWORD_RESET=false
TOKEN_EXPIRY_HOURS=1
REFRESH_TOKEN_EXPIRY_DAYS=30

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600

# External Services
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USERNAME=oauth@yourdomain.com
SMTP_PASSWORD=smtp_password
```

### Environment Validation

```go
// Add to config package
func ValidateConfig(cfg *Config) error {
    if cfg.JWTSecret == "" || len(cfg.JWTSecret) < 32 {
        return errors.New("JWT_SECRET must be at least 32 characters")
    }
    
    if cfg.Port == "" {
        return errors.New("PORT is required")
    }
    
    if cfg.DatabaseURL == "" {
        return errors.New("DATABASE_URL is required")
    }
    
    return nil
}
```

## 🗄️ Database Migration

### Migration Strategy

1. **Backup current database:**
```bash
# SQLite
cp oauth.db oauth.db.backup

# PostgreSQL
pg_dump oauth2_db > backup.sql
```

2. **Run migrations:**
```bash
# Using GORM AutoMigrate (automatic)
go run main.go

# Manual migration (if needed)
psql -U oauth2_user -d oauth2_db -f migrations/001_initial.sql
```

3. **Verify migration:**
```bash
# Check tables exist
psql -U oauth2_user -d oauth2_db -c "\dt"

# Verify data integrity
go run scripts/verify_migration.go
```

### Migration Scripts

```sql
-- migrations/001_initial.sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP NULL
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
```

## 🔒 Security Hardening

### Application Security

1. **Strong JWT Secret:**
```bash
# Generate secure JWT secret
openssl rand -base64 64
```

2. **Environment Variable Security:**
```bash
# Restrict file permissions
chmod 600 .env
chown app:app .env
```

3. **Application User:**
```bash
# Create dedicated user
sudo useradd -r -s /bin/false oauth2
sudo chown -R oauth2:oauth2 /opt/oauth2-api
```

### Network Security

1. **Firewall Configuration:**
```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

2. **Fail2Ban (Brute Force Protection):**
```bash
sudo apt install fail2ban

# Create jail for OAuth API
sudo tee /etc/fail2ban/jail.d/oauth2.conf > /dev/null <<EOF
[oauth2-login]
enabled = true
port = http,https
filter = oauth2-login
logpath = /var/log/oauth2/access.log
maxretry = 5
bantime = 3600
findtime = 300
EOF
```

### Database Security

1. **PostgreSQL Security:**
```sql
-- Restrict database permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO oauth2_user;
GRANT CREATE ON SCHEMA public TO oauth2_user;

-- Enable SSL
ALTER SYSTEM SET ssl = on;
SELECT pg_reload_conf();
```

2. **Connection Security:**
```bash
# Require SSL connections
export DATABASE_URL="postgres://oauth2_user:password@localhost:5432/oauth2_db?sslmode=require"
```

## 📊 Monitoring Setup

### Health Check Endpoint

```go
// Add to main.go
func setupHealthCheck(router *gin.Engine, db *gorm.DB) {
    router.GET("/health", func(c *gin.Context) {
        // Database health check
        sqlDB, err := db.DB()
        if err != nil {
            c.JSON(503, gin.H{
                "status": "unhealthy",
                "database": "error",
                "error": err.Error(),
            })
            return
        }
        
        if err := sqlDB.Ping(); err != nil {
            c.JSON(503, gin.H{
                "status": "unhealthy",
                "database": "disconnected",
            })
            return
        }
        
        c.JSON(200, gin.H{
            "status": "healthy",
            "database": "connected",
            "version": "1.0.0",
            "uptime": time.Since(startTime).String(),
        })
    })
}
```

### Prometheus Metrics

```go
// Add Prometheus metrics
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    httpRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "oauth2_http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )
    
    httpRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "oauth2_http_request_duration_seconds",
            Help: "HTTP request duration in seconds",
        },
        []string{"method", "endpoint"},
    )
)

func init() {
    prometheus.MustRegister(httpRequestsTotal)
    prometheus.MustRegister(httpRequestDuration)
}

// Metrics middleware
func PrometheusMiddleware() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        start := time.Now()
        c.Next()
        
        duration := time.Since(start).Seconds()
        status := strconv.Itoa(c.Writer.Status())
        
        httpRequestsTotal.WithLabelValues(
            c.Request.Method,
            c.FullPath(),
            status,
        ).Inc()
        
        httpRequestDuration.WithLabelValues(
            c.Request.Method,
            c.FullPath(),
        ).Observe(duration)
    })
}

// Add metrics endpoint
router.GET("/metrics", gin.WrapH(promhttp.Handler()))
```

### Logging Configuration

```go
// Structured logging with logrus
import (
    "github.com/sirupsen/logrus"
    "gopkg.in/natefinch/lumberjack.v2"
)

func setupLogging() {
    logrus.SetFormatter(&logrus.JSONFormatter{})
    
    if os.Getenv("GIN_MODE") == "release" {
        logrus.SetLevel(logrus.InfoLevel)
        
        // Log rotation
        logrus.SetOutput(&lumberjack.Logger{
            Filename:   "/var/log/oauth2/app.log",
            MaxSize:    100, // MB
            MaxBackups: 3,
            MaxAge:     28, // days
            Compress:   true,
        })
    } else {
        logrus.SetLevel(logrus.DebugLevel)
    }
}

// Request logging middleware
func LoggingMiddleware() gin.HandlerFunc {
    return gin.HandlerFunc(func(c *gin.Context) {
        start := time.Now()
        c.Next()
        
        logrus.WithFields(logrus.Fields{
            "method":      c.Request.Method,
            "path":        c.Request.URL.Path,
            "status":      c.Writer.Status(),
            "duration":    time.Since(start),
            "ip":          c.ClientIP(),
            "user_agent":  c.Request.UserAgent(),
        }).Info("HTTP Request")
    })
}
```

## 🔧 Troubleshooting

### Common Issues

#### Server Won't Start

```bash
# Check port availability
netstat -tlnp | grep :8080
lsof -i :8080

# Check logs
journalctl -u oauth2-api -f

# Check environment variables
env | grep -E "(PORT|DATABASE_URL|JWT_SECRET)"
```

#### Database Connection Issues

```bash
# Test database connection
psql -U oauth2_user -h localhost -d oauth2_db -c "SELECT 1"

# Check database logs
sudo journalctl -u postgresql -f

# Verify connection string
echo $DATABASE_URL
```

#### SSL/TLS Issues

```bash
# Test SSL certificate
openssl s_client -connect oauth.yourdomain.com:443

# Check certificate expiry
echo | openssl s_client -connect oauth.yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates

# Renew Let's Encrypt certificate
sudo certbot renew --dry-run
```

#### Memory Issues

```bash
# Check memory usage
free -h
ps aux | grep oauth2-api

# Monitor memory over time
watch -n 1 'ps aux | grep oauth2-api'

# Adjust container limits (Docker)
docker update --memory=1g oauth2-api
```

### Performance Optimization

1. **Database Query Optimization:**
```go
// Use database indexes
db.Where("email = ?", email).First(&user)

// Preload relationships
db.Preload("Tokens").Find(&users)

// Use pagination
db.Limit(limit).Offset(offset).Find(&users)
```

2. **Connection Pooling:**
```go
sqlDB, err := db.DB()
sqlDB.SetMaxIdleConns(10)
sqlDB.SetMaxOpenConns(100)
sqlDB.SetConnMaxLifetime(time.Hour)
```

3. **Caching Strategy:**
```go
// Add Redis caching
func (s *OAuthService) ValidateAccessToken(token string) (*models.OAuthToken, error) {
    // Check cache first
    if cached := s.cache.Get("token:" + token); cached != nil {
        return cached.(*models.OAuthToken), nil
    }
    
    // Query database
    var oauthToken models.OAuthToken
    err := s.db.Where("access_token = ?", token).First(&oauthToken).Error
    if err != nil {
        return nil, err
    }
    
    // Cache result
    s.cache.Set("token:"+token, &oauthToken, time.Minute*10)
    
    return &oauthToken, nil
}
```

### Rollback Procedures

1. **Application Rollback:**
```bash
# Systemd service
sudo systemctl stop oauth2-api
sudo cp /opt/oauth2-api/oauth2-api.backup /opt/oauth2-api/oauth2-api
sudo systemctl start oauth2-api

# Docker
docker-compose down
docker-compose up -d --force-recreate oauth2-api:previous-version
```

2. **Database Rollback:**
```bash
# PostgreSQL
psql -U oauth2_user -d oauth2_db < backup.sql

# SQLite
cp oauth.db.backup oauth.db
```

---

This deployment guide provides comprehensive instructions for deploying the OAuth2 Authorization Server across various environments, from development to production-scale deployments in the cloud.
