package main

import (
	"bytes"
	"fmt"
	"log"
	"oauth2-api/internal/config"
	"oauth2-api/internal/database"
	"oauth2-api/internal/handlers"
	"oauth2-api/internal/logger"
	"oauth2-api/internal/middleware"
	"oauth2-api/internal/services"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Initialize services
	userService := services.NewUserService(db)
	oauthService := services.NewOAuthService(db, cfg.JWTSecret)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userService, oauthService)
	userHandler := handlers.NewUserHandler(userService)

	// Setup router
	router := setupRouter(authHandler, userHandler, cfg.JWTSecret)

	log.Printf("Server starting on port %s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b) // เก็บสำเนาไว้
	return w.ResponseWriter.Write(b)
}



func setupRouter(authHandler *handlers.AuthHandler, userHandler *handlers.UserHandler, jwtSecret string) *gin.Engine {
	router := gin.Default()

	logApp := logger.NewLogger(logger.LogConfig{
		Level:             "debug",
		EnableFileLogging: false,
		LogFileProperties: logger.LogFileProperties{},
	})

	dirname := "logs/detail"
	filename := "detail-%DATE%"
	datePattern := "YYYY-MM-DD-HH"
	extension := ".log"
	logDetail := logger.NewLogger(logger.LogConfig{
		Level:             "debug",
		EnableFileLogging: true,
		LogFileProperties: logger.LogFileProperties{
			Filename:    filename,
			Dirname:     dirname,
			DatePattern: datePattern,
			Extension:   extension,
		},
	})
	logSummary := logger.NewLogger(logger.LogConfig{
		Level:             "debug",
		EnableFileLogging: true,
		LogFileProperties: logger.LogFileProperties{
			Filename:    "summary-%DATE%",
			Dirname:     "logs/summary",
			DatePattern: datePattern,
			Extension:   extension,
		},
	})
	maskingService := logger.NewMaskingService()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		sessionId := c.GetHeader("X-Session-ID")
		if sessionId == "" {
			sessionId = uuid.New().String()
		}

		reqId := c.Request.Header.Get("X-Request-ID")
		if reqId == "" {
			reqId = uuid.New().String()
		}
		t := logger.NewTimer()
		csLog := logger.NewCustomLogger(logDetail, logSummary, t, maskingService)
		hostName, _ := os.Hostname()
		customLog := logger.LogDto{
			ServiceName:      "oauth2-api",
			LogType:          "detail",
			ComponentVersion: "1.0.0",
			Instance:         hostName,
			SessionId:        sessionId,
			RequestId:        reqId,
			UseCase:          "none",
		}
		csLog.Init(customLog)
		c.Set("logApp", logApp)
		c.Set("customLog", csLog)

		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		// After request
		response := map[string]any{
			"headers": c.Writer.Header(),
			"body":    blw.body.String(),
			"status":  c.Writer.Status(),
		}
		useCase := csLog.GetLogDto().UseCase
		csLog.Info(logger.NewOutbound(useCase, fmt.Sprintf("%s -> %s", c.Request.Method, c.Request.URL.Path)), response)
		csLog.End(c.Writer.Status(), "")
	})

	router.LoadHTMLGlob("templates/*")

	// Public routes
	v1 := router.Group("/api/v1")
	{
		// Authentication routes
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.POST("/logout", authHandler.Logout)
		}

		// OAuth2 routes
		oauth := v1.Group("/oauth")
		{
			oauth.GET("/authorize", authHandler.Authorize)
			oauth.POST("/token", authHandler.Token)
			oauth.GET("/userinfo", middleware.RequireAuth(jwtSecret), authHandler.UserInfo)
		}
	}
	oauth2 := router.Group("/oauth")
	{

		oauth2.GET("/authorize", authHandler.Authorize)
		oauth2.POST("/token", authHandler.Token)
		oauth2.GET("/profile", authHandler.UserInfo)

	}

	// Protected routes
	protected := v1.Group("/")
	protected.Use(middleware.RequireAuth(jwtSecret))
	{
		protected.GET("/profile", userHandler.GetProfile)
		protected.PUT("/profile", userHandler.UpdateProfile)
		protected.GET("/users", userHandler.GetUsers) // Admin only
	}

	return router
}
