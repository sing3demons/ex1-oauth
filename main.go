package main

import (
	"log"
	"oauth2-api/internal/config"
	"oauth2-api/internal/database"
	"oauth2-api/internal/handlers"
	"oauth2-api/internal/middleware"
	"oauth2-api/internal/services"

	"github.com/gin-gonic/gin"
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

func setupRouter(authHandler *handlers.AuthHandler, userHandler *handlers.UserHandler, jwtSecret string) *gin.Engine {
	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

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
