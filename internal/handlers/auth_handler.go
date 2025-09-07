package handlers

import (
	"net/http"
	"oauth2-api/internal/models"
	"oauth2-api/internal/services"
	"strconv"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	userService  *services.UserService
	oauthService *services.OAuthService
}

func NewAuthHandler(userService *services.UserService, oauthService *services.OAuthService) *AuthHandler {
	return &AuthHandler{
		userService:  userService,
		oauthService: oauthService,
	}
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,min=3"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Check if user already exists
	if _, err := h.userService.GetUserByEmail(req.Email); err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this email already exists",
		})
		return
	}

	if _, err := h.userService.GetUserByUsername(req.Username); err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this username already exists",
		})
		return
	}

	// Create new user
	user := &models.User{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Role:      "user",
		IsActive:  true,
	}

	if err := h.userService.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	// Generate access token
	accessToken, err := h.oauthService.GenerateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
		},
		"access_token": accessToken,
		"token_type":   "Bearer",
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	// Validate user credentials
	user, err := h.userService.ValidateUser(req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Generate access token
	accessToken, err := h.oauthService.GenerateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		return
	}

	// Generate refresh token
	refreshToken, err := h.oauthService.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
		},
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600, // 1 hour
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	// Validate refresh token and generate new tokens
	token, err := h.oauthService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Generate new access token
	accessToken, err := h.oauthService.GenerateAccessToken(&token.User)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusOK, gin.H{
			"message": "Logged out successfully",
		})
		return
	}

	// Extract token from header
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		accessToken := authHeader[7:]
		// Revoke the token
		h.oauthService.RevokeToken(accessToken)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// OAuth2 Authorization endpoint
func (h *AuthHandler) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameters",
		})
		return
	}

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported response type",
		})
		return
	}

	// Validate redirect URI
	if err := h.oauthService.ValidateRedirectURI(clientID, redirectURI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// For demo purposes, we'll auto-approve the authorization
	// In a real implementation, you'd show an authorization page
	userID := uint(1) // This should come from the authenticated user

	// Generate authorization code
	authCode, err := h.oauthService.GenerateAuthorizationCode(userID, clientID, redirectURI, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate authorization code",
		})
		return
	}

	// Redirect with authorization code
	redirectURL := redirectURI + "?code=" + authCode.Code
	if state != "" {
		redirectURL += "&state=" + state
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// OAuth2 Token endpoint
func (h *AuthHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		h.handleRefreshTokenGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
	}
}

func (h *AuthHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")

	// Validate client credentials
	_, err := h.oauthService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Validate authorization code
	authCode, err := h.oauthService.ValidateAuthorizationCode(code, clientID, redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_grant",
		})
		return
	}

	// Create OAuth tokens
	token, err := h.oauthService.CreateOAuthToken(authCode.UserID, clientID, authCode.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create tokens",
		})
		return
	}

	response := TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    3600,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Validate client credentials
	_, err := h.oauthService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Validate refresh token and generate new tokens
	token, err := h.oauthService.ValidateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_grant",
		})
		return
	}

	response := TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    3600,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}

	c.JSON(http.StatusOK, response)
}

// UserInfo returns user information (OAuth2 userinfo endpoint)
func (h *AuthHandler) UserInfo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	user, err := h.userService.GetUserByID(userID.(uint))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":        strconv.Itoa(int(user.ID)),
		"email":      user.Email,
		"username":   user.Username,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
	})
}
