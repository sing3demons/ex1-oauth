package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"oauth2-api/internal/logger"
	"oauth2-api/internal/mlog"
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

func cloneRequestBody(req *http.Request) ([]byte, error) {
	// อ่าน body ออกมา
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	// คืนค่า body กลับให้ req ใช้ต่อ
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, nil
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "register",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		summaryParam.Description = err.Error()
		summaryParam.Code = "400"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user registration"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Failed to bind request data"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user registration"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
		"body":    req,
	})

	// Check if user already exists
	if _, err := h.userService.GetUserByEmail(req.Email, detailLog); err == nil {
		summaryParam.Code = fmt.Sprintf("%d", http.StatusConflict)
		summaryParam.Description = "invalid_request"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "User with this email already exists"), response)
		c.JSON(http.StatusConflict, response)
		return
	}

	if _, err := h.userService.GetUserByUsername(req.Username, detailLog); err == nil {
		summaryParam.Code = fmt.Sprintf("%d", http.StatusConflict)
		summaryParam.Description = "invalid_request"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "User with this username already exists"), response)
		c.JSON(http.StatusConflict, response)
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
		summaryParam.Code = fmt.Sprintf("%d", http.StatusInternalServerError)
		summaryParam.Description = err.Error()
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Failed to create user"), response)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	// Generate access token
	accessToken, err := h.oauthService.GenerateAccessToken(user)
	if err != nil {
		detailLog.AddField("Error", err.Error())
		summaryParam.Code = fmt.Sprintf("%d", http.StatusInternalServerError)
		summaryParam.Description = "server_error"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Failed to generate access token"), response)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	response := map[string]any{
		"message": "success",
		"user": map[string]any{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
		},
		"access_token": accessToken,
		"token_type":   "Bearer",
	}
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "User registered successfully"), response)
	// detailLog.End(http.StatusCreated, "")
	c.JSON(http.StatusCreated, response)
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "login",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		summaryParam.Description = err.Error()
		summaryParam.Code = "400"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user login"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user login"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
		"body":    req,
	})

	// Validate user credentials
	user, err := h.userService.ValidateUser(req.Email, req.Password, detailLog)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Generate access token
	accessToken, err := h.oauthService.GenerateAccessToken(user)
	if err != nil {
		detailLog.AddField("Error", err.Error())
		summaryParam.Code = fmt.Sprintf("%d", http.StatusInternalServerError)
		summaryParam.Description = "server_error"
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Failed to generate access token"), map[string]any{
			"error": summaryParam.Description,
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": summaryParam.Description,
		})
		return
	}

	// Generate refresh token
	refreshToken, err := h.oauthService.GenerateRefreshToken()
	if err != nil {
		summaryParam.Code = fmt.Sprintf("%d", http.StatusInternalServerError)
		detailLog.AddField("Error", err.Error())
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Failed to generate refresh token"), map[string]any{
			"error": summaryParam.Description,
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": summaryParam.Description,
		})
		return
	}

	response := gin.H{
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
	}
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "User logged in successfully"), response)
	c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "refresh_token",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		summaryParam.Description = "invalid_request"
		summaryParam.Code = "400"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling token refresh"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Failed to bind request data"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	// Validate refresh token and generate new tokens
	token, err := h.oauthService.ValidateRefreshToken(req.RefreshToken, detailLog)
	if err != nil {
		summaryParam.Description = "invalid_grant"
		summaryParam.Code = "401"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Failed to validate refresh token"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    req,
			"error":   err.Error(),
		})
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid refresh token"), response)
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	// Generate new access token
	accessToken, err := h.oauthService.GenerateAccessToken(&token.User)
	if err != nil {
		detailLog.AddField("Error", err.Error())
		summaryParam.Code = fmt.Sprintf("%d", http.StatusInternalServerError)
		summaryParam.Description = "server_error"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Failed to generate access token"), response)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	response := map[string]any{
		"access_token":  accessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600, // 1 hour
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Token refreshed successfully"), response)

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "logout",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user logout"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
		"body":    string(body),
	})

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		summaryParam.Code = "400"
		summaryParam.Description = "no_authorization_header"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "No Authorization header provided"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	// Extract token from header
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		accessToken := authHeader[7:]
		// Revoke the token
		h.oauthService.RevokeToken(accessToken, detailLog)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// OAuth2 Authorization endpoint
func (h *AuthHandler) Authorize(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "logout",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()
	detailLog.Info(logger.NewInbound(summaryParam.Command, "Start handling OAuth2 authorization"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
	})
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		summaryParam.Code = "400"
		summaryParam.Description = "missing_required_parameters"
		detailLog.SetSummary(summaryParam)
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Failed to validate request parameters"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	if responseType != "code" {
		summaryParam.Code = "400"
		summaryParam.Description = "unsupported_response_type"
		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Unsupported response type"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}
	detailLog.SetSummary(summaryParam)

	// Validate redirect URI
	if err := h.oauthService.ValidateRedirectURI(clientID, redirectURI, detailLog); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// For demo purposes, we'll auto-approve the authorization
	// In a real implementation, you'd show an authorization page
	userID := uint(1) // This should come from the authenticated user

	// Generate authorization code
	authCode, err := h.oauthService.GenerateAuthorizationCode(userID, clientID, redirectURI, scope, detailLog)
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

	detailLog.Info(logger.NewOutbound(summaryParam.Command, "Authorization successful, redirecting"), map[string]any{
		"redirect_url": redirectURL,
	})
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
		summaryParam := logger.LogEventTag{
			Node:        "client",
			Command:     "token",
			Description: "success",
		}
		detailLog := mlog.Log(c)
		detailLog.Update("UseCase", summaryParam.Command)
		headers := c.Request.Header
		method := c.Request.Method
		path := c.Request.URL.Path
		query := c.Request.URL.Query()
		summaryParam.Code = "400"
		summaryParam.Description = "unsupported_grant_type"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling OAuth2 token request"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
		})

		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Unsupported grant type"), response)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
	}
}

func (h *AuthHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "token",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling authorization code grant"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
	})

	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")

	// Validate client credentials
	_, err := h.oauthService.ValidateClient(clientID, clientSecret, detailLog)
	if err != nil {
		response := map[string]string{
			"error": "invalid_client",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid client credentials"), response)

		c.JSON(http.StatusUnauthorized, response)
		return
	}

	// Validate authorization code
	authCode, err := h.oauthService.ValidateAuthorizationCode(code, clientID, redirectURI, detailLog)
	if err != nil {
		response := map[string]string{
			"error": "invalid_grant",
		}

		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid authorization code"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}

	// Create OAuth tokens
	token, err := h.oauthService.CreateOAuthToken(authCode.UserID, clientID, authCode.Scope, detailLog)
	if err != nil {
		response := map[string]string{
			"error": "server_error",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Failed to create OAuth tokens"), response)
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	response := TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    3600,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "Authorization code grant successful"), response)

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) handleRefreshTokenGrant(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "token",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling refresh token grant"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
	})

	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Validate client credentials
	_, err := h.oauthService.ValidateClient(clientID, clientSecret, detailLog)
	if err != nil {
		response := map[string]string{
			"error": "invalid_client",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid client credentials"), response)
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	// Validate refresh token and generate new tokens
	token, err := h.oauthService.ValidateRefreshToken(refreshToken, detailLog)
	if err != nil {
		response := map[string]string{
			"error": "invalid_grant",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid refresh token"), response)
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	response := TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    3600,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "Refresh token grant successful"), response)

	c.JSON(http.StatusOK, response)
}

// UserInfo returns user information (OAuth2 userinfo endpoint)
func (h *AuthHandler) UserInfo(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "userinfo",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	userID, exists := c.Get("user_id")
	if !exists {
		summaryParam.Code = "401"
		summaryParam.Description = "User not authenticated"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Start handling user info request"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
		})

		response := map[string]string{
			"error": summaryParam.Description,
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not authenticated"), response)
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	user, err := h.userService.GetUserByID(userID.(uint), detailLog)
	if err != nil {
		response := map[string]string{
			"error": "User not found",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not found"), response)
		c.JSON(http.StatusNotFound, response)
		return
	}

	response := map[string]any{
		"sub":        strconv.Itoa(int(user.ID)),
		"email":      user.Email,
		"username":   user.Username,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
	}

	detailLog.Info(logger.NewOutbound(summaryParam.Command, "User info retrieved successfully"), response)

	c.JSON(http.StatusOK, response)
}
