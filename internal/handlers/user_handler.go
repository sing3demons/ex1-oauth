package handlers

import (
	"net/http"
	"oauth2-api/internal/logger"
	"oauth2-api/internal/mlog"
	"oauth2-api/internal/services"
	"strconv"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// GetProfile returns the current user's profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "get_profile",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	userID, exists := c.Get("user_id")
	if !exists {
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "User not authenticated"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Fetching user profile"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
		"body":    string(body),
	})

	user, err := h.userService.GetUserByID(userID.(uint), detailLog)
	if err != nil {
		response := map[string]string{
			"error": "data_not_found",
		}
		c.JSON(http.StatusNotFound, response)
		return
	}

	response := map[string]any{
		"id":         user.ID,
		"email":      user.Email,
		"username":   user.Username,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
		"is_active":  user.IsActive,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}
	c.JSON(http.StatusOK, response)
}

// UpdateProfile updates the current user's profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "update_profile",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	body, _ := cloneRequestBody(c.Request)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	userID, exists := c.Get("user_id")
	if !exists {
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "User not authenticated"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	type UpdateRequest struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Username  string `json:"username"`
	}

	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Invalid request data"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
			"error":   err.Error(),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		c.JSON(http.StatusBadRequest, response)
		return
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Updating user profile"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
		"body":    req,
	})

	user, err := h.userService.GetUserByID(userID.(uint), detailLog)
	if err != nil {
		response := map[string]string{
			"error": "data_not_found",
		}
		c.JSON(http.StatusNotFound, response)
		return
	}

	// Update fields if provided
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Username != "" {
		// Check if username is already taken by another user
		existingUser, err := h.userService.GetUserByUsername(req.Username, detailLog)
		if err == nil && existingUser.ID != user.ID {
			response := map[string]string{
				"error": "username_taken",
			}
			c.JSON(http.StatusConflict, response)
			return
		}
		user.Username = req.Username
	}

	if err := h.userService.UpdateUser(user, detailLog); err != nil {
		response := map[string]string{
			"error": "update_failed",
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	response := map[string]any{
		"message": "Profile updated successfully",
		"user": map[string]any{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"updated_at": user.UpdatedAt,
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetUsers returns all users (admin only)
func (h *UserHandler) GetUsers(c *gin.Context) {
	summaryParam := logger.LogEventTag{
		Node:        "client",
		Command:     "get_users",
		Description: "success",
	}
	detailLog := mlog.Log(c)
	detailLog.Update("UseCase", summaryParam.Command)
	headers := c.Request.Header
	method := c.Request.Method
	path := c.Request.URL.Path
	query := c.Request.URL.Query()

	userRole, exists := c.Get("user_role")
	if !exists || (userRole != "admin") {
		summaryParam.Code = "403"
		summaryParam.Description = "insufficient_permissions"
		detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Insufficient permissions"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
		})

		response := map[string]string{
			"error": "insufficient_permissions",
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewInbound(summaryParam.Command, "Fetching all users"), map[string]any{
		"headers": headers,
		"method":  method,
		"path":    path,
		"query":   query,
	})

	// Parse query parameters for pagination
	page := 1
	limit := 10

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	users, err := h.userService.GetAllUsers(detailLog)
	if err != nil {
		response := map[string]string{
			"error": "failed_to_fetch_users",
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	// Simple pagination (in production, you'd do this at the database level)
	start := (page - 1) * limit
	end := start + limit

	if start >= len(users) {
		response := map[string]any{
			"users":       []interface{}{},
			"total":       len(users),
			"page":        page,
			"limit":       limit,
			"total_pages": (len(users) + limit - 1) / limit,
		}
		c.JSON(http.StatusOK, response)
		return
	}

	if end > len(users) {
		end = len(users)
	}

	paginatedUsers := users[start:end]

	// Convert to response format (excluding sensitive data)
	var userResponses []gin.H
	for _, user := range paginatedUsers {
		userResponses = append(userResponses, gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		})
	}
	response := map[string]any{
		"users":       userResponses,
		"total":       len(users),
		"page":        page,
		"limit":       limit,
		"total_pages": (len(users) + limit - 1) / limit,
	}
	c.JSON(http.StatusOK, response)
}
