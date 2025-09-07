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
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "User not authenticated"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not authenticated"), response)
		c.JSON(http.StatusUnauthorized, response)
		return
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Fetching user profile"), map[string]any{
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
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not found"), response)
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
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "User profile fetched successfully"), response)
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
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "User not authenticated"), map[string]any{
			"headers": headers,
			"method":  method,
			"path":    path,
			"query":   query,
			"body":    string(body),
		})

		response := map[string]string{
			"error": "invalid_request",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not authenticated"), response)
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
		detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Invalid request data"), map[string]any{
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
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Invalid request data"), response)
		c.JSON(http.StatusBadRequest, response)
		return
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewOutbound(summaryParam.Command, "Updating user profile"), map[string]any{
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
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "User not found"), response)
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
			detailLog.Info(logger.NewOutbound(summaryParam.Command, "Username already taken"), response)
			c.JSON(http.StatusConflict, response)
			return
		}
		user.Username = req.Username
	}

	if err := h.userService.UpdateUser(user); err != nil {
		response := map[string]string{
			"error": "update_failed",
		}
		detailLog.Info(logger.NewOutbound(summaryParam.Command, "Failed to update user profile"), response)
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
	detailLog.Info(logger.NewOutbound(summaryParam.Command, "User profile updated successfully"), response)

	c.JSON(http.StatusOK, response)
}

// GetUsers returns all users (admin only)
func (h *UserHandler) GetUsers(c *gin.Context) {
	userRole, exists := c.Get("user_role")
	if !exists || (userRole != "admin") {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions",
		})
		return
	}

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

	users, err := h.userService.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch users",
		})
		return
	}

	// Simple pagination (in production, you'd do this at the database level)
	start := (page - 1) * limit
	end := start + limit

	if start >= len(users) {
		c.JSON(http.StatusOK, gin.H{
			"users":       []interface{}{},
			"total":       len(users),
			"page":        page,
			"limit":       limit,
			"total_pages": (len(users) + limit - 1) / limit,
		})
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

	c.JSON(http.StatusOK, gin.H{
		"users":       userResponses,
		"total":       len(users),
		"page":        page,
		"limit":       limit,
		"total_pages": (len(users) + limit - 1) / limit,
	})
}
