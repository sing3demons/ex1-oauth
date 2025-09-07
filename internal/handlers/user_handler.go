package handlers

import (
	"net/http"
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

// UpdateProfile updates the current user's profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	type UpdateRequest struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Username  string `json:"username"`
	}

	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
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

	// Update fields if provided
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Username != "" {
		// Check if username is already taken by another user
		existingUser, err := h.userService.GetUserByUsername(req.Username)
		if err == nil && existingUser.ID != user.ID {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Username already taken",
			})
			return
		}
		user.Username = req.Username
	}

	if err := h.userService.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update profile",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"updated_at": user.UpdatedAt,
		},
	})
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
