package services

import (
	"errors"
	"fmt"
	"oauth2-api/internal/logger"
	"oauth2-api/internal/models"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	db *gorm.DB
}

func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// CreateUser creates a new user with hashed password
func (s *UserService) CreateUser(user *models.User, detailLog logger.CustomLoggerService) error {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "create_user",
		Code:        "200",
		Description: "success",
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		detailLog.AddField("Error", err.Error())
		return err
	}
	user.Password = string(hashedPassword)
	detailLog.Info(logger.NewDBRequest(logger.INSERT, "Creating new user"), map[string]any{
		"sql":    "INSERT INTO `users` (`username`,`email`,`password`,`is_active`,`created_at`,`updated_at`) VALUES (?,?,?,?,?,?)",
		"params": []string{user.Username, user.Email, "****", fmt.Sprintf("%t", user.IsActive), user.CreatedAt.String(), user.UpdatedAt.String()},
	})
	// Create user in database
	result := s.db.Create(user)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.INSERT, "User creation completed"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
		"Error": func() string {
			if result.Error != nil {
				return result.Error.Error()
			} else {
				return ""
			}
		}(),
	})
	return result.Error
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(email string, detailLog logger.CustomLoggerService) (*models.User, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_user_by_email",
		Code:        "200",
		Description: "success",
	}

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying user by email"), map[string]any{
		"sql":    "SELECT * FROM `users` WHERE email = ? AND `users`.`deleted_at` IS NULL ORDER BY `users`.`id` LIMIT 1",
		"params": []string{email},
	})
	var user models.User
	result := s.db.Where("email = ?", email).First(&user)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, result.Error
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed successfully"),
		map[string]any{
			"return": user,
		})

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(id uint, detailLog logger.CustomLoggerService) (*models.User, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_user_by_id",
		Code:        "200",
		Description: "success",
	}

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying user by ID"), map[string]any{
		"sql":    "SELECT * FROM `users` WHERE id = ? AND `users`.`deleted_at` IS NULL ORDER BY `users`.`id` LIMIT 1",
		"params": []string{fmt.Sprintf("%d", id)},
	})
	var user models.User
	result := s.db.First(&user, id)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, result.Error
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed successfully"), map[string]any{
		"return": user,
	})
	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string, detailLog logger.CustomLoggerService) (*models.User, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_user_by_user",
		Code:        "200",
		Description: "success",
	}

	var user models.User
	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying user by username"), map[string]any{
		"sql":    "SELECT * FROM `users` WHERE username = ? AND `users`.`deleted_at` IS NULL ORDER BY `users`.`id` LIMIT 1",
		"params": []string{username},
	})
	result := s.db.Where("username = ?", username).First(&user)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, result.Error
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed successfully"), map[string]any{
		"return": user,
	})

	return &user, nil
}

// VerifyPassword verifies if the provided password matches the user's password
func (s *UserService) VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(user *models.User, detailLog logger.CustomLoggerService) error {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "update_user",
		Code:        "200",
		Description: "success",
	}
	detailLog.Info(logger.NewDBRequest(logger.UPDATE, "Updating user information"), map[string]any{
		"sql":    "UPDATE `users` SET `username`=?,`email`=?,`password`=?,`is_active`=?,`created_at`=?,`updated_at`=? WHERE `id` = ?",
		"params": []string{user.Username, user.Email, "****", fmt.Sprintf("%t", user.IsActive), user.CreatedAt.String(), user.UpdatedAt.String(), fmt.Sprintf("%d", user.ID)},
	})
	result := s.db.Save(user)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.UPDATE, "User update completed"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
		"Error": func() string {
			if result.Error != nil {
				return result.Error.Error()
			} else {
				return ""
			}
		}(),
	})
	return result.Error
}

// GetAllUsers retrieves all users (admin only)
func (s *UserService) GetAllUsers(detailLog logger.CustomLoggerService) ([]models.User, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_all_users",
		Code:        "200",
		Description: "success",
	}

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying all users"), map[string]any{
		"sql":    "SELECT * FROM `users` WHERE `users`.`deleted_at` IS NULL",
		"params": []string{},
	})
	var users []models.User
	result := s.db.Find(&users)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "All users query completed"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
		"Error": func() string {
			if result.Error != nil {
				return result.Error.Error()
			} else {
				return ""
			}
		}(),
	})
	return users, result.Error
}

// ValidateUser validates user credentials and returns the user if valid
func (s *UserService) ValidateUser(email, password string, detailLog logger.CustomLoggerService) (*models.User, error) {
	user, err := s.GetUserByEmail(email, detailLog)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		detailLog.AddField("Error", "account is deactivated")
		return nil, errors.New("account is deactivated")
	}

	err = s.VerifyPassword(user.Password, password)
	if err != nil {
		detailLog.AddField("Error", "invalid credentials")
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}
