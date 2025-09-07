package services

import (
	"errors"
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
func (s *UserService) CreateUser(user *models.User) error {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// Create user in database
	result := s.db.Create(user)
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

	// SELECT * FROM `users` WHERE email = "test@example.com" AND `users`.`deleted_at` IS NULL ORDER BY `users`.`id` LIMIT 1
	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying user by email"), map[string]any{
		"sql":   "SELECT * FROM `users` WHERE email = ? AND `users`.`deleted_at` IS NULL ORDER BY `users`.`id` LIMIT 1",
		"params": []string{email},
	})
	var user models.User
	result := s.db.Where("email = ?", email).First(&user)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed with error"), map[string]any{
			"return": result,
		})
		return nil, result.Error
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "User query completed successfully"), map[string]any{
		"return": user,
	})

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	result := s.db.First(&user, id)
	if result.Error != nil {
		return nil, result.Error
	}
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
			"return": result,
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
func (s *UserService) UpdateUser(user *models.User) error {
	result := s.db.Save(user)
	return result.Error
}

// GetAllUsers retrieves all users (admin only)
func (s *UserService) GetAllUsers() ([]models.User, error) {
	var users []models.User
	result := s.db.Find(&users)
	return users, result.Error
}

// ValidateUser validates user credentials and returns the user if valid
func (s *UserService) ValidateUser(email, password string, detailLog logger.CustomLoggerService) (*models.User, error) {
	user, err := s.GetUserByEmail(email, detailLog)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	err = s.VerifyPassword(user.Password, password)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}
