package database

import (
	"fmt"
	"oauth2-api/internal/models"
	"os"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Initialize creates and returns a database connection
func Initialize(databaseURL string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	// Determine database type from URL or environment
	dbType := os.Getenv("DB_TYPE")
	if dbType == "" {
		// Auto-detect from URL
		if strings.Contains(databaseURL, "postgres://") {
			dbType = "postgres"
		} else {
			dbType = "sqlite"
		}
	}

	// Connect based on database type
	switch dbType {
	case "postgres":
		db, err = gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
		}
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(databaseURL), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SQLite: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(
		&models.User{},
		&models.OAuthClient{},
		&models.OAuthToken{},
		&models.AuthorizationCode{},
	)
	if err != nil {
		return nil, err
	}

	// Seed default OAuth client for testing
	seedDefaultClient(db)

	return db, nil
}

// seedDefaultClient creates a default OAuth client for testing
func seedDefaultClient(db *gorm.DB) {
	var count int64
	db.Model(&models.OAuthClient{}).Count(&count)

	if count == 0 {
		defaultClient := &models.OAuthClient{
			ID:           "test-client-id",
			Secret:       "test-client-secret",
			Name:         "Test OAuth Client",
			RedirectURIs: `["http://localhost:3000/callback", "http://localhost:8080/callback"]`,
			Scopes:       "read write",
		}
		db.Create(defaultClient)
	}
}
