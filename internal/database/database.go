package database

import (
	"oauth2-api/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Initialize creates and returns a database connection
func Initialize(databaseURL string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(databaseURL), &gorm.Config{})
	if err != nil {
		return nil, err
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
