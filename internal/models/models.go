package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Email     string         `json:"email" gorm:"uniqueIndex;not null"`
	Username  string         `json:"username" gorm:"uniqueIndex;not null"`
	Password  string         `json:"-" gorm:"column:password_hash;not null"` // Hidden from JSON
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Role      string         `json:"role" gorm:"default:user"` // user, admin
	IsActive  bool           `json:"is_active" gorm:"default:true"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// OAuthClient represents an OAuth2 client application
type OAuthClient struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	Secret       string    `json:"-" gorm:"not null"`
	Name         string    `json:"name" gorm:"not null"`
	RedirectURIs string    `json:"redirect_uris"` // JSON array stored as string
	Scopes       string    `json:"scopes"`        // Space-separated scopes
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OAuthToken represents OAuth2 tokens
type OAuthToken struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	UserID       uint      `json:"user_id" gorm:"not null"`
	ClientID     string    `json:"client_id" gorm:"not null"`
	AccessToken  string    `json:"access_token" gorm:"uniqueIndex;not null"`
	RefreshToken string    `json:"refresh_token" gorm:"uniqueIndex"`
	TokenType    string    `json:"token_type" gorm:"default:Bearer"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships
	User   User        `json:"user" gorm:"foreignKey:UserID"`
	Client OAuthClient `json:"client" gorm:"foreignKey:ClientID"`
}

// AuthorizationCode represents OAuth2 authorization codes
type AuthorizationCode struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Code        string    `json:"code" gorm:"uniqueIndex;not null"`
	UserID      uint      `json:"user_id" gorm:"not null"`
	ClientID    string    `json:"client_id" gorm:"not null"`
	RedirectURI string    `json:"redirect_uri" gorm:"not null"`
	Scope       string    `json:"scope"`
	ExpiresAt   time.Time `json:"expires_at"`
	Used        bool      `json:"used" gorm:"default:false"`
	CreatedAt   time.Time `json:"created_at"`

	// Relationships
	User   User        `json:"user" gorm:"foreignKey:UserID"`
	Client OAuthClient `json:"client" gorm:"foreignKey:ClientID"`
}

// TableName methods for custom table names
func (User) TableName() string {
	return "users"
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}

func (OAuthToken) TableName() string {
	return "oauth_tokens"
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}
