package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"oauth2-api/internal/models"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type OAuthService struct {
	db        *gorm.DB
	jwtSecret string
}

type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func NewOAuthService(db *gorm.DB, jwtSecret string) *OAuthService {
	return &OAuthService{
		db:        db,
		jwtSecret: jwtSecret,
	}
}

// GenerateAccessToken generates a JWT access token
func (s *OAuthService) GenerateAccessToken(user *models.User) (string, error) {
	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", user.ID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

// GenerateRefreshToken generates a refresh token
func (s *OAuthService) GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAuthorizationCode generates an authorization code for OAuth2 flow
func (s *OAuthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI, scope string) (*models.AuthorizationCode, error) {
	code := uuid.New().String()

	authCode := &models.AuthorizationCode{
		Code:        code,
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute), // 10 minutes expiry
		Used:        false,
	}

	result := s.db.Create(authCode)
	if result.Error != nil {
		return nil, result.Error
	}

	return authCode, nil
}

// ValidateAuthorizationCode validates and marks an authorization code as used
func (s *OAuthService) ValidateAuthorizationCode(code, clientID, redirectURI string) (*models.AuthorizationCode, error) {
	var authCode models.AuthorizationCode

	result := s.db.Where("code = ? AND client_id = ? AND redirect_uri = ? AND used = ? AND expires_at > ?",
		code, clientID, redirectURI, false, time.Now()).First(&authCode)

	if result.Error != nil {
		return nil, errors.New("invalid or expired authorization code")
	}

	// Mark as used
	authCode.Used = true
	s.db.Save(&authCode)

	return &authCode, nil
}

// CreateOAuthToken creates and stores OAuth tokens
func (s *OAuthService) CreateOAuthToken(userID uint, clientID, scope string) (*models.OAuthToken, error) {
	accessToken, err := s.generateRandomToken()
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	oauthToken := &models.OAuthToken{
		UserID:       userID,
		ClientID:     clientID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Scope:        scope,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}

	result := s.db.Create(oauthToken)
	if result.Error != nil {
		return nil, result.Error
	}

	return oauthToken, nil
}

// ValidateAccessToken validates an OAuth access token
func (s *OAuthService) ValidateAccessToken(accessToken string) (*models.OAuthToken, error) {
	var token models.OAuthToken

	result := s.db.Where("access_token = ? AND expires_at > ?", accessToken, time.Now()).
		Preload("User").First(&token)

	if result.Error != nil {
		return nil, errors.New("invalid or expired access token")
	}

	return &token, nil
}

// ValidateRefreshToken validates a refresh token and creates new tokens
func (s *OAuthService) ValidateRefreshToken(refreshToken string) (*models.OAuthToken, error) {
	var token models.OAuthToken

	result := s.db.Where("refresh_token = ?", refreshToken).Preload("User").First(&token)
	if result.Error != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Generate new tokens
	newAccessToken, err := s.generateRandomToken()
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Update the token
	token.AccessToken = newAccessToken
	token.RefreshToken = newRefreshToken
	token.ExpiresAt = time.Now().Add(1 * time.Hour)

	result = s.db.Save(&token)
	if result.Error != nil {
		return nil, result.Error
	}

	return &token, nil
}

// ValidateClient validates OAuth client credentials
func (s *OAuthService) ValidateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	var client models.OAuthClient

	result := s.db.Where("id = ? AND secret = ?", clientID, clientSecret).First(&client)
	if result.Error != nil {
		return nil, errors.New("invalid client credentials")
	}

	return &client, nil
}

// ValidateRedirectURI validates if the redirect URI is allowed for the client
func (s *OAuthService) ValidateRedirectURI(clientID, redirectURI string) error {
	var client models.OAuthClient

	result := s.db.Where("id = ?", clientID).First(&client)
	if result.Error != nil {
		return errors.New("client not found")
	}

	re := regexp.MustCompile(redirectURI)

	// Simple validation - check if redirect URI is in the allowed URIs
	// In production, you'd want more sophisticated URI validation
	allowedURIs := strings.Split(strings.Trim(client.RedirectURIs, "[]\""), "\",\"")
	for _, uri := range allowedURIs {
		match := re.FindString(uri)

		uri = strings.Trim(uri, "\" ")
		if uri == redirectURI {
			return nil
		}

		if match == redirectURI {
			return nil
		}
	}

	return errors.New("invalid redirect URI")
}

// RevokeToken revokes an access token
func (s *OAuthService) RevokeToken(accessToken string) error {
	result := s.db.Where("access_token = ?", accessToken).Delete(&models.OAuthToken{})
	return result.Error
}

// generateRandomToken generates a random token for access tokens
func (s *OAuthService) generateRandomToken() (string, error) {
	bytes := make([]byte, 48) // Different size for access tokens
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "at_" + base64.URLEncoding.EncodeToString(bytes), nil // Different prefix
}
