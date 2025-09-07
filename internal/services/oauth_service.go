package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"oauth2-api/internal/logger"
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
func (s *OAuthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI, scope string, detailLog logger.CustomLoggerService) (*models.AuthorizationCode, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "create_authorization_code",
		Code:        "200",
		Description: "success",
	}

	code := uuid.New().String()
	detailLog.Info(logger.NewDBRequest(logger.INSERT, "Inserting new authorization code into database"), map[string]any{
		"SQL":    "INSERT INTO `authorization_codes` (`code`, `user_id`, `client_id`, `redirect_uri`, `scope`, `expires_at`, `used`) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"Params": []any{code, userID, clientID, redirectURI, scope, time.Now().Add(10 * time.Minute), false},
	})

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
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.INSERT, "Authorization code creation failed"), map[string]any{
			"SQL":    result.Statement.SQL.String(),
			"Params": result.Statement.Vars,
			"Error":  result.Error.Error(),
		})
		return nil, result.Error
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.INSERT, "Authorization code creation completed"), map[string]any{
		"SQL":    result.Statement.SQL.String(),
		"Params": result.Statement.Vars,
		"return": authCode,
	})

	return authCode, nil
}

// ValidateAuthorizationCode validates and marks an authorization code as used
func (s *OAuthService) ValidateAuthorizationCode(code, clientID, redirectURI string, detailLog logger.CustomLoggerService) (*models.AuthorizationCode, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_authorization_code",
		Code:        "200",
		Description: "success",
	}
	var authCode models.AuthorizationCode
	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying authorization code by code, client ID, and redirect URI"), map[string]any{
		"sql":    "SELECT * FROM `authorization_codes` WHERE code = ? AND client_id = ? AND redirect_uri = ? AND used = ? AND expires_at > ? AND `authorization_codes`.`deleted_at` IS NULL ORDER BY `authorization_codes`.`id` LIMIT 1",
		"params": []any{code, clientID, redirectURI, false, time.Now()},
	})

	result := s.db.Where("code = ? AND client_id = ? AND redirect_uri = ? AND used = ? AND expires_at > ?",
		code, clientID, redirectURI, false, time.Now()).First(&authCode)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "Authorization code query completed with error"), map[string]any{
			"SQL":    result.Statement.SQL.String(),
			"Params": result.Statement.Vars,
			"Error":  result.Error.Error(),
		})
		return nil, errors.New("invalid or expired authorization code")
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "Authorization code query completed successfully"), map[string]any{
		"SQL":    result.Statement.SQL.String(),
		"Params": result.Statement.Vars,
		"return": authCode,
	})

	start = time.Now()
	summaryParam = logger.LogEventTag{
		Node:        "gorm",
		Command:     "update_authorization_code",
		Code:        "200",
		Description: "success",
	}

	// Mark as used
	authCode.Used = true
	detailLog.Info(logger.NewDBRequest(logger.UPDATE, "Marking authorization code as used"), map[string]any{
		"SQL":    "UPDATE `authorization_codes` SET `used`=? WHERE `id` = ?",
		"Params": []any{authCode.ID},
	})
	r := s.db.Save(&authCode)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if r.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = r.Error.Error()
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.UPDATE, "Authorization code update completed"), map[string]any{
		"SQL":    r.Statement.SQL.String(),
		"Params": r.Statement.Vars,
		"return": authCode,
	})

	return &authCode, nil
}

// CreateOAuthToken creates and stores OAuth tokens
func (s *OAuthService) CreateOAuthToken(userID uint, clientID, scope string, detailLog logger.CustomLoggerService) (*models.OAuthToken, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "create_oauth_token",
		Code:        "200",
		Description: "success",
	}
	accessToken, err := s.generateRandomToken()
	if err != nil {
		detailLog.AddField("Error", err.Error())
		return nil, err
	}

	refreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		detailLog.AddField("Error", err.Error())
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

	detailLog.Info(logger.NewDBRequest(logger.INSERT, "Inserting new OAuth token into database"), map[string]any{
		"sql":    "INSERT INTO `oauth_tokens` (`user_id`,`client_id`,`access_token`,`refresh_token`,`token_type`,`scope`,`expires_at`,`created_at`) VALUES (?,?,?,?,?,?,?,?)",
		"params": oauthToken,
	})

	result := s.db.Create(oauthToken)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.INSERT, "OAuth token creation failed"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, result.Error
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.INSERT, "OAuth token created successfully"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
		"return":       oauthToken,
	})
	return oauthToken, nil
}

// ValidateAccessToken validates an OAuth access token
func (s *OAuthService) ValidateAccessToken(accessToken string, detailLog logger.CustomLoggerService) (*models.OAuthToken, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_oauth_token",
		Code:        "200",
		Description: "success",
	}
	var token models.OAuthToken

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying OAuth token by access token"), map[string]any{
		"sql":    "SELECT * FROM `oauth_tokens` WHERE access_token = ? AND expires_at > ? AND `oauth_tokens`.`deleted_at` IS NULL ORDER BY `oauth_tokens`.`id` LIMIT 1",
		"params": []string{accessToken, time.Now().String()},
	})

	result := s.db.Where("access_token = ? AND expires_at > ?", accessToken, time.Now()).
		Preload("User").First(&token)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth token query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, errors.New("invalid or expired access token")
	}

	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth token query completed successfully"), map[string]any{
		"return": token,
	})

	return &token, nil
}

// ValidateRefreshToken validates a refresh token and creates new tokens
func (s *OAuthService) ValidateRefreshToken(refreshToken string, detailLog logger.CustomLoggerService) (*models.OAuthToken, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_oauth_token",
		Code:        "200",
		Description: "success",
	}
	var token models.OAuthToken

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying OAuth token by refresh token"), map[string]any{
		"sql":    "SELECT * FROM `oauth_tokens` WHERE refresh_token = ? AND `oauth_tokens`.`deleted_at` IS NULL ORDER BY `oauth_tokens`.`id` LIMIT 1",
		"params": []string{refreshToken},
	})
	result := s.db.Where("refresh_token = ?", refreshToken).Preload("User").First(&token)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth token query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, errors.New("invalid refresh token")
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth token query completed successfully"), map[string]any{
		"return": token,
	})

	// Generate new tokens
	newAccessToken, err := s.generateRandomToken()
	if err != nil {
		detailLog.AddField("Error", err.Error())
		return nil, err
	}

	newRefreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		detailLog.AddField("Error", err.Error())
		return nil, err
	}

	// Update the token
	token.AccessToken = newAccessToken
	token.RefreshToken = newRefreshToken
	token.ExpiresAt = time.Now().Add(1 * time.Hour)

	summaryParamSave := logger.LogEventTag{
		Node:        "gorm",
		Command:     "update_oauth_token",
		Code:        "200",
		Description: "success",
	}
	detailLog.Info(logger.NewDBRequest(logger.UPDATE, "Updating OAuth token with new access and refresh tokens"), map[string]any{
		"sql":    "UPDATE `oauth_tokens` SET `access_token`=?,`refresh_token`=?,`expires_at`=? WHERE `id` = ?",
		"params": []string{token.AccessToken, token.RefreshToken, token.ExpiresAt.String(), fmt.Sprintf("%d", token.ID)},
	})

	result = s.db.Save(&token)
	summaryParamSave.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParamSave.Code = "500"
		summaryParamSave.Description = result.Error.Error()
		detailLog.SetSummary(summaryParamSave).Info(logger.NewDBResponse(logger.UPDATE, "OAuth token update failed"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, result.Error
	}

	detailLog.SetSummary(summaryParamSave).Info(logger.NewDBResponse(logger.UPDATE, "OAuth token updated successfully"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
		"return":       token,
	})

	return &token, nil
}

// ValidateClient validates OAuth client credentials
func (s *OAuthService) ValidateClient(clientID, clientSecret string, detailLog logger.CustomLoggerService) (*models.OAuthClient, error) {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_oauth_client",
		Code:        "200",
		Description: "success",
	}
	var client models.OAuthClient
	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying OAuth client by ID and Secret"), map[string]any{
		"sql":    "SELECT * FROM `oauth_clients` WHERE id = ? AND secret = ? AND `oauth_clients`.`deleted_at` IS NULL ORDER BY `oauth_clients`.`id` LIMIT 1",
		"params": []string{clientID, clientSecret},
	})
	result := s.db.Where("id = ? AND secret = ?", clientID, clientSecret).First(&client)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth client query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return nil, errors.New("invalid client credentials")
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth client query completed successfully"), map[string]any{
		"return": client,
	})

	return &client, nil
}

// ValidateRedirectURI validates if the redirect URI is allowed for the client
func (s *OAuthService) ValidateRedirectURI(clientID, redirectURI string, detailLog logger.CustomLoggerService) error {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "find_oauth_client",
		Code:        "200",
		Description: "success",
	}

	detailLog.Info(logger.NewDBRequest(logger.QUERY, "Querying OAuth client by ID"), map[string]any{
		"sql":    "SELECT * FROM `oauth_clients` WHERE id = ? AND `oauth_clients`.`deleted_at` IS NULL ORDER BY `oauth_clients`.`id` LIMIT 1",
		"params": []string{clientID},
	})
	var client models.OAuthClient
	result := s.db.Where("id = ?", clientID).First(&client)
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "404"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth client query completed with error"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return errors.New("client not found")
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.QUERY, "OAuth client query completed successfully"), map[string]any{
		"return": client,
	})

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
func (s *OAuthService) RevokeToken(accessToken string, detailLog logger.CustomLoggerService) error {
	start := time.Now()
	summaryParam := logger.LogEventTag{
		Node:        "gorm",
		Command:     "delete_oauth_token",
		Code:        "200",
		Description: "success",
	}
	detailLog.Info(logger.NewDBRequest(logger.DELETE, "Revoking access token"), map[string]any{
		"sql":    "DELETE FROM `oauth_tokens` WHERE access_token = ?",
		"params": []string{accessToken},
	})

	result := s.db.Where("access_token = ?", accessToken).Delete(&models.OAuthToken{})
	summaryParam.ResTime = time.Since(start).Milliseconds()
	if result.Error != nil {
		summaryParam.Code = "500"
		summaryParam.Description = result.Error.Error()
		detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.DELETE, "OAuth token revocation failed"), map[string]any{
			"RowsAffected": result.RowsAffected,
			"SQL":          result.Statement.SQL.String(),
			"Var":          result.Statement.Vars,
			"Error":        result.Error.Error(),
		})
		return result.Error
	}
	detailLog.SetSummary(summaryParam).Info(logger.NewDBResponse(logger.DELETE, "OAuth token revoked successfully"), map[string]any{
		"RowsAffected": result.RowsAffected,
		"SQL":          result.Statement.SQL.String(),
		"Var":          result.Statement.Vars,
	})
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
