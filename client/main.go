package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// Constants for routes and templates
const (
	RouteLogin    = "/login"
	RouteCallback = "/callback"
	RouteProfile  = "/profile"
	RouteLogout   = "/logout"

	TemplateIndex   = "index.html"
	TemplateProfile = "profile.html"
	TemplateError   = "error.html"
)

// OAuthClient represents our OAuth2 client configuration
type OAuthClient struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ServerURL    string
	accessToken  string
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// UserInfo represents user information from the OAuth2 server
type UserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	serverHost := os.Getenv("OAUTH2_SERVER_HOST")
	if serverHost == "" {
		serverHost = "http://localhost:8080"
	}

	clientHost := os.Getenv("OAUTH2_CLIENT_HOST")
	if clientHost == "" {
		clientHost = "http://localhost:3000"
	}
	// Initialize OAuth client with configuration
	client := &OAuthClient{
		ClientID:     "test-client-id",     // ต้องตรงกับที่ตั้งค่าใน OAuth server
		ClientSecret: "test-client-secret", // ต้องตรงกับที่ตั้งค่าใน OAuth server
		RedirectURL:  clientHost + "/callback",
		ServerURL:    serverHost, // OAuth server URL
	}

	// Setup Gin router
	router := gin.Default()

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	// Routes
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, TemplateIndex, gin.H{
			"title": "OAuth2 Client Demo",
		})
	})

	router.GET(RouteLogin, client.initiateOAuth)
	router.GET(RouteCallback, client.handleCallback)
	router.GET(RouteProfile, client.showProfile)
	router.POST(RouteLogout, client.logout)

	fmt.Println("🚀 OAuth2 Client กำลังทำงานที่ http://localhost:3000")
	fmt.Println("📝 ตรวจสอบให้แน่ใจว่า OAuth2 Server ทำงานอยู่ที่ http://localhost:8080")
	log.Fatal(router.Run(":3000"))
}

// initiateOAuth เริ่มต้นกระบวนการ OAuth2 authorization
func (c *OAuthClient) initiateOAuth(ctx *gin.Context) {
	// Generate state parameter for security
	state, err := generateState()
	if err != nil {
		ctx.HTML(http.StatusInternalServerError, TemplateError, gin.H{
			"error": "ไม่สามารถสร้าง state parameter ได้",
		})
		return
	}

	// Build authorization URL
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", c.ClientID)
	params.Add("redirect_uri", c.RedirectURL)
	params.Add("scope", "read")
	params.Add("state", state)

	authURL := fmt.Sprintf("%s/oauth/authorize?%s", c.ServerURL, params.Encode())

	// Store state in cookie for verification
	ctx.SetCookie("oauth_state", state, 600, "/", "", false, true)

	fmt.Printf("🔄 เริ่มต้น OAuth2 flow - redirect ไปยัง: %s\n", authURL)
	ctx.Redirect(http.StatusFound, authURL)
}

// handleCallback จัดการ callback จาก OAuth2 server
func (c *OAuthClient) handleCallback(ctx *gin.Context) {
	// Get authorization code and state from query parameters
	code := ctx.Query("code")
	state := ctx.Query("state")
	errorParam := ctx.Query("error")

	// Check for OAuth2 errors
	if errorParam != "" {
		errorDesc := ctx.Query("error_description")
		ctx.HTML(http.StatusBadRequest, TemplateError, gin.H{
			"error": fmt.Sprintf("OAuth2 Error: %s - %s", errorParam, errorDesc),
		})
		return
	}

	// Verify state parameter to prevent CSRF attacks
	storedState, err := ctx.Cookie("oauth_state")
	if err != nil || state != storedState {
		ctx.HTML(http.StatusBadRequest, TemplateError, gin.H{
			"error": "State parameter ไม่ถูกต้อง (อาจเป็น CSRF attack)",
		})
		return
	}

	if code == "" {
		ctx.HTML(http.StatusBadRequest, TemplateError, gin.H{
			"error": "ไม่ได้รับ authorization code จาก OAuth2 server",
		})
		return
	}

	fmt.Printf("✅ ได้รับ authorization code: %s\n", code[:10]+"...")

	// Exchange authorization code for access token
	token, err := c.exchangeCodeForToken(code)
	if err != nil {
		ctx.HTML(http.StatusBadRequest, TemplateError, gin.H{
			"error": fmt.Sprintf("การแลกเปลี่ยน token ล้มเหลว: %v", err),
		})
		return
	}

	// Store access token
	c.accessToken = token

	// Clear state cookie
	ctx.SetCookie("oauth_state", "", -1, "/", "", false, true)

	fmt.Printf("🎉 ได้รับ access token สำเร็จ: %s\n", token[:20]+"...")

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": token,
	})

	// Redirect to profile page
	// ctx.Redirect(http.StatusFound, RouteProfile)
}

// exchangeCodeForToken แลกเปลี่ยน authorization code เป็น access token
func (c *OAuthClient) exchangeCodeForToken(code string) (string, error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", c.ServerURL)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.RedirectURL)
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.ClientSecret)

	fmt.Printf("🔄 ส่งคำขอ token ไปยัง: %s\n", tokenURL)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("ไม่สามารถส่งคำขอ token ได้: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("คำขอ token ล้มเหลว status code: %d", resp.StatusCode)
	}

	// Parse token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("ไม่สามารถ parse token response ได้: %v", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("token error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return tokenResp.AccessToken, nil
}

// showProfile แสดงข้อมูลโปรไฟล์ผู้ใช้
func (c *OAuthClient) showProfile(ctx *gin.Context) {
	if c.accessToken == "" {
		ctx.Redirect(http.StatusFound, RouteLogin)
		return
	}

	// Get user info from OAuth2 server
	userURL := fmt.Sprintf("%s/oauth/profile", c.ServerURL)
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		ctx.HTML(http.StatusInternalServerError, TemplateError, gin.H{
			"error": "ไม่สามารถสร้างคำขอได้",
		})
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	fmt.Printf("🔄 ขอข้อมูลผู้ใช้จาก: %s\n", userURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		ctx.HTML(http.StatusInternalServerError, TemplateError, gin.H{
			"error": "ไม่สามารถขอข้อมูลผู้ใช้ได้",
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Token expired or invalid
		c.accessToken = ""
		ctx.Redirect(http.StatusFound, RouteLogin)
		return
	}

	if resp.StatusCode != http.StatusOK {
		ctx.HTML(http.StatusInternalServerError, TemplateError, gin.H{
			"error": fmt.Sprintf("ไม่สามารถขอข้อมูลผู้ใช้ได้ status: %d", resp.StatusCode),
		})
		return
	}

	var user UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		ctx.HTML(http.StatusInternalServerError, TemplateError, gin.H{
			"error": "ไม่สามารถ parse ข้อมูลผู้ใช้ได้",
		})
		return
	}

	fmt.Printf("👤 ได้รับข้อมูลผู้ใช้: %s (%s)\n", user.Username, user.Email)

	ctx.HTML(http.StatusOK, TemplateProfile, gin.H{
		"user": user,
	})
}

// logout ออกจากระบบ
func (c *OAuthClient) logout(ctx *gin.Context) {
	c.accessToken = ""
	fmt.Println("🚪 ผู้ใช้ออกจากระบบ")
	ctx.Redirect(http.StatusFound, "/")
}

// generateState สร้าง random state parameter สำหรับป้องกัน CSRF
func generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
