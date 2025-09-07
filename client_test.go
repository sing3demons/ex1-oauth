package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "http://localhost:8080/api/v1"

func main2() {
	fmt.Println("=== OAuth2 API Client Test ===")

	// Wait a moment for server to be ready
	time.Sleep(2 * time.Second)

	// Test 1: Register a user
	fmt.Println("\n1. Testing user registration...")
	registerData := map[string]interface{}{
		"email":      "demo@example.com",
		"username":   "demouser",
		"password":   "demo123456",
		"first_name": "Demo",
		"last_name":  "User",
	}

	registerResp, err := makeRequest("POST", baseURL+"/auth/register", registerData, "")
	if err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}
	fmt.Printf("Registration response: %s\n", registerResp)

	// Test 2: Login
	fmt.Println("\n2. Testing user login...")
	loginData := map[string]interface{}{
		"email":    "demo@example.com",
		"password": "demo123456",
	}

	loginResp, err := makeRequest("POST", baseURL+"/auth/login", loginData, "")
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}
	fmt.Printf("Login response: %s\n", loginResp)

	// Extract access token
	var loginResult map[string]interface{}
	json.Unmarshal([]byte(loginResp), &loginResult)
	accessToken, ok := loginResult["access_token"].(string)
	if !ok {
		fmt.Println("Failed to extract access token")
		return
	}

	// Test 3: Get profile
	fmt.Println("\n3. Testing protected endpoint - get profile...")
	profileResp, err := makeRequest("GET", baseURL+"/profile", nil, accessToken)
	if err != nil {
		fmt.Printf("Get profile failed: %v\n", err)
		return
	}
	fmt.Printf("Profile response: %s\n", profileResp)

	// Test 4: Update profile
	fmt.Println("\n4. Testing profile update...")
	updateData := map[string]interface{}{
		"first_name": "Updated Demo",
		"last_name":  "Updated User",
	}

	updateResp, err := makeRequest("PUT", baseURL+"/profile", updateData, accessToken)
	if err != nil {
		fmt.Printf("Update profile failed: %v\n", err)
		return
	}
	fmt.Printf("Update response: %s\n", updateResp)

	// Test 5: OAuth userinfo endpoint
	fmt.Println("\n5. Testing OAuth userinfo endpoint...")
	userinfoResp, err := makeRequest("GET", baseURL+"/oauth/userinfo", nil, accessToken)
	if err != nil {
		fmt.Printf("Userinfo failed: %v\n", err)
		return
	}
	fmt.Printf("Userinfo response: %s\n", userinfoResp)

	fmt.Println("\n=== All tests completed successfully! ===")
}

func makeRequest(method, url string, data interface{}, token string) (string, error) {
	var body io.Reader

	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return "", err
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return "", err
	}

	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(responseBody), nil
}
