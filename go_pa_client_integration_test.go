package go_pa_client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func newClientApp1() *Client {
	return NewClient("http://localhost:25898", "123456", "testkey")
}

func newClientApp2() *Client {
	return NewClient("http://localhost:25898", "2", "testkey")
}

func TestCodeFlow(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	client := newClientApp1()
	err := client.Authenticate("test@example.com", "otp")
	if err != nil {
		t.Error(err)
	}
	cmd := exec.Command("docker-compose", "-f", "integration-test/docker-compose.yml", "run", "--rm", "volume-access", "sh", "-c", "cat /test-data/email-to-test@example.com.json")
	stdout, err := cmd.Output()
	if err != nil {
		t.Error("Failed reading email")
	}

	var data map[string]string

	if err := json.Unmarshal(stdout, &data); err != nil {
		t.Error("Could not get data from email")
	}

	if data["to"] != "test@example.com" {
		t.Errorf("Wrong recipient, expected %s, got %s", "test@example.com", data["to"])
	}

	if data["from"] != "App <test@mg.example.com>" {
		t.Errorf("Invalid sender, expected %s, got %s", "App <test@mg.example.com>", data["from"])
	}

	if data["subject"] != "Your One Time Login Code" {
		t.Errorf("Invalid subject, expected %s, got %s", "Your One Time Login Code", data["subject"])
	}

	re := regexp.MustCompile(`Your code is ([0-9]*)`)

	matches := re.FindAllStringSubmatch(data["text"], -1)
	code := matches[0][1]

	token, err := client.SubmitCode("test@example.com", code)
	if err != nil {
		t.Error(err)
	}

	verification, err := client.VerifyTokenRemote(token.IDToken)
	if err != nil {
		t.Error(err)
	}

	if verification.Headers == nil {
		t.Error("No headers found")
	}

	if verification.Claims.Email != "test@example.com" {
		t.Errorf("Wrong email, expected %s, got %s", "test@example.com", verification.Claims.Email)
	}

	claims, err := client.VerifyToken(token.IDToken)
	if err != nil {
		t.Error(err)
	}

	if claims["sub"] != "test@example.com" {
		t.Errorf("Wrong email, expected %s, got %s", "test@example.com", claims["email"])
	}

	newIDToken, err := client.Refresh(token.Refresh)
	if err != nil {
		t.Error(err)
	}

	_, err = client.VerifyToken(newIDToken)
	if err != nil {
		t.Error(err)
	}
}

func TestMagicFlow(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}

	client := newClientApp1()
	err := client.Authenticate("test2@example.com", "magic")
	if err != nil {
		t.Error(err)
	}
	cmd := exec.Command("docker-compose", "-f", "integration-test/docker-compose.yml", "run", "--rm", "volume-access", "sh", "-c", "cat /test-data/email-to-test2@example.com.json")
	stdout, err := cmd.Output()
	if err != nil {
		t.Error("Failed reading email")
	}

	var data map[string]string

	if err := json.Unmarshal(stdout, &data); err != nil {
		t.Error("Could not get data from email")
	}

	if data["to"] != "test2@example.com" {
		t.Errorf("Wrong recipient, expected %s, got %s", "test2@example.com", data["to"])
	}

	if data["from"] != "App <test@mg.example.com>" {
		t.Errorf("Invalid sender, expected %s, got %s", "App <test@mg.example.com>", data["from"])
	}

	if data["subject"] != "Your Magic Sign In Link" {
		t.Errorf("Invalid subject, expected %s, got %s", "Your Magic Sign In Link", data["subject"])
	}

	re := regexp.MustCompile(`Click or copy this link to sign in:
(.*)
It`)

	matches := re.FindAllStringSubmatch(data["text"], -1)
	magicLink := matches[0][1]

	response, err := httpclient.Get(magicLink)
	if err != nil {
		t.Error(err)
	}
	if response.StatusCode != 200 {
		t.Errorf("Wrong status code, expected 200, got %d", response.StatusCode)
	}

	cmd = exec.Command("docker-compose", "-f", "integration-test/docker-compose.yml", "run", "--rm", "volume-access", "sh", "-c", "cat /test-data/magic-from-test2@example.com.json")
	stdout, err = cmd.Output()
	if err != nil {
		t.Error("Failed reading magic link output")
	}

	var tokenData map[string]string
	if err := json.Unmarshal(stdout, &tokenData); err != nil {
		t.Error("Invalid magic link data")
	}

	verification, err := client.VerifyTokenRemote(tokenData["idToken"])
	if err != nil {
		t.Error(err)
	}

	if verification.Headers == nil {
		t.Error("No headers found")
	}

	if verification.Claims.Email != "test2@example.com" {
		t.Errorf("Wrong email, expected %s, got %s", "test2@example.com", verification.Claims.Email)
	}

	claims, err := client.VerifyToken(tokenData["idToken"])
	if err != nil {
		t.Error(err)
	}

	if claims["sub"] != "test2@example.com" {
		t.Errorf("Wrong email, expected %s, got %s", "test2@example.com", claims["email"])
	}

	newIDToken, err := client.Refresh(tokenData["refreshToken"])
	if err != nil {
		t.Error(err)
	}

	_, err = client.VerifyToken(newIDToken)
	if err != nil {
		t.Error(err)
	}

}

func TestCodeFlowWrongCode(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	client := newClientApp1()
	err := client.Authenticate("test3@example.com", "otp")
	if err != nil {
		t.Error(err)
	}

	_, err = client.SubmitCode("test3@example.com", "wrong")
	if err == nil {
		t.Error("Expected error for wrong code")
	}
}

func TestRemoteVerifyInvalidToken(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error("Could not generate key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "test3@example.com",
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Errorf("Could not sign token %s", err)
	}
	client := newClientApp1()
	_, err = client.VerifyTokenRemote(tokenString)
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestLocalVerifyInvalidToken(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error("Could not generate key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "test3@example.com",
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Errorf("Could not sign token %s", err)
	}
	client := newClientApp1()
	_, err = client.VerifyToken(tokenString)
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func performCodeAuth(client *Client, email string, t *testing.T) Token {
	err := client.Authenticate(email, "otp")
	if err != nil {
		t.Error(err)
	}
	cmd := exec.Command("docker-compose", "-f", "integration-test/docker-compose.yml", "run", "--rm", "volume-access", "sh", "-c", fmt.Sprintf("cat /test-data/email-to-%s.json", email))
	stdout, err := cmd.Output()
	if err != nil {
		t.Error("Failed reading email")
	}

	var data map[string]string

	if err := json.Unmarshal(stdout, &data); err != nil {
		t.Error("Could not get data from email")
	}

	re := regexp.MustCompile(`Your code is ([0-9]*)`)

	matches := re.FindAllStringSubmatch(data["text"], -1)
	code := matches[0][1]

	token, err := client.SubmitCode(email, code)
	if err != nil {
		t.Error(err)
	}
	return token
}

func TestVerifyFromOtherAppFails(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	client1 := newClientApp1()
	client2 := newClientApp2()
	token1 := performCodeAuth(client1, "test4@example.com", t)
	_, err := client2.VerifyTokenRemote(token1.IDToken)
	if err == nil {
		t.Error("App should not verify token from other app")
	}
}

func TestCannotRefreshAfterDeletingToken(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	client := newClientApp1()
	token := performCodeAuth(client, "test5@example.com", t)
	err := client.DeleteRefreshToken(&token)
	if err != nil {
		t.Error(err)
	}

	_, err = client.Refresh(token.Refresh)
	if err == nil {
		t.Error("Should not be able to refresh with invalidated token")
	}
}

func TestCannotRefreshAfterDeletingAllTokens(t *testing.T) {
	if os.Getenv("INTEGRATION_UP") == "" {
		t.Skip("Skipping integration test")
	}
	client := newClientApp1()
	token1 := performCodeAuth(client, "test5@example.com", t)
	token2 := performCodeAuth(client, "test5@example.com", t)

	err := client.DeleteAllRefreshTokens(token1.IDToken)
	if err != nil {
		t.Error(err)
	}

	_, err = client.Refresh(token1.Refresh)
	if err == nil {
		t.Error("Should not be able to refresh with invalidated token")
	}
	_, err = client.Refresh(token2.Refresh)
	if err == nil {
		t.Error("Should not be able to refresh with any refresh token")
	}
}
