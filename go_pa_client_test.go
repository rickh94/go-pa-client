package go_pa_client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	FAKE_TOKEN   = "this-is-a-fake-jwt"
	FAKE_APP_ID  = "fake-app-id"
	FAKE_API_KEY = "fake-api-key"
)

func TestCreateClient(t *testing.T) {
	client := NewClient("http://example.com", FAKE_APP_ID, FAKE_API_KEY)
	if client.Host != "http://example.com" {
		t.Error("Host not set correctly")
	}
	if client.AppID != FAKE_APP_ID {
		t.Error("AppID not set correctly")
	}
	if client.ApiKey != FAKE_API_KEY {
		t.Error("ApiKey not set correctly")
	}
	if client.publicKeyCached != nil {
		t.Error("publicKeyCached should be set lazily")
	}
}

func checkRequest(req *http.Request, endpoint string, method string, authorization string, t *testing.T) {
	correctEndpoint := fmt.Sprintf("%s/%s", endpoint, FAKE_APP_ID)
	if req.URL.Path != correctEndpoint {
		t.Errorf("Request was made to incorrect endpoint: expected %s, got %s", correctEndpoint, req.URL.Path)
	}
	correctAuthorization := fmt.Sprintf("Bearer %s", authorization)
	if req.Header.Get("Authorization") != correctAuthorization {
		t.Errorf("Request authorization was incorrect: expected %s, got %s", correctAuthorization, req.Header.Get("Authorization"))
	}
	if req.Method != method {
		t.Errorf("Request method was incorrect, expected %s, got %s", method, req.Method)
	}
}

func TestAuthenticateOtpSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/request", "POST", FAKE_API_KEY, t)
		rw.Write([]byte(`"Check your email for a code"`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "otp")
	if err != nil {
		t.Error(err)
	}
}

func TestAuthenticateMagicSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/magic/request", "POST", FAKE_API_KEY, t)
		rw.Write([]byte(`"Check your email for a code"`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "magic")
	if err != nil {
		t.Error(err)
	}
}

func TestAuthenticateDoesNotAcceptInvalidFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("Should not be called")
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "nothing")
	if err == nil {
		t.Error("There should have been an error for an invalid flow")
	}
}

func TestAuthenticateNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/request", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "otp")
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestAuthenticateServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/request", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "otp")
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestAuthenticateAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/request", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "otp")
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestAuthenticateValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/request", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.Authenticate("email", "otp")
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func TestSubmitCodeSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		body, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			t.Error(err)
		}
		var data map[string]string
		if err := json.Unmarshal(body, &data); err != nil {
			t.Error(err)
		}
		if data["code"] != "123456" {
			t.Error("Code not sent correctly")
		}

		if data["email"] != "test@example.com" {
			t.Error("Email not sent correctly")
		}

		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"idToken": "fake-id-token", "refreshToken": null}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	token, err := client.SubmitCode("test@example.com", "123456")
	if err != nil {
		t.Error(err)
	}
	if token.IDToken != "fake-id-token" {
		t.Error("IDToken not set correctly")
	}
	if token.Refresh != "" {
		t.Error("RefreshToken not set correctly")
	}
}

func TestSubmitCodeWithRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		body, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			t.Error(err)
		}
		var data map[string]string
		if err := json.Unmarshal(body, &data); err != nil {
			t.Error(err)
		}
		if data["code"] != "123456" {
			t.Error("Code not sent correctly")
		}

		if data["email"] != "test@example.com" {
			t.Error("Email not sent correctly")
		}

		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"idToken": "fake-id-token", "refreshToken": "fake-refresh-token"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	token, err := client.SubmitCode("test@example.com", "123456")
	if err != nil {
		t.Error(err)
	}
	if token.IDToken != "fake-id-token" {
		t.Error("IDToken not set correctly")
	}
	if token.Refresh != "fake-refresh-token" {
		t.Error("RefreshToken not set correctly")
	}
}

func TestSubmitCodeNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.SubmitCode("test@example.com", "123456")
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestSubmitCodeServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.SubmitCode("test@example.com", "123456")
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestSubmitCodeAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.SubmitCode("test@example.com", "123456")
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestSubmitCodeValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/otp/confirm", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.SubmitCode("test@example.com", "123456")
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func TestVerifyTokenRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/verify", "POST", FAKE_API_KEY, t)
		rw.Write([]byte(`{"headers": {}, "claims": {"sub": "test@example.com"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	resp, err := client.VerifyTokenRemote(FAKE_TOKEN)
	if err != nil {
		t.Error(err)
	}
	if resp.Claims.Email != "test@example.com" {
		t.Error("Email not set correctly")
	}
}

func TestVerifyTokenRemoteNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/verify", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.VerifyTokenRemote(FAKE_TOKEN)
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestVerifyTokenRemoteServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/verify", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.VerifyTokenRemote(FAKE_TOKEN)
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestVerifyTokenRemoteAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/verify", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.VerifyTokenRemote(FAKE_TOKEN)
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestVerifyTokenRemoteValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/verify", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.VerifyTokenRemote(FAKE_TOKEN)
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func TestRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "POST", FAKE_API_KEY, t)
		body, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			t.Error(err)
		}
		var data map[string]string
		if err := json.Unmarshal(body, &data); err != nil {
			t.Error(err)
		}
		if data["refreshToken"] != "fake-refresh-token" {
			t.Error("Refresh token is not sent correctly")
		}

		rw.Write([]byte(`{"idToken": "new-id-token", "refreshToken": "fake-refresh-token"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	newToken, err := client.Refresh("fake-refresh-token")
	if err != nil {
		t.Error(err)
	}

	if newToken != "new-id-token" {
		t.Error("IDToken not set correctly")
	}
}

func TestRefreshNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.Refresh("fake-refresh-token")
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestRefreshServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.Refresh("fake-refresh-token")
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestRefreshAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.Refresh("fake-refresh-token")
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestRefreshValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "POST", FAKE_API_KEY, t)
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.Refresh("fake-refresh-token")
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func TestAppInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app", "GET", FAKE_API_KEY, t)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"name": "fakeApp", "app_id": "fake-app-id", "redirect_url": "https://example.com/magic" }`))
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	appInfo, err := client.GetAppInfo()
	if err != nil {
		t.Error(err)
	}
	if appInfo.Name != "fakeApp" {
		t.Error("Name not set correctly")
	}
	if appInfo.AppID != "fake-app-id" {
		t.Error("AppID not set correctly")
	}
	if appInfo.RedirectURL != "https://example.com/magic" {
		t.Error("RedirectURL not set correctly")
	}

}

func TestAppInfoNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app", "GET", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.GetAppInfo()
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestAppInfoServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app", "GET", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.GetAppInfo()
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestAppInfoAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app", "GET", FAKE_API_KEY, t)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.GetAppInfo()
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestAppInfoValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app", "GET", FAKE_API_KEY, t)
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	_, err := client.GetAppInfo()
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func genFakeKey() jwk.Key {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := jwk.FromRaw(privkey)
	if err != nil {
		panic(err)
	}
	key.Set(jwk.KeyIDKey, "fake-key-id")
	return key
}

func genValidToken(email string, url string, appID string, key *jwk.Key) string {
	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = jwt.MapClaims{
		"sub": email,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": fmt.Sprintf("%s/app/%s", url, appID),
	}
	token.Header["kid"] = "fake-key-id"
	var rawKey ecdsa.PrivateKey

	if err := (*key).Raw(&rawKey); err != nil {
		panic(err)
	}
	tokenstring, err := token.SignedString(&rawKey)
	if err != nil {
		panic(err)
	}
	return tokenstring
}

func genExpiredToken(email string, url string, appID string, key *jwk.Key) string {
	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = jwt.MapClaims{
		"sub": email,
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iss": fmt.Sprintf("%s/app/%s", url, appID),
	}
	token.Header["kid"] = "fake-key-id"
	var rawKey ecdsa.PrivateKey

	if err := (*key).Raw(&rawKey); err != nil {
		panic(err)
	}
	tokenstring, err := token.SignedString(&rawKey)
	if err != nil {
		panic(err)
	}
	return tokenstring
}

func TestVerifySuccess(t *testing.T) {
	key := genFakeKey()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app/public_key", "GET", FAKE_API_KEY, t)
		pubkey, err := key.PublicKey()
		jsonKey, err := json.Marshal(pubkey)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(jsonKey)
	}))
	defer server.Close()
	token := genValidToken("test@example.com", server.URL, FAKE_APP_ID, &key)

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)
	claims, err := client.VerifyToken(token)
	if err != nil {
		t.Error(err)
	}
	if claims["sub"] != "test@example.com" {
		t.Error("Email not set correctly")
	}

}

func TestVerifyWrongKey(t *testing.T) {
	rightKey := genFakeKey()
	wrongKey := genFakeKey()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app/public_key", "GET", FAKE_API_KEY, t)
		pubkey, err := rightKey.PublicKey()
		jsonKey, err := json.Marshal(pubkey)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(jsonKey)
	}))
	defer server.Close()
	token := genValidToken("test@example.com", server.URL, "test", &wrongKey)

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)
	claims, err := client.VerifyToken(token)
	if err == nil {
		t.Error("Should not verify token with different signing key")
	}
	if claims != nil {
		t.Error("Claims should be nil")
	}

}

func TestVerifyWrongIssuer(t *testing.T) {
	rightKey := genFakeKey()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app/public_key", "GET", FAKE_API_KEY, t)
		pubkey, err := rightKey.PublicKey()
		jsonKey, err := json.Marshal(pubkey)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(jsonKey)
	}))
	defer server.Close()
	token := genValidToken("test@example.com", "http://example.com", "test", &rightKey)

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)
	claims, err := client.VerifyToken(token)
	if err == nil {
		t.Error("Should not verify token with different issuer")
	}
	if claims != nil {
		t.Error("Claims should be nil")
	}

}

func TestVerifyExpired(t *testing.T) {
	rightKey := genFakeKey()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/app/public_key", "GET", FAKE_API_KEY, t)
		pubkey, err := rightKey.PublicKey()
		jsonKey, err := json.Marshal(pubkey)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(jsonKey)
	}))
	defer server.Close()
	token := genExpiredToken("test@example.com", server.URL, "test", &rightKey)

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)
	claims, err := client.VerifyToken(token)
	if err == nil {
		t.Error("Should not verify expired token")
	}
	if claims != nil {
		t.Error("Claims should be nil")
	}
}

func TestDeleteRefresh(t *testing.T) {
	fakeToken := Token{
		IDToken: "fake-id-token",
		Refresh: "fake-refresh-token",
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		correctEndpoint := fmt.Sprintf("%s/%s/%s", "/token/refresh", FAKE_APP_ID, url.PathEscape(fakeToken.Refresh))
		if req.URL.Path != correctEndpoint {
			t.Errorf("Request was made to incorrect endpoint: expected %s, got %s", correctEndpoint, req.URL.Path)
		}
		correctAuthorization := fmt.Sprintf("Bearer %s", fakeToken.IDToken)
		if req.Header.Get("Authorization") != correctAuthorization {
			t.Errorf("Request authorization was incorrect: expected %s, got %s", correctAuthorization, req.Header.Get("Authorization"))
		}
		if req.Method != "DELETE" {
			t.Errorf("Request method was incorrect, expected %s, got %s", "DELETE", req.Method)
		}
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteRefreshToken(&fakeToken)
	if err != nil {
		t.Error(err)
	}

}

func TestDeleteRefreshNotFound(t *testing.T) {
	fakeToken := Token{
		IDToken: "fake-id-token",
		Refresh: "fake-refresh-token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteRefreshToken(&fakeToken)
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestDeleteRefreshServerError(t *testing.T) {
	fakeToken := Token{
		IDToken: "fake-id-token",
		Refresh: "fake-refresh-token",
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteRefreshToken(&fakeToken)
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestDeleteRefreshAuthenticationFailure(t *testing.T) {
	fakeToken := Token{
		IDToken: "fake-id-token",
		Refresh: "fake-refresh-token",
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteRefreshToken(&fakeToken)
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestDeleteRefreshValidationError(t *testing.T) {
	fakeToken := Token{
		IDToken: "fake-id-token",
		Refresh: "fake-refresh-token",
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteRefreshToken(&fakeToken)
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}

func TestDeleteAllRefresh(t *testing.T) {
	fakeToken := "fake-id-token"
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		checkRequest(req, "/token/refresh", "DELETE", fakeToken, t)
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteAllRefreshTokens(fakeToken)
	if err != nil {
		t.Error(err)
	}

}

func TestDeleteAllRefreshNotFound(t *testing.T) {
	fakeToken := "fake-id-token"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteAllRefreshTokens(fakeToken)
	if err != ErrAppNotFound {
		t.Errorf("Should have return ErrAppNotFound on not found http code, instead got: %v", err)
	}
}

func TestDeleteAllRefreshServerError(t *testing.T) {
	fakeToken := "fake-id-token"
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteAllRefreshTokens(fakeToken)
	if err != ErrServerError {
		t.Errorf("Should have return ErrServerError on not found http code, instead got: %v", err)
	}
}

func TestDeleteAllRefreshAuthenticationFailure(t *testing.T) {
	fakeToken := "fake-id-token"
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteAllRefreshTokens(fakeToken)
	if err != ErrAuthenticationFailure {
		t.Errorf("Should have return ErrAuthenticationFailure on not found http code, instead got: %v", err)
	}
}

func TestDeleteAllRefreshValidationError(t *testing.T) {
	fakeToken := "fake-id-token"
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(422)
	}))
	defer server.Close()

	client := NewClient(server.URL, FAKE_APP_ID, FAKE_API_KEY)

	err := client.DeleteAllRefreshTokens(fakeToken)
	if err != ErrValidationError {
		t.Errorf("Should have return ErrValidationError on not found http code, instead got: %v", err)
	}
}
