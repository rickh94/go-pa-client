// Package go_pa_client provides a client for the purpleauth.com api.
package go_pa_client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Client is the configuration struct for working with the purple auth api.
// It also receives all the methods.
type Client struct {
	Host            string
	AppID           string
	ApiKey          string
	publicKeyCached *interface{}
}

// Token holds the id token and refresh token for an authenticated user. It is
// configured to be json serializable (renamed to camelCase).
type Token struct {
	IDToken string `json:"idToken"`
	Refresh string `json:"refreshToken"`
}

var ErrAppNotFound = errors.New("App not found")
var ErrServerError = errors.New("Server error")
var ErrValidationError = errors.New("Validation error")
var ErrAuthenticationFailure = errors.New("Authentication failure")

var httpclient = &http.Client{
	Timeout: 30 * time.Second,
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return ErrAuthenticationFailure
		case http.StatusForbidden:
			return ErrAuthenticationFailure
		case http.StatusNotFound:
			return ErrAppNotFound
		case 422: // Validation error
			return ErrValidationError
		default:
			return ErrServerError
		}
	}
	return nil
}

// NewClient creates a new instance of the GoPaClient.
// It initializes the GoPaClient with the provided host, appId, and apiKey.
//
// Parameters:
//   - host: The host of the GoPa server (probably purpleauth.com).
//   - appId: The application ID from purpleauth.com.
//   - apiKey: The API key for authentication with purpleauth.com.
//
// Returns:
//   - *GoPaClient: A pointer to the newly created GoPaClient instance.
func NewClient(host string, appId string, apiKey string) *Client {
	return &Client{
		Host:            host,
		AppID:           appId,
		ApiKey:          apiKey,
		publicKeyCached: nil,
	}
}

// Authenticate starts a new passwordless authentication for the provided email
// using the given flow.
//
// Parameters:
//   - email: The email address of the user.
//   - flow: The authentication flow to use. Must by "otp" for a one-time code
//     or "magic" for a magic link.
//
// Returns:
//   - error: An error if the authentication could not be started, or nil.
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) Authenticate(email string, flow string) error {
	if flow != "otp" && flow != "magic" {
		return ErrValidationError
	}
	endpoint := fmt.Sprintf("%s/request", flow)
	_, err := c.performPost(endpoint, map[string]string{"email": email})
	return err
}

// SubmitCode submits an authentication code and returns a token.
//
// Parameters:
//   - email: User's email address.
//   - code: Submitted one-time password code.
//
// Returns:
//   - Token: A struct containing the IDToken and RefreshToken.
//   - err: An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) SubmitCode(email string, code string) (Token, error) {
	body, err := c.performPost("otp/confirm", map[string]string{"email": email, "code": code})
	if err != nil {
		return Token{}, err
	}
	var token Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		return Token{}, err
	}
	return token, nil
}

// JWTClaims holds the expected claims for a JWT from purpleauth.com.
type JWTClaims struct {
	jwt.Claims
	Email string `json:"sub"`
}

type TokenResponse struct {
	Claims  JWTClaims
	Headers map[string]string
}

// VerifyTokenRemote requests the server to verify a user's JWT.
//
// Parameters:
//   - token: The token (string) to verify
//
// Returns:
//   - the claims decoded from the token (or nil)
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) VerifyTokenRemote(token string) (*TokenResponse, error) {
	body, err := c.performPost("token/verify", map[string]string{"idToken": token})
	if err != nil {
		return nil, err
	}

	var claims TokenResponse
	err = json.Unmarshal(body, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

// Refresh submits a refresh token to the server to get a new id token.
//
// Parameters:
//   - refreshToken: The refresh token from the user.
//
// Returns:
//   - the new id token as a string
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) Refresh(refreshToken string) (string, error) {
	body, err := c.performPost("token/refresh", map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return "", err
	}
	var token Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}
	return token.IDToken, nil
}

// AppInfo holds info a configured app
type AppInfo struct {
	Name        string `json:"name"`
	AppID       string `json:"app_id"`
	RedirectURL string `json:"redirect_url"`
}

// AppInfo gets full info about the configured app
//
// Returns:
//   - map of info about the app
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
func (c *Client) GetAppInfo() (*AppInfo, error) {
	fullUrl := fmt.Sprintf("%s/%s/%s", c.Host, "app", c.AppID)
	req, err := http.NewRequest(http.MethodGet, fullUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var appInfo AppInfo
	err = json.Unmarshal(respBody, &appInfo)
	if err != nil {
		return nil, err
	}

	return &appInfo, nil
}

// VerifyToken verifies the token locally without making a request to the server
//
// Parameters:
//   - tokenString: The token (string) to verify
//
// Returns:
//   - the claims decoded from the token (or nil)
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) VerifyToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		key, err := c.getPublicKey()
		if err != nil {
			return nil, err
		}
		return *key, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("Couldn't parse claims")
	}

	expires, err := claims.GetExpirationTime()
	if err != nil || expires.Unix() < time.Now().Unix() {
		return nil, errors.New("Token has expired")
	}

	issuer, err := claims.GetIssuer()
	if err != nil || issuer != fmt.Sprintf("%s/app/%s", c.Host, c.AppID) {
		return nil, errors.New("Invalid issuer")
	}

	return claims, nil
}

// DeleteRefreshToken requests the server to permanently delete an active refesh
// token
//
// Parameters:
//   - token: The Token struct for the user with the RefreshToken to delete
//
// Returns:
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) DeleteRefreshToken(token *Token) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/token/refresh/%s/%s", c.Host, c.AppID, url.PathEscape(token.Refresh)), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.IDToken))

	resp, err := httpclient.Do(req)
	if err != nil {
		return err
	}

	if err = checkStatus(resp); err != nil {
		return err
	}

	return nil
}

// DeleteAllRefreshTokens request the server to permanently delete all refresh
// tokens for a user.
//
// Parameters:
//   - idToken: The IDToken string for the user
//
// Returns:
//   - An error if any of the following occurs:
//     ErrAppNotFound: If the app ID is invalid (cannot be found).
//     ErrServerError: If something goes wrong on the server.
//     ErrValidationError: If something is wrong with the request data.
//     ErrAuthenticationFailure: If the email code combination doesn't authenticate.
func (c *Client) DeleteAllRefreshTokens(idToken string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/token/refresh/%s", c.Host, c.AppID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", idToken))

	resp, err := httpclient.Do(req)
	if err != nil {
		return err
	}

	if err = checkStatus(resp); err != nil {
		return err
	}

	return nil
}

func (c *Client) performPost(endpoint string, data map[string]string) ([]byte, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	fullUrl := fmt.Sprintf("%s/%s/%s", c.Host, endpoint, c.AppID)
	req, err := http.NewRequest(http.MethodPost, fullUrl, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBody, nil

}

func (c *Client) getPublicKey() (*interface{}, error) {
	if c.publicKeyCached != nil {
		return c.publicKeyCached, nil
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s", c.Host, "app/public_key", c.AppID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))
	resp, err := httpclient.Do(req)

	if err != nil {
		return nil, err
	}

	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	keyset, err := jwk.Parse(respBody)
	if err != nil {
		return nil, err
	}

	key, ok := keyset.Key(0)
	if !ok {
		return nil, errors.New("No public key found")
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, err
	}

	c.publicKeyCached = &rawKey

	return c.publicKeyCached, nil
}
