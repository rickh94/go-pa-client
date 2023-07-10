package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	purpleauth "github.com/rickh94/go-pa-client"
)

type EmailBody struct {
	Email string `json:"email"`
}

type CodeBody struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type RefreshBody struct {
	RefreshToken string `json:"refreshToken"`
}

func main() {
	r := gin.Default()

	appID := os.Getenv("APP_ID")
	if appID == "" {
		panic("APP_ID is not set")
	}
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		panic("API_KEY is not set")
	}

	paClient := purpleauth.NewClient("https://purpleauth.com", appID, apiKey)

	r.POST("/authenticate/code", func(c *gin.Context) {

		var body EmailBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := paClient.Authenticate(body.Email, "otp"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Authentication started, check your email"})
	})

	r.POST("/authenticate/magic", func(c *gin.Context) {

		var body EmailBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := paClient.Authenticate(body.Email, "magic"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Authentication started, check your email"})
	})

	r.POST("/submit/code", func(c *gin.Context) {
		var body CodeBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := paClient.SubmitCode(body.Email, body.Code)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, token)
	})

	r.POST("/verify/remote", func(c *gin.Context) {
		var token purpleauth.Token
		if err := c.ShouldBindJSON(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		claims, err := paClient.VerifyTokenRemote(token.IDToken)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Could not verify Token", "reason": err.Error()})
			return
		}

		c.JSON(http.StatusOK, claims)
	})

	r.POST("/verify/local", func(c *gin.Context) {
		var token purpleauth.Token
		if err := c.ShouldBindJSON(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		claims, err := paClient.VerifyToken(token.IDToken)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Could not verify Token", "reason": err.Error()})
			return
		}

		c.JSON(http.StatusOK, claims)
	})

	r.GET("/appinfo", func(c *gin.Context) {
		appInfo, err := paClient.GetAppInfo()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, appInfo)
	})

	r.POST("/refresh/delete", func(c *gin.Context) {
		var token purpleauth.Token

		if err := c.ShouldBindJSON(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := paClient.DeleteRefreshToken(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Refresh token deleted"})
	})

	r.POST("/refresh/delete-all", func(c *gin.Context) {
		var token purpleauth.Token

		if err := c.ShouldBindJSON(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := paClient.DeleteAllRefreshTokens(token.IDToken); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Refresh tokens deleted"})
	})

	r.POST("/refresh", func(c *gin.Context) {
		var body RefreshBody

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := paClient.Refresh(body.RefreshToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"idToken": token})
	})

	r.Run()

}
