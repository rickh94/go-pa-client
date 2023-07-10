# Purple Auth Client (Go)

An async python client for my ["Purple Auth"
microservice](https://purpleauth.com).

The basics are outlined below, or you can [look at an example](https://github.com/rickh94/go-pa-client/tree/main/example)


### initialization

Create an account and application on [purpelauth.com](https://purpleauth.com),
then initialize the client with those values. You should store the api key in an
environment variable, but the app id is a public value, not a secret.

```go
import (
    purpleauth "github.com/rick94/go-pa-client"
)

func main() {
    client := purpleauth.NewClient("https://purpleauth.com", "My-App-ID", "My-API-Key")
}
```

You will initially be limited to 500 authentications per app, but you can email
me to have that increased.

## Routes Covered

### /otp/request/

Start otp authentication flow with server. This will send a one time code to
the user's email.

```go
if err := client.Authenticate("test@example.com", "otp"); err != nil {
    log.Fatal(err)
}
```

### /otp/confirm/

Complete authentication with email and generated code submitted by the user.

```go
token, err := client.SubmitCode("test@example.com", "123456")
```

### /token/verify/

Send idToken to server for verification.

```go
claims, err := client.VerifyTokenRemote(idTokenFromClient)
```

You should prefer to verify tokens locally using the `VerifyToken` function, but
this is provided as a convenience and sanity check.

### /token/refresh/

Request a new ID Token from the server using a refresh token

```go
newToken, err := client.Refresh(refreshTokenFromClient)
```


### /app/

Get more info about this app from the server.

```go
info = client.GetAppInfo()
```


### /magic/request/

Start authentication using magic link flow.

```go
if err := client.Authenticate("test@example.com", "otp"); err != nil {
    log.Fatal(err)
}
```


## Local Verification

Verify and decode an ID Token on directly in the app without having to
call out every time

```go
claims, err := client.VerifyToken(idTokenFromClient)
```

