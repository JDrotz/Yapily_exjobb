package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/time/rate"
)

var mu sync.Mutex
var clientLimits = make(map[string]*rate.Limiter)

func getLimiter(clientIP string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := clientLimits[clientIP]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Millisecond*500), 5)
		clientLimits[clientIP] = limiter
	}
	return limiter
}

type Claims struct {
	AllowedPaths []string
	jwt.RegisteredClaims
}

// NOTE: /auth is reserved
var endpoints = map[string]string{
	"/yapilyAuth":   "http://backend-service:8081/",
	"/authCallback": "http://backend-service:8081/",
	"/ping":         "http://ping-service:8082/",
}

const ADMIN_PASS = "1234"
const USER_PASS = "2345"

func main() {
	key, jwtKeySet := os.LookupEnv("JWT_KEY")
	jwtKey := []byte(key)
	if !jwtKeySet {
		log.Println(jwtKey)
		log.Fatal("JWT_KEY must be set in the environment")
	}

	var authTemplate string = `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Sign in</title>
</head>
<body>
	<h1>Sign in</h1>
	<form method="POST" action="/auth">
		<input type="text" name="token">
		<br><br>
		<input type="submit" value="Authenticate">
	</form>
</body>
</html>
`
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", RootHandler(jwtKey))
	mux.HandleFunc("GET /auth", AuthPageHandler(authTemplate))
	mux.HandleFunc("POST /auth", AuthSubmitHandler(jwtKey))
	mux.HandleFunc("/", ProxyHandler(jwtKey))

	http.ListenAndServe(":8083", mux)
}
