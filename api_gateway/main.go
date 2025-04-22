package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
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

var authTemplate = `
<!DOCTYPE html>
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		log.Printf("Request from %s: %s", clientIP, r.URL.Path)

		limiter := getLimiter(clientIP)
		allowed := limiter.Allow()
		if !limiter.Allow() {
			log.Printf("Rate limit exceeded by %s", clientIP)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		log.Printf("limiter allowed for %s: %v", clientIP, allowed)

		if r.URL.Path == "/auth" {
			if r.Method == "GET" {
				// User is requesting the auth page
				// TODO: Use Content-Type and Accept instead
				if strings.Split(r.UserAgent(), "/")[0] == "curl" {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				} else {
					t, err := template.New("auth").Parse(authTemplate)
					if err != nil {
						panic(err)
					}
					err = t.Execute(w, nil)
					if err != nil {
						log.Println("Failed at executing form template" + err.Error())
					}
				}
			} else if r.Method == "POST" {
				// User is trying to log in
				var tokenString string
				var err error
				if r.FormValue("token") == ADMIN_PASS {
					tokenString, err = GenerateJWT(
						jwtKey,
						[]string{
							"/yapilyAuth",
							"/authCallback",
							"/ping",
						},
					)
					if err != nil {
						panic(err)
					}
				} else if r.FormValue("token") == USER_PASS {
					tokenString, err = GenerateJWT(
						jwtKey,
						[]string{"/ping"},
					)
					if err != nil {
						panic(err)
					}
				} else {
					http.Error(w, "invalid credentials", http.StatusBadRequest)
					return
				}
				if strings.Split(r.UserAgent(), "/")[0] == "curl" {
					w.Write([]byte(tokenString))
				} else {
					cookie := &http.Cookie{
						Name:     "__Host-ProxyAuth",
						Value:    tokenString,
						Path:     "/",
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteStrictMode,
						Expires:  time.Now().Add(15 * time.Minute),
					}
					http.SetCookie(w, cookie)
					http.Redirect(w, r, "/", http.StatusFound)
				}
			}
		} else if r.URL.Path == "/" {
			w.Write([]byte("<h1>API Gateway</h1>"))
			w.Write([]byte("<a href=/auth>log in</a>"))
			proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
			if err != nil {
				return
			}
			claims, err, status := ParseJWT(jwtKey, proxyAuthCookie.Value)
			if err != nil {
				http.Error(w, err.Error(), status)
				return
			}
			w.Write([]byte("<br>"))
			for _, path := range claims.AllowedPaths {
				w.Write([]byte("<a href="))
				w.Write([]byte(path))
				w.Write([]byte(">"))
				w.Write([]byte(path))
				w.Write([]byte("</a>"))
				w.Write([]byte("<br>"))
			}
		} else {
			var allowedPaths []string

			if strings.Split(r.UserAgent(), "/")[0] == "curl" {
				authHeader := r.Header.Get("Authorization")
				if authHeader == "" {
					http.Error(w, "no token", http.StatusUnauthorized)
					return
				}
				if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
					http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
					return
				}
				tokenString := strings.TrimPrefix(authHeader, "Bearer ")
				claims, err, status := ParseJWT(jwtKey, tokenString)
				if err != nil {
					http.Error(w, err.Error(), status)
					return
				}
				allowedPaths = claims.AllowedPaths
			} else {
				proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
				if err != nil || proxyAuthCookie.Value == "" {
					http.Error(w, "no token", http.StatusUnauthorized)
					return
				}
				claims, err, status := ParseJWT(jwtKey, proxyAuthCookie.Value)
				if err != nil {
					http.Error(w, err.Error(), status)
					return
				}
				allowedPaths = claims.AllowedPaths
			}

			var trimmedPath = strings.TrimRight(r.URL.Path, "/")
			fmt.Println("CLAIMS", allowedPaths)
			if serviceURL, found := endpoints[trimmedPath]; found {
				backendURL, err := url.Parse(serviceURL)
				if err != nil {
					panic(err)
				}

				fmt.Println(backendURL)
				if slices.Contains(allowedPaths, trimmedPath) {
					backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
					fmt.Println(backendURL)
					backendRedirect.ServeHTTP(w, r)
				} else {
					http.Error(w, "unauthorized payload", http.StatusUnauthorized)
				}
			} else {
				http.Error(w, "invalid payload", http.StatusUnauthorized)
			}
		}
	})

	// Start API Gateway server
	log.Println("Starting API Gateway on :8083")
	http.ListenAndServe(":8083", nil)
}

func ParseJWT(jwtKey []byte, authHeader string) (*Claims, error, int) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(authHeader, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrTokenUnverifiable
		}
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("Invalid token"), http.StatusUnauthorized
	}
	return token.Claims.(*Claims), nil, 0
}

func GenerateJWT(jwtKey []byte, allowedPaths []string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		AllowedPaths: allowedPaths,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "YAPILY_EXJOBB_APIGATEWAY",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}
