package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

var authorizedTokens map[string][]string = map[string][]string{}

// NOTE: /auth is reserved
var endpoints = map[string]string{
	"/yapilyAuth":   "http://backend-service:8081/",
	"/authCallback": "http://backend-service:8081/",
	"/ping":         "http://ping-service:8082/",
}

const ADMIN_PASS = "1234"
const USER_PASS = "2345"

func main() {
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
				var token string
				if r.FormValue("token") == ADMIN_PASS {
					token = uuid.NewString()
					// Simulate an administrator logging in
					authorizedTokens[token] = []string{
						"/yapilyAuth",
						"/authCallback",
						"/ping",
					}
				} else if r.FormValue("token") == USER_PASS {
					token = uuid.NewString()
					// Simulate a user logging in
					authorizedTokens[token] = []string{
						"/ping",
					}
				} else {
					http.Error(w, "invalid credentials", http.StatusBadRequest)
					return
				}
				if strings.Split(r.UserAgent(), "/")[0] == "curl" {
					w.Write([]byte(token))
				} else {
					w.Header().Set("Set-Cookie", "ProxyAuth="+token)
					http.Redirect(w, r, "/", http.StatusFound)
				}
			}
		} else if r.URL.Path == "/" {
			w.Write([]byte("<h1>API Gateway</h1>"))
			w.Write([]byte("<a href=/auth>log in</a>"))
			proxyAuthCookie, err := r.Cookie("ProxyAuth")
			if err != nil {
				return
			}
			authorizedPayloads, ok := authorizedTokens[proxyAuthCookie.Value]
			if !ok {
				return
			}
			w.Write([]byte("<br>"))
			for _, path := range authorizedPayloads {
				w.Write([]byte("<a href="))
				w.Write([]byte(path))
				w.Write([]byte(">"))
				w.Write([]byte(path))
				w.Write([]byte("</a>"))
				w.Write([]byte("<br>"))
			}
		} else {
			var proxyAuth string
			if strings.Split(r.UserAgent(), "/")[0] == "curl" {
				proxyAuth = r.Header.Get("token")
			} else {
				proxyAuthCookie, err := r.Cookie("ProxyAuth")
				proxyAuth = proxyAuthCookie.Value
				if err != nil {
					http.Error(w, "invalid auth: "+err.Error(), http.StatusBadRequest)
					return
				}
			}
			authorizedPayloads, ok := authorizedTokens[proxyAuth]
			if ok {
				if serviceURL, found := endpoints[r.URL.Path]; found {
					backendURL, err := url.Parse(serviceURL)
					if err != nil {
						panic(err)
					}

					fmt.Println(backendURL)
					if slices.Contains(authorizedPayloads, r.URL.Path) {
						backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
						fmt.Println(backendURL)
						backendRedirect.ServeHTTP(w, r)
					} else {
						http.Error(w, "unauthorized payload", http.StatusUnauthorized)
					}

				} else {
					http.Error(w, "invalid payload", http.StatusUnauthorized)
				}

			} else {
				http.Error(w, "bad token", http.StatusBadRequest)
			}
		}
	})

	// Start API Gateway server
	log.Println("Starting API Gateway on :8080")
	http.ListenAndServe(":8080", nil)
}
