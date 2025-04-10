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
	"/yapilyAuth":   "http://backend-service:8081/yapilyAuth",
	"/authCallback": "http://backend-service:8081/authCallback",
	"/ping":         "http://ping-service:8082/ping",
}

const ADMIN_PASS = "1234"

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
				t, err := template.New("auth").Parse(authTemplate)
				if err != nil {
					panic(err)
				}
				err = t.Execute(w, nil)
				if err != nil {
					log.Println("Failee at executing form template" + err.Error())
				}
			} else if r.Method == "POST" {
				// User is trying to log in
				if r.FormValue("token") == ADMIN_PASS {
					var token string = uuid.NewString()
					// Simulate an administrator logging in
					authorizedTokens[token] = []string{
						"/yapilyAuth",
						"/authCallback",
						"/ping",
					}
					w.Header().Set("Set-Cookie", "ProxyAuth="+token)
					// Should have a ?redirect= param?
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					http.Error(w, "invalid credentials", http.StatusBadRequest)
				}
			}
		} else if r.URL.Path == "/" {
			w.Write([]byte("<h1>API Gateway</h1>"))
			w.Write([]byte("<a href=/yapilyAuth>yapily auth</a>"))
			w.Write([]byte("<br>"))
			w.Write([]byte("<a href=/authCallback>callback</a>"))
			w.Write([]byte("<br>"))
			w.Write([]byte("<a href=/ping>ping</a>"))
		} else {
			proxyAuthCookie, err := r.Cookie("ProxyAuth")
			if err != nil {
				// TODO: could redirect to /auth here
				http.Error(w, "no such cookie ProxyAuth: "+err.Error(), http.StatusBadRequest)
				return
			}
			authorizedPayloads, ok := authorizedTokens[proxyAuthCookie.Value]
			if ok {
				if serviceURL, found := endpoints[r.URL.Path]; found {
					backendURL, err := url.Parse(serviceURL)
					if err != nil {
						panic(err)
					}

					fmt.Println(r.URL.Path)
					if slices.Contains(authorizedPayloads, r.URL.Path) {
						backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
						fmt.Println(backendURL)
						backendRedirect.ServeHTTP(w, r)
					} else {
						http.Error(w, "anauthorized payload", http.StatusUnauthorized)
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
