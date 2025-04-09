package main

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
		limiter = rate.NewLimiter(rate.Every(time.Second*10), 5)
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

// TODO: add which endpoints the token is authorized for
var authorizedTokens map[string]bool = map[string]bool{}

var endpoint = map[string]string{
	"/":                "http://backend-service:8081",
	"/authCallback":    "http://backend-service:8081",
	"/getAuthRequests": "http://ping-service:8082",
}

func main() {
	// Define the backend service URL
	/*	backendURL, err := url.Parse("http://backend-service:8081")
		if err != nil {
			panic(err)
		}

		backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
	*/ // Request handler for the API Gateway
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
				t := template.Must(template.New("auth").Parse(authTemplate))
				err := t.Execute(w, nil)
				if err != nil {
					log.Println("Failee at executing form template" + err.Error())
				}
			} else if r.Method == "POST" {
				log.Println(r.Body)
				if r.FormValue("token") == "1234" {
					var token string = uuid.NewString()
					authorizedTokens[token] = true
					w.Header().Set("Set-Cookie", "ProxyAuth="+token)
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					http.Error(w, "invalid credentials", http.StatusBadRequest)
				}
			}
		} else {
			proxyAuthCookie, err := r.Cookie("ProxyAuth")
			if err != nil {
				http.Error(w, "no such cookie ProxyAuth: "+err.Error(), http.StatusInternalServerError)
				return
			}
			_, ok := authorizedTokens[proxyAuthCookie.Value]
			if ok {
				if serviceURL, found := endpoint[r.URL.Path]; found {
					backendURL, err := url.Parse(serviceURL)
					if err != nil {
						panic(err)
					}
					backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)

					backendRedirect.ServeHTTP(w, r)
				} else {
					http.Error(w, "invalid redirect", http.StatusUnauthorized)
					log.Println("invalid redirect path: " + r.URL.Path)
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
