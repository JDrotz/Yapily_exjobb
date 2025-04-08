package main

import (
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "sync"
    "time"
    "net"

    "golang.org/x/time/rate"
)

var mu sync.Mutex
var clientLimits = make(map[string]*rate.Limiter)

func getLimiter(clientIP string) *rate.Limiter {
    mu.Lock()
    defer mu.Unlock()

    limiter, exists := clientLimits[clientIP]
    if !exists {
        limiter = rate.NewLimiter(rate.Every(time.Second*1), 2)
        clientLimits[clientIP] = limiter
    }
    return limiter
}

func main() {
    // Define the backend service URL
    backendURL, err := url.Parse("http://backend-service:8081")
    if err != nil {
        panic(err)
    }

    redirect := httputil.NewSingleHostReverseProxy(backendURL)

    // Request handler for the API Gateway
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	clientIP,_,_ := net.SplitHostPort(r.RemoteAddr)
	log.Printf("Request from %s: %s", clientIP, r.URL.Path)

        limiter := getLimiter(clientIP)
	allowed := limiter.Allow()
        if !limiter.Allow() {
	    log.Printf("Rate limit exceeded by %s", clientIP)
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
	log.Printf("limiter allowed for %s: %v", clientIP, allowed)

	if (r.URL.Path == "/getAuthRequests" || r.URL.Path == "/auth") && r.Header.Get("authentication") == "true" {
            redirect.ServeHTTP(w, r)
        } else {
	    log.Printf("Invalid request from %s: %s", clientIP, r.URL.Path)
            http.Error(w, "Invalid request", http.StatusBadRequest)
        }
    })

    // Start API Gateway server
    log.Println("Starting API Gateway on :8080")
    http.ListenAndServe(":8080", nil)
}
