package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"
)

type EndpointData struct {
	url            string
	allowedMethods []string
}

// var allMethods = []string{
// 	http.MethodGet,
// 	http.MethodHead,
// 	http.MethodPost,
// 	http.MethodPut,
// 	http.MethodPatch,
// 	http.MethodDelete,
// 	http.MethodConnect,
// 	http.MethodOptions,
// 	http.MethodTrace,
// }

// NOTE: /auth and / are reserved
var endpoints = map[string]EndpointData{
	"/yapilyAuth": {
		url:            "http://backend-service:8081/",
		allowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
	},
	"/authCallback": {
		url:            "http://backend-service:8081/",
		allowedMethods: []string{http.MethodGet, http.MethodOptions},
	},
	"/ping": {
		url:            "http://ping-service:8082/",
		allowedMethods: []string{http.MethodGet, http.MethodOptions},
	},
}

// Helper function to disallow all unhandled methods for a path
func DenyMethod(allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Helper function to handle OPTIONS requests
func OptionsHandler(allowedMethods []string, allowedHeaders []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		methods := strings.Join(allowedMethods, ", ")
		headers := strings.Join(allowedHeaders, ", ")
		w.Header().Set("Allow", methods)
		w.Header().Set("Access-Control-Allow-Methods", methods)
		w.Header().Set("Access-Control-Allow-Headers", headers)
		w.WriteHeader(http.StatusNoContent)
	}
}

// Helper function to handle OPTIONS requests with Authentication allowed
func OptionsHandlerAuth(allowedMethods []string, allowedHeaders []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		methods := strings.Join(allowedMethods, ", ")
		headers := strings.Join(allowedHeaders, ", ")
		w.Header().Set("Allow", methods)
		w.Header().Set("Access-Control-Allow-Methods", methods)
		w.Header().Set("Access-Control-Allow-Headers", headers)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusNoContent)
	}
}

// GET "/"
func RootHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<!DOCTYPE html>"))
			w.Write([]byte("<h1>API Gateway</h1>"))
			w.Write([]byte("<a href=/auth>log in</a>"))

			proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
			if err == http.ErrNoCookie {
				log.Println("Proxy auth cookie not found: " + err.Error())
				return
			}

			if err = CheckCookie(proxyAuthCookie); err != nil {
				log.Println("Bad proxy auth cookie: " + err.Error())
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}

			claims, err := ParseJWT(jwtKey, proxyAuthCookie.Value)
			if err != nil {
				log.Println("Error parsing JWT: " + err.Error())
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			w.Write([]byte("<br>"))
			for _, path := range claims.AllowedPaths {
				fmt.Fprintf(w, `<a href="%s">%s</a><br>`, path, path)
			}
		} else {
			http.Error(w, "Not acceptable", http.StatusNotAcceptable)
		}
	}
}

// GET "/favicon.ico"
func FaviconHandler(filepath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath)
	}
}

// GET "/auth"
func AuthPageHandler(authTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			tpl, err := template.New("auth").Parse(authTemplate)
			if err != nil {
				log.Println("Failed at creating form template: " + err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			err = tpl.Execute(w, nil)
			if err != nil {
				log.Println("Failed at executing form template: " + err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("usage: curl -d 'token=<TOKEN>' <HOST>/auth"))
			return
		}
	}
}

// Mock "API tokens"
const ADMIN_PASS = "1234"
const USER_PASS = "2345"

// POST "/auth"
func AuthSubmitHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var jwtToken string
		var err error

		log.Println("AUDIT: Validation requested by: " + r.RemoteAddr)
		switch r.FormValue("token") {
		case ADMIN_PASS:
			jwtToken, err = GenerateJWT(jwtKey, []string{"/yapilyAuth", "/authCallback", "/ping"})
		case USER_PASS:
			jwtToken, err = GenerateJWT(jwtKey, []string{"/ping"})
		default:
			log.Println("AUDIT: Validation error by: " + r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Println("Failed at generating JWT: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			cookie := &http.Cookie{
				Name:     "__Host-ProxyAuth",
				Value:    jwtToken,
				Path:     "/",
				MaxAge:   900,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(15 * time.Minute),
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			response := map[string]any{
				"token":      jwtToken,
				"token_type": "Bearer",
				"expires_in": 900,
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Println("Failed to encode JSON response")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}
		log.Println("AUDIT: Validation granted to: " + r.RemoteAddr)
	}
}

// VERB anything not in ["/", "/auth"]
func ProxyHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Println("Bad host data in request: " + err.Error())
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			log.Println("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		var jwtToken string
		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
			if err != nil {
				log.Println("Proxy auth cookie not found: " + err.Error())
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			if err = CheckCookie(proxyAuthCookie); err != nil {
				log.Println("Bad proxy auth cookie: " + err.Error())
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			jwtToken = proxyAuthCookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				log.Println("Bad bearer token")
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
		}

		claims, err := ParseJWT(jwtKey, jwtToken)
		if err != nil {
			log.Println("Error parsing JWT: " + err.Error())
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var trimmedPath = strings.TrimRight(r.URL.Path, "/")
		if endpoint, found := endpoints[trimmedPath]; found {
			if !slices.Contains(endpoint.allowedMethods, r.Method) {
				DenyMethod(endpoint.allowedMethods)(w, r)
				return
			}
			backendURL, err := url.Parse(endpoint.url)
			if err != nil {
				log.Println("Failed at parsing serviceURL: " + err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if slices.Contains(claims.AllowedPaths, trimmedPath) {
				backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
				backendRedirect.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
				return
			}
		} else {
			http.NotFound(w, r)
			return
		}
	}
}
