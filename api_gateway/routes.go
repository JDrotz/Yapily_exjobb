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

// Helper function to disallow all unhandled methods for a path
func DenyMethod(allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", strings.Join(allowedMethods, ","))
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// GET "/"
func RootHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!DOCTYPE html>"))
		w.Write([]byte("<h1>API Gateway</h1>"))
		w.Write([]byte("<a href=/auth>log in</a>"))

		proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
		if err != nil {
			log.Println(err)
			return
		}
		if err = CheckCookie(proxyAuthCookie); err != nil {
			log.Println(err)
			return
		}

		claims, err := ParseJWT(jwtKey, proxyAuthCookie.Value)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("<br>"))
		for _, path := range claims.AllowedPaths {
			fmt.Fprintf(w, `<a href="%s">%s</a><br>`, path, path)
		}
	}
}

// GET "/auth"
func AuthPageHandler(authTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			tpl, err := template.New("auth").Parse(authTemplate)
			if err != nil {
				log.Fatalln("Failed at creating form template: " + err.Error())
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			err = tpl.Execute(w, nil)
			if err != nil {
				log.Fatalln("Failed at executing form template: " + err.Error())
			}
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("usage: curl -X POST -d 'token=<token>' /auth"))
		}
	}
}

// POST "/auth"
func AuthSubmitHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var jwtToken string
		var err error

		switch r.FormValue("token") {
		case ADMIN_PASS:
			jwtToken, err = GenerateJWT(jwtKey, []string{"/yapilyAuth", "/authCallback", "/ping"})
		case USER_PASS:
			jwtToken, err = GenerateJWT(jwtKey, []string{"/ping"})
		default:
			http.Error(w, "invalid credentials", http.StatusBadRequest)
			return
		}
		if err != nil {
			log.Fatalln("Failed at generating JWT: " + err.Error())
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
			response := map[string]string{"token": jwtToken}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				http.Error(w, "Failed to encode JSON response", http.StatusInternalServerError)
			}
		}
	}
}

// VERB anything not in ["/", "/auth"]
func ProxyHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
		}
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		var jwtToken string
		accept := r.Header.Get("accept")
		if strings.Contains(accept, "text/html") {
			proxyAuthCookie, err := r.Cookie("__Host-ProxyAuth")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if err = CheckCookie(proxyAuthCookie); err != nil {
				http.NotFound(w, r)
				return
			}
			jwtToken = proxyAuthCookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.NotFound(w, r)
				return
			}
			jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
		}

		claims, err := ParseJWT(jwtKey, jwtToken)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		var trimmedPath = strings.TrimRight(r.URL.Path, "/")
		if serviceURL, found := endpoints[trimmedPath]; found {
			backendURL, err := url.Parse(serviceURL)
			if err != nil {
				log.Fatalln("Failed at parsing serviceURL: " + err.Error())
			}

			if slices.Contains(claims.AllowedPaths, trimmedPath) {
				backendRedirect := httputil.NewSingleHostReverseProxy(backendURL)
				backendRedirect.ServeHTTP(w, r)
			} else {
				http.Error(w, "unauthorized payload", http.StatusUnauthorized)
			}
		} else {
			http.Error(w, "invalid payload", http.StatusUnauthorized)
		}
	}
}
