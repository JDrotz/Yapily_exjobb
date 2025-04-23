package main

import (
	"fmt"
	"html/template"
	"log"
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
			fmt.Fprintf(w, `<a href="%s">%s</a><br>`, path, path)
		}
	}
}

// GET "/auth"
func AuthPageHandler(authTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// User is requesting the auth page
		// TODO: Use Content-Type and Accept instead
		UA := strings.Split(r.UserAgent(), "/")[0]
		if UA == "curl" {
			w.Write([]byte("usage: curl -X POST -F token=<token> /auth"))
		} else {
			t, err := template.New("auth").Parse(authTemplate)
			if err != nil {
				log.Fatalln("Failed at creating form template: " + err.Error())
			}
			err = t.Execute(w, nil)
			if err != nil {
				log.Fatalln("Failed at executing form template: " + err.Error())
			}
		}
	}
}

// POST "/auth"
func AuthSubmitHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenString string
		var err error

		switch r.FormValue("token") {
		case ADMIN_PASS:
			tokenString, err = GenerateJWT(jwtKey, []string{"/yapilyAuth", "/authCallback", "/ping"})
		case USER_PASS:
			tokenString, err = GenerateJWT(jwtKey, []string{"/ping"})
		default:
			http.Error(w, "invalid credentials", http.StatusBadRequest)
			return
		}
		if err != nil {
			log.Fatalln("Failed at generating JWT: " + err.Error())
		}

		UA := strings.Split(r.UserAgent(), "/")[0]
		if UA == "curl" {
			w.Write([]byte(tokenString))
		} else {
			cookie := &http.Cookie{
				Name:     "__Host-ProxyAuth",
				Value:    tokenString,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(15 * time.Minute),
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
}

// VERB anything not in ["/", "/auth"]
func ProxyHandler(jwtKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if serviceURL, found := endpoints[trimmedPath]; found {
			backendURL, err := url.Parse(serviceURL)
			if err != nil {
				log.Fatalln("Failed at parsing serviceURL: " + err.Error())
			}

			if slices.Contains(allowedPaths, trimmedPath) {
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
