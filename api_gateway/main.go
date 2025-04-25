package main

import (
	"log"
	"net/http"
	"os"
)

var allMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

func main() {
	key, jwtKeySet := os.LookupEnv("JWT_KEY")
	jwtKey := []byte(key)
	if !jwtKeySet {
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

	// "/"
	rootMethods := []string{http.MethodGet, http.MethodOptions}
	rootHeaders := []string{"Accept", "Content-Type"}
	mux.HandleFunc("GET /{$}", RootHandler(jwtKey))
	mux.HandleFunc("OPTIONS /{$}", OptionsHandler(rootMethods, rootHeaders))
	mux.HandleFunc("/{$}", DenyMethod(rootMethods))

	// "/auth"
	authMethods := []string{http.MethodGet, http.MethodPost, http.MethodOptions}
	authHeaders := []string{"Accept", "Content-Type"}
	mux.HandleFunc("GET /auth", AuthPageHandler(authTemplate))
	mux.HandleFunc("POST /auth", AuthSubmitHandler(jwtKey))
	mux.HandleFunc("OPTIONS /auth", OptionsHandler(authMethods, authHeaders))
	mux.HandleFunc("/auth", DenyMethod(authMethods))

	// "/favicon.ico"
	mux.HandleFunc("GET /favicon.ico", FaviconHandler("assets/favicon.ico"))
	mux.HandleFunc("/favicon.ico", DenyMethod([]string{http.MethodGet}))

	// "/*"
	proxyHeaders := []string{"Authorization"}
	mux.HandleFunc("OPTIONS /", OptionsHandlerAuth(allMethods, proxyHeaders))
	mux.HandleFunc("/", ProxyHandler(jwtKey))

	http.ListenAndServe(":8083", mux)
}
