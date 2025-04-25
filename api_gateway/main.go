package main

import (
	"log"
	"net/http"
	"os"
)

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

	mux.HandleFunc("GET /{$}", RootHandler(jwtKey))
	mux.HandleFunc("/{$}", DenyMethod([]string{http.MethodGet}))

	mux.HandleFunc("GET /auth", AuthPageHandler(authTemplate))
	mux.HandleFunc("POST /auth", AuthSubmitHandler(jwtKey))
	mux.HandleFunc("/auth", DenyMethod([]string{http.MethodGet, http.MethodPost}))

	mux.HandleFunc("GET /favicon.ico", FaviconHandler("assets/favicon.ico"))
	mux.HandleFunc("/favicon.ico", DenyMethod([]string{http.MethodGet}))

	mux.HandleFunc("/", ProxyHandler(jwtKey))

	http.ListenAndServe(":8083", mux)
}
