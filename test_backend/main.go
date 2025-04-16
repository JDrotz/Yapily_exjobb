package main

import (
	"log"
	"net/http"
	"os"

	_ "github.com/joho/godotenv/autoload"
)

type ApiClient struct {
	appUuid   string
	appSecret string
}

func main() {
	appUuid, uuidSet := os.LookupEnv("APP_UUID")
	appSecret, secretSet := os.LookupEnv("APP_SECRET")

	if !uuidSet || !secretSet {
		log.Fatal("API_KEY and API_SECRET must be set in the environment")
	}

	var ac ApiClient = ApiClient{
		appUuid,
		appSecret,
	}

	http.HandleFunc("/yapilyAuth", ac.indexHandler)
	http.HandleFunc("/authCallback", ac.authCallbackHandler)
	http.HandleFunc("/authCallback/", ac.authCallbackHandler)

	port := "8081"
	log.Println("Server starting on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
