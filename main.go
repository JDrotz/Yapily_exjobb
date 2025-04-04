package main

import (
	"fmt"
	"log"
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

	institutions, err := ac.getInstitutions()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("1%v\n", institutions)

	var paymentAuthReqs *PaymentAuthRequests
	paymentAuthReqs, err = ac.getPaymentAuth()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("2%v\n", paymentAuthReqs)
}
