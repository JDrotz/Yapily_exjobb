package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
        "time"

	_ "github.com/joho/godotenv/autoload"
)

type Institutions struct {
	Meta Meta          `json:"meta"`
	Data []Institution `json:"data"`
}
type Pagination struct {
	TotalCount int `json:"totalCount"`
}
type Meta struct {
	TracingID  string     `json:"tracingId"`
	Count      int        `json:"count"`
	Pagination Pagination `json:"pagination"`
}
type Countries struct {
	DisplayName  string `json:"displayName"`
	CountryCode2 string `json:"countryCode2"`
}
type Media struct {
	Source string `json:"source"`
	Type   string `json:"type"`
}
type Institution struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	FullName        string      `json:"fullName"`
	Countries       []Countries `json:"countries"`
	EnvironmentType string      `json:"environmentType"`
	CredentialsType string      `json:"credentialsType"`
	Media           []Media     `json:"media"`
	Features        []string    `json:"features"`
}

func main() {
	appUuid, uuidSet := os.LookupEnv("APP_UUID")
	appSecret, secretSet := os.LookupEnv("APP_SECRET")

	if !uuidSet || !secretSet {
		log.Fatal("API_KEY and API_SECRET must be set in the environment")
	}

	institutions, err := get_institutions(appUuid, appSecret)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%v\n", institutions)
}

func get_institutions(appUuid string, appSecret string) (*Institutions, error) {
	req, err := http.NewRequest("GET", "https://api.yapily.com/institutions", nil)
	if err != nil {
		return nil, err
	}
	var basicAuth string = base64.RawURLEncoding.EncodeToString([]byte(appUuid + ":" + appSecret))
	req.Header.Set("Authorization", "Basic "+basicAuth)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	jsonBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	institutions := new(Institutions)
	err = json.Unmarshal(jsonBody, &institutions)
	if err != nil {
		return nil, err
	}
	return institutions, nil
}
