package main

import (
	"context"
	"bytes"
	"encoding/json"
	"encoding/base64"
	"io"
	"net/http"
	"time"
	"errors"
)

type PaymentAuthRequests struct {
	Meta PaymentAuthMeta `json:"meta"`
	Data PaymentAuthData `json:"data"`
}
type PaymentAuthMeta struct {
	TracingID string `json:"tracingId"`
}
type PaymentAuthData struct {
	ID                   string    `json:"id"`
	UserUUID             string    `json:"userUuid"`
	ApplicationUserID    string    `json:"applicationUserId"`
	InstitutionID        string    `json:"institutionId"`
	Status               string    `json:"status"`
	CreatedAt            time.Time `json:"createdAt"`
	FeatureScope         []string  `json:"featureScope"`
	State                string    `json:"state"`
	InstitutionConsentID string    `json:"institutionConsentId"`
	AuthorisationURL     string    `json:"authorisationUrl"`
	QrCodeURL            string    `json:"qrCodeUrl"`
}

const exampleRequest = `
{
  "applicationUserId": "string",
  "institutionId": "bpm-sandbox",
  "callback": "https://display-parameters.com/",
  "paymentRequest": {
    "paymentIdempotencyId": "234g87t58tgeuo848wudjew489",
    "payer": {
      "name": "John Doe",
      "accountIdentifications": [
        {
          "type": "IBAN",
          "identification": "DE89370400440532013000"
        }
      ]
    },
    "amount": {
      "amount": 1,
      "currency": "EUR"
    },
    "reference": "Bill Payment",
    "type": "DOMESTIC_PAYMENT",
    "payee": {
      "name": "Jane Doe",
      "address": {
        "country": "BE"
      },
      "accountIdentifications": [
        {
          "type": "IBAN",
          "identification": "BE68539007547034"
        }
      ]
    }
  }
}
`

func (ac *ApiClient) getPaymentAuth() (*PaymentAuthRequests, error) {
	req, err := http.NewRequest("POST", "https://api.yapily.com/payment-auth-requests", bytes.NewBufferString(exampleRequest))
	if err != nil {
		return nil, err
	}
	var basicAuth string = base64.RawURLEncoding.EncodeToString([]byte(ac.appUuid + ":" + ac.appSecret))
	req.Header.Set("Authorization", "Basic "+basicAuth)
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")

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

	if resp.StatusCode != 201 {
		// errorResp := new(ErrorResp)
		// err = json.Unmarshal(jsonBody, &errorResp)
		return nil, errors.New(string(jsonBody))
	}

	paymentAuthRequests := new(PaymentAuthRequests)
	err = json.Unmarshal(jsonBody, &paymentAuthRequests)
	if err != nil {
		return nil, err
	}
	return paymentAuthRequests, nil
}
