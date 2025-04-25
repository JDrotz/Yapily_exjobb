package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"
)

type AccountAuthRequests struct {
	Meta AccountAuthMeta `json:"meta"`
	Data AccountAuthData `json:"data"`
}
type AccountAuthMeta struct {
	TracingID string `json:"tracingId"`
}
type AccountAuthData struct {
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

var indexTemplate = `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Select Sandbox</title>
</head>
<body>
	<h1>Select a Sandbox</h1>
	<form method="POST" action="/yapilyAuth">
		<label for="institutionId">Choose a sandbox:</label>
		<select name="institutionId" id="institutionId">
			{{ range . }}
				<option value="{{ .ID }}">{{ .Name }} ({{ .EnvironmentType }})</option>
			{{ end }}
		</select>
		<br><br>
		<input type="submit" value="Authenticate">
	</form>
</body>
</html>
`

type ConsentAuthCode struct {
	ID                string    `json:"id"`
	UserUUID          string    `json:"userUuid"`
	ApplicationUserID string    `json:"applicationUserId"`
	InstitutionID     string    `json:"institutionId"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"createdAt"`
	FeatureScope      []string  `json:"featureScope"`
	ConsentToken      string    `json:"consentToken"`
	State             string    `json:"state"`
	AuthorizedAt      time.Time `json:"authorizedAt"`
	LastConfirmedAt   time.Time `json:"lastConfirmedAt"`

	TimeToExpire         *string `json:"timeToExpire,omitempty"`
	InstitutionConsentID *string `json:"institutionConsentId,omitempty"`
}

func (ac *ApiClient) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		institutions, err := ac.getInstitutions()
		if err != nil {
			log.Println("Error getting institutions" + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		t, err := template.New("index").Parse(indexTemplate)
		if err != nil {
			log.Println("Error creating new form template" + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if err = t.Execute(w, institutions.Data); err != nil {
			log.Println("Failed at executing form template" + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			log.Println("Error parsing form: " + err.Error())
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		institutionId := r.FormValue("institutionId")
		if institutionId == "" {
			log.Println("Missing institutionId in request")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		authUrl, err := ac.createAuthRequest(institutionId)
		if err != nil {
			log.Println("Failed to create auth request: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authUrl, http.StatusFound)
	}
}

func (ac *ApiClient) authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	url := "https://api.yapily.com/consent-auth-code"

	authState := r.URL.Query().Get("state")
	authCode := r.URL.Query().Get("code")

	if authState == "" {
		log.Println("Request callback missing state")
		http.Error(w, "Bad request", http.StatusBadRequest)
	}

	request := map[string]any{
		"authCode":  authCode,
		"authState": authState,
	}
	bodyBytes, err := json.Marshal(request)
	if err != nil {
		log.Println("Failed to marshal json: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Println("Failed to create request: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	var basicAuth string = base64.RawURLEncoding.EncodeToString([]byte(ac.appUuid + ":" + ac.appSecret))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Failed to make request: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read request: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var consentAuth ConsentAuthCode
	err = json.Unmarshal(respBody, &consentAuth)
	if err != nil {
		log.Println("Failed to unmarshal consentAuth: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<!DOCTYPE html>"))
	w.Write([]byte("<h1>Consent Token</h1>"))
	w.Write([]byte(consentAuth.ConsentToken))
}

func (ac *ApiClient) createAuthRequest(institutionId string) (string, error) {
	url := "https://api.yapily.com/account-auth-requests"

	request := map[string]any{
		"applicationUserId": "Authflow_test@liu.se",
		"institutionId":     institutionId,
		"redirect":          "https://gateway.hoppenr.xyz/authCallback/",
	}
	bodyBytes, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	if institutionId == "deutschebank-sandbox" {
		// Sandbox PSU-ID
		req.Header.Set("psu-id", "6154033403")
	}

	var basicAuth string = base64.RawURLEncoding.EncodeToString([]byte(ac.appUuid + ":" + ac.appSecret))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated {
		errorResp := new(ErrorResp)
		err = json.Unmarshal(respBody, &errorResp)
		return "", errorResp
	}

	var authResp AccountAuthRequests
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return "", err
	}

	return authResp.Data.AuthorisationURL, nil
}
