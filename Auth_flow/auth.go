package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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
	<form method="POST" action="/">
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

func (ac *ApiClient) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		institutions, err := ac.getInstitutions()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("institutions: %v\n", institutions)
		t := template.Must(template.New("index").Parse(indexTemplate))
		err = t.Execute(w, institutions.Data)
		if err != nil {
			fmt.Println("Failed at executing form template" + err.Error())
		}
		return
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
			return
		}
		institutionId := r.FormValue("institutionId")
		authUrl, err := ac.createAuthRequest(institutionId)
		if err != nil {
			http.Error(w, "Failed to create auth request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authUrl, http.StatusFound)
	}
}

func (ac *ApiClient) authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	consent := r.URL.Query().Get("consent")
	if consent == "" {
		consent = "No token provided"
	}
	w.Write([]byte("Authentication successful. Consent: " + consent))
}

func (ac *ApiClient) createAuthRequest(institutionId string) (string, error) {
	url := "https://api.yapily.com/account-auth-requests"

	request := map[string]any{
		"applicationUserId": "Authflow_test@liu.se",
		"institutionId":     institutionId,
		"callback":          "https://display-parameters.com/",
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
