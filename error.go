package main

type ErrorResp struct {
	Error struct {
		TracingID        string `json:"tracingId"`
		Code             int    `json:"code"`
		InstitutionError struct {
			ErrorMessage   string `json:"errorMessage"`
			HTTPStatusCode int    `json:"httpStatusCode"`
		} `json:"institutionError"`
		Source  string `json:"source"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}
