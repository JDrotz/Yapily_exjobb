package main

import (
	"net/http"
)

type ErrorResp struct {
	ErrorInfo struct {
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

func (e *ErrorResp) Error() string {
	return "HTTP " + http.StatusText(e.ErrorInfo.Code) + ": " + e.ErrorInfo.Message + ": " + e.ErrorInfo.InstitutionError.ErrorMessage
}
