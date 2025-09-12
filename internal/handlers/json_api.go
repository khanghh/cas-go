package handlers

// Google JSON API style response structures
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status,omitempty"`
}

type APIResponse struct {
	APIVersion string         `json:"apiVersion"`
	Data       interface{}    `json:"data,omitempty"`
	Error      *ErrorResponse `json:"error,omitempty"`
}
