package handlers

var (
	ErrorInvalidBody        = "invalid body data in request"
	ErrorUnhandledOperation = "unhandled operation"
)

// Generic type for error body
type ErrorBody struct {
	ErrorMsg *string `json:"error,omitempty"`
}
