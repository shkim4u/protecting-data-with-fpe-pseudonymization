package handlers

import (
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
)

type FpeResponse struct {
	Operation  string `json:"operation"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	Radix      int    `json:"radix"`
}

func apiResponse(status int, body interface{}) (events.APIGatewayV2HTTPResponse, error) {
	resp := events.APIGatewayV2HTTPResponse{Headers: map[string]string{"Content-Type": "application/json"}}
	resp.StatusCode = status

	stringBody, _ := json.Marshal(body)
	resp.Body = string(stringBody)
	return resp, nil
}
