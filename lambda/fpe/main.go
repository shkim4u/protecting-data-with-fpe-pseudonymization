package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/shkim4u/protecting-data-with-fpe-pseudonymization/pkg/handlers"
)

// Structure to hold parameter as JSON
type FpeRequestParams struct {
	Input string `json:"input"`
	Radix int    `json:"radix"`
}

func handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// [2021-11-23] For debug only while developing
	// Remove when done
	fmt.Println("--- Request[Begin] ---")
	fmt.Println(req)
	fmt.Println("--- Request[End] ---")

	var params FpeRequestParams
	if err := json.Unmarshal([]byte(req.Body), &params); err != nil {
		return handlers.HandleError(http.StatusBadRequest, errors.New(handlers.ErrorInvalidBody))
	}

	fmt.Println("--- Params[Begin] ---")
	fmt.Println(params)
	fmt.Println("--- Params[END] ---")

	path := req.RequestContext.HTTP.Path
	switch path {
	case "/encrypt":
		return handlers.Encrypt(params.Input, params.Radix, ctx, req)

	case "/decrypt":
		return handlers.Decrypt(params.Input, params.Radix, ctx, req)

	default:
		return handlers.UnhandledOperation()
	}
}

func main() {
	lambda.Start(handler)
}
