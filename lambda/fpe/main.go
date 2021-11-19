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

var (
	ErrorInvalidBody = "invalid body data in request"
)

type FpeRequestParams struct {
	// Operation string `json:"operation"`
	Input string `json:"input"`
	Radix int    `json:"radix"`
}

func init() {
	handlers.Init()
}

// func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
func handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// func handler(params Params) (events.APIGatewayV2HTTPResponse, error) {

	// TODO: Discriminate methods - GET, POST, PUT, DELETE

	fmt.Println("--- Context[Begin] ---")
	fmt.Println(ctx)
	fmt.Println("--- Context[End] ---")

	fmt.Println("--- Request[Begin] ---")
	fmt.Println(req)
	fmt.Println("--- Request[End] ---")

	var params FpeRequestParams
	if err := json.Unmarshal([]byte(req.Body), &params); err != nil {
		return handlers.HandleError(http.StatusBadRequest, errors.New(ErrorInvalidBody))
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

	// [2021-11-17]: Discriminate operations with path instead of parameter in body.
	/*
		switch params.Operation {
		case "Encrypt":
			return handlers.Encrypt(params.Input, params.Radix, ctx, req)

		case "Decrypt":
			return handlers.Decrypt(params.Input, params.Radix, ctx, req)

		default:
			return handlers.UnhandledOperation()
		}
	*/
}

func main() {
	lambda.Start(handler)
}
