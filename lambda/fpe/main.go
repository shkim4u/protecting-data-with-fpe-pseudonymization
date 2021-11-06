package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/capitalone/fpe/ff1"
)

func handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("EF4359D8D580AA4F7F036D6F04FC6A94")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := ff1.NewCipher(10, 8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := "123456789"

	// Call the encryption function on an example SSN
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original:", original)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)

	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       "CDK",
	}, nil
}

func main() {
	lambda.Start(handler)
}
