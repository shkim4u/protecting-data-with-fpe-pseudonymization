/*
Package handlers implements format-preserving encryption/decryption.

References for AWS Secrets Manager:
- https://github.com/aws/aws-sdk-go/blob/main/service/secretsmanager/examples_test.go
- https://gist.github.com/xlyk/f2f2246ee259415c05f84eb21218ac73
- https://docs.aws.amazon.com/sdk-for-go/api/service/secretsmanager/
- https://aws.amazon.com/blogs/security/how-to-securely-provide-database-credentials-to-lambda-functions-by-using-aws-secrets-manager/

References for AWS KMS:
- https://github.com/meltwater/secretary/blob/master/kms.go
- Generate data encryption key for FPE.
- https://docs.aws.amazon.com/sdk-for-go/api/service/kms/
- https://globaldatanet.com/tech-blog/using-aws-kms-with-golang

*/
package handlers

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/capitalone/fpe/ff1"
)

var (
	kmsClient            = newKmsClient()
	secretsManagerClient = newSecretsManagerClient()

	// FPE encryption/decryption key bytes as plain in global state.
	// NOTE: This is only for faster operation, and have to be encrypted form instead if this concerns you.
	dekBlob []byte
)

func init() {
	fmt.Println("{Handlers} Initializing to acquire FPE data encryption key.")

	var dekEnvelopeBlob []byte
	exist, secretValue := secretsManagerClient.CheckIfSecretValueExist(os.Getenv("FPE_DEK_SECRET_NAME"))
	if exist {
		// FPE data encryption key sucessfully retrieved from Secrets Manager.
		// Parse it as byte array.
		fmt.Println("Encrypted FPE Data Encryption Key: ", *secretValue)

		// [2021-11-20] Decrypt FPE data encryption key.
		dekEnvelopeBlob, _ = hex.DecodeString(*secretValue)
	} else {
		// Secret value for FPE data encryption key does not exist, create a new one
		dekEnvelopeBlob = kmsClient.GenerateDEK(os.Getenv("FPE_MASTER_KEY_ARN"))
		secretsManagerClient.CreateSecretWithValue(
			os.Getenv("FPE_DEK_SECRET_NAME"),
			hex.EncodeToString(dekEnvelopeBlob),
			"FPE data enryption key protected by KMS CMK.",
		)
	}

	dekBlob = kmsClient.DecryptDEK(dekEnvelopeBlob)
}

func Encrypt(
	input string,
	radix int,
	ctx context.Context, // Reserved.
	req events.APIGatewayV2HTTPRequest, // Reserved.
) (
	events.APIGatewayV2HTTPResponse,
	error,
) {
	var resp FpeResponse

	// Key and tweak should be byte arrays. Put your key and tweak here.
	key := dekBlob
	tweak, err := hex.DecodeString(os.Getenv("FPE_TWEAK"))
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	// Create a new FF1 cipher "object"
	FF1, err := ff1.NewCipher(radix, binary.Size(tweak), key, tweak)
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	plaintext := input

	// Call the encryption function on a plaintext
	ciphertext, err := FF1.Encrypt(plaintext)
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	// WARNING) For debugging only
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Ciphertext:", ciphertext)

	// Set response.
	resp.Operation = "Encrypt"
	resp.Plaintext = plaintext
	resp.Ciphertext = ciphertext
	resp.Radix = radix

	return apiResponse(
		http.StatusOK,
		&resp,
	)
}

func Decrypt(
	input string,
	radix int,
	ctx context.Context, // Reserved.
	req events.APIGatewayV2HTTPRequest, // Reserved.
) (
	events.APIGatewayV2HTTPResponse,
	error,
) {
	var resp FpeResponse

	// Key and tweak should be byte arrays. Put your key and tweak here.
	key := dekBlob
	tweak, err := hex.DecodeString("D8E7920AFA330A73")
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	FF1, err := ff1.NewCipher(radix, 8, key, tweak)
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	ciphertext := input

	// Call the encryption function on an example SSN
	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	// WARNING) For debugging only
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)

	// Set response.
	resp.Operation = "Decrypt"
	resp.Plaintext = plaintext
	resp.Ciphertext = ciphertext
	resp.Radix = radix

	return apiResponse(
		http.StatusOK,
		&resp,
	)
}

func UnhandledOperation() (events.APIGatewayV2HTTPResponse, error) {
	return apiResponse(http.StatusMethodNotAllowed, ErrorUnhandledOperation)
}

func HandleError(status int, err error) (events.APIGatewayV2HTTPResponse, error) {
	return apiResponse(status, ErrorBody{aws.String(err.Error())})
}
