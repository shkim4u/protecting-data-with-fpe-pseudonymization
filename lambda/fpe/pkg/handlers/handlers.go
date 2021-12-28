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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/capitalone/fpe/ff1"
	"golang.org/x/crypto/nacl/secretbox"
)

type KmsPayload struct {
	EncryptedDataKey []byte
	Nonce            *[24]byte
	Message          []byte
}

var (
	kmsClient            = newKmsClient()
	secretsManagerClient = newSecretsManagerClient()

	// FPE encryption/decryption key bytes as plain in global state.
	// NOTE: This is only for faster operation, and have to be encrypted form instead if this concerns you.
	dekBlob         []byte
	dekEnvelopeBlob []byte
)

func init() {
	fmt.Println("{Handlers} Initializing to acquire FPE data encryption key.")

	// var dekEnvelopeBlob []byte
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

func EnvelopeEncrypt(
	input string,
	ctx context.Context, // Reserved.
	req events.APIGatewayV2HTTPRequest, // Reserved.
) (
	events.APIGatewayV2HTTPResponse,
	error,
) {
	var resp FpeResponse

	// fmt.Println("[EnvelopeEncrypt] dekEnvelopeBlob: ", hex.EncodeToString(dekEnvelopeBlob))
	// fmt.Println("[EnvelopeEncrypt] dekBlob: ", hex.EncodeToString(dekBlob))

	// Initialize payload.
	payload := &KmsPayload{
		EncryptedDataKey: dekEnvelopeBlob,
		Nonce:            &[24]byte{},
	}

	// Generate nonce.
	_, err := io.ReadFull(rand.Reader, payload.Nonce[:])
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New("failed to generate random nonce: "+err.Error()))
	}

	plaintext := input
	plainbytes := []byte(plaintext)

	var dataKey [32]byte
	copy(dataKey[:], dekBlob)

	// Encrypt message.
	payload.Message = secretbox.Seal(
		payload.Message,
		plainbytes,
		payload.Nonce,
		// (*[32]byte)(unsafe.Pointer(&dekBlob)),
		&dataKey,
	)

	buffer := &bytes.Buffer{}
	if err := gob.NewEncoder(buffer).Encode(payload); err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	ciphertext := encode(buffer.Bytes())

	// WARNING) For debugging only
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Ciphertext:", ciphertext)

	// Set response.
	resp.Operation = "Envelope-Encrypt"
	resp.Plaintext = plaintext
	resp.Ciphertext = ciphertext
	resp.Radix = -1 // Unused

	return apiResponse(
		http.StatusOK,
		&resp,
	)
}

func EnvelopeDecrypt(
	input string,
	ctx context.Context, // Reserved.
	req events.APIGatewayV2HTTPRequest, // Reserved.
) (
	events.APIGatewayV2HTTPResponse,
	error,
) {
	var resp FpeResponse

	// fmt.Println("[EnvelopeDecrypt] dekEnvelopeBlob: ", hex.EncodeToString(dekEnvelopeBlob))
	// fmt.Println("[EnvelopeDecrypt] dekBlob: ", hex.EncodeToString(dekBlob))

	// Extract payload.
	// encrypted, err := decode(input[8 : len(input)-1])
	encrypted, err := decode(input)
	if err != nil {
		return HandleError(http.StatusInternalServerError, errors.New(err.Error()))
	}

	// Decode payload structure.
	var payload KmsPayload
	gob.NewDecoder(bytes.NewReader(encrypted)).Decode(&payload)

	// // [2021-12-28] Decrypt key.
	// dataKey := kmsClient.DecryptDEK(payload.EncryptedDataKey)
	// fmt.Println("[EnvelopeDecrypt] decrypted data key: ", hex.EncodeToString(dataKey))

	var dataKey [32]byte
	copy(dataKey[:], dekBlob)

	// Decrypt message.
	var plainbytes []byte
	plainbytes, ok := secretbox.Open(
		plainbytes,
		payload.Message,
		payload.Nonce,
		// (*[32]byte)(unsafe.Pointer(&dekBlob)),
		&dataKey,
	)
	if !ok {
		return HandleError(http.StatusInternalServerError, errors.New("failed to open secretbox"))
	}

	ciphertext := input
	plaintext := string(plainbytes)

	// WARNING) For debugging only
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Ciphertext:", ciphertext)

	// Set response.
	resp.Operation = "Envelope-Decrypt"
	resp.Plaintext = plaintext
	resp.Ciphertext = ciphertext
	resp.Radix = -1 // Unused

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
