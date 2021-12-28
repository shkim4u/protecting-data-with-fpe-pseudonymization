package handlers

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// KmsClientImpl implements the real KMS client
type KmsClientImpl struct {
	Impl *kms.KMS
}

// KmsFunction is a lambda that operates on the KMS service
type KmsFunction func(*kms.KMS) error

func newKmsClient() *KmsClientImpl {
	return &KmsClientImpl{}
}

// CallWithRetry executes a function with retry for MissingRegion or some errors
func (k *KmsClientImpl) CallWithRetry(f KmsFunction) error {
	// Lazy initialize the session
	if k.Impl == nil {
		// Force enable Shared Config to support $AWS_DEFAULT_REGION
		sess, err := session.NewSessionWithOptions(
			session.Options{
				SharedConfigState: session.SharedConfigEnable,
			},
		)

		if err != nil {
			return err
		}

		k.Impl = kms.New(sess)
	}

	// Invoke the function
	err := f(k.Impl)

	// Some retry logics by error go from here.
	switch err {
	case aws.ErrMissingRegion:
		// With default session.
		sess, err := session.NewSession()

		if err == nil {
			k.Impl = kms.New(sess)

			// Retry the function with the new session
			return f(k.Impl)
		}

	default:
	}

	return err
}

func (k *KmsClientImpl) DecryptDEK(data []byte) []byte {
	var response *kms.DecryptOutput

	err := k.CallWithRetry(func(impl *kms.KMS) error {
		var ferr error
		response, ferr = impl.Decrypt(
			&kms.DecryptInput{
				CiphertextBlob: data,
			},
		)
		return ferr
	})

	if err != nil {
		return nil
	}

	return response.Plaintext
}

// Generate FPE data encryption key and return its CiphertextBlob part
func (k *KmsClientImpl) GenerateDEK(keyId string) []byte {
	var response *kms.GenerateDataKeyOutput

	err := k.CallWithRetry(func(impl *kms.KMS) error {
		var ferr error
		keyNumberOfBytes := int64(32)
		response, ferr = impl.GenerateDataKey(
			&kms.GenerateDataKeyInput{
				KeyId:         &keyId,
				NumberOfBytes: &keyNumberOfBytes,
			},
		)
		return ferr
	})

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return response.CiphertextBlob
}
