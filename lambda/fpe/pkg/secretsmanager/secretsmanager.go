package secretsmanager

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// Hold the real Secrets Manager client
type SecretsManagerClientImpl struct {
	Impl *secretsmanager.SecretsManager
}

// Arbitrary function to operate Secrets Manager service
type SecretsManagerFunction func(*secretsmanager.SecretsManager) error

func NewSecretsManagerClient() *SecretsManagerClientImpl {
	return &SecretsManagerClientImpl{}
}

// CallWithRetry executes a function with retry for MissingRegion or some errors
func (s *SecretsManagerClientImpl) CallWithRetry(f SecretsManagerFunction) error {
	// Lazy initialize the session
	if s.Impl == nil {
		// Force enable Shared Config to support $AWS_DEFAULT_REGION
		sess, err := session.NewSessionWithOptions(
			session.Options{
				SharedConfigState: session.SharedConfigEnable,
			},
		)

		if err != nil {
			return err
		}

		s.Impl = secretsmanager.New(sess)
	}

	// Invoke the function
	err := f(s.Impl)

	// Some retry logics by error go from here.
	switch err {
	case aws.ErrMissingRegion:
		// With default session.
		sess, err := session.NewSession()

		if err == nil {
			s.Impl = secretsmanager.New(sess)

			// Retry the function with the new session
			return f(s.Impl)
		}

	default:
	}

	return err
}

func (s *SecretsManagerClientImpl) CheckIfSecretValueExist(secretId string) (bool, *string) {
	var response *secretsmanager.GetSecretValueOutput

	err := s.CallWithRetry(func(impl *secretsmanager.SecretsManager) error {
		var ferr error
		response, ferr = impl.GetSecretValue(
			&secretsmanager.GetSecretValueInput{
				SecretId: aws.String(secretId),
			},
		)
		return ferr
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				return false, nil
			default:
				// How about the other case? Let's just also return false about this case.
				return false, nil
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and Message from an error.
			fmt.Println(err.Error())
			return false, nil
		}
	} else {
		return true, response.SecretString
	}
}

func (s *SecretsManagerClientImpl) CreateSecretWithValue(name string, secretString string, description string) {
	var response *secretsmanager.CreateSecretOutput

	err := s.CallWithRetry(func(impl *secretsmanager.SecretsManager) error {
		var ferr error
		response, ferr = impl.CreateSecret(
			&secretsmanager.CreateSecretInput{
				Name:         aws.String(name),
				SecretString: aws.String(secretString),
				Description:  aws.String(description),
			},
		)
		return ferr
	})

	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("CreateSecret() result: ", response)
	}
}
