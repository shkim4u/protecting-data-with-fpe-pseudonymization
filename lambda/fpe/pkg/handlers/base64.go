package handlers

import (
	"encoding/base64"
)

func decode(encoded string) ([]byte, error) {
	message := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(message, []byte(encoded))
	if err != nil {
		return nil, err
	}

	return message[0:n], nil
}

func encode(message []byte) string {
	return base64.StdEncoding.EncodeToString(message)
}
