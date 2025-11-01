package manifest

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"github.com/minio/sha256-simd"
	"os"
)

var DEFAULT_HMAC_KEY = []byte("this-is-obscurity-key-that")
var HMAC_KEY_ENV_VAR = "BYTECHECK_HMAC_KEY"

func calculateHMAC(data []byte) string {
	hmacKey := DEFAULT_HMAC_KEY
	if val, exist := os.LookupEnv(HMAC_KEY_ENV_VAR); exist {
		hmacKey = []byte(val)
		fmt.Printf("Using HMAC key from environment variable %s\n", HMAC_KEY_ENV_VAR)
	}
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
