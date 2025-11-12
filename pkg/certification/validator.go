package certification

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// VerifyCertificateChain remains exactly the same as before,
// as it only validates public keys and signatures.
func VerifyCertificateChain(chain []Certificate) error {
	if len(chain) == 0 {
		return errors.New("certificate chain is empty")
	}

	// 1. Verify the root certificate (chain[0])
	root := chain[0]
	if !bytes.Equal(root.PublicKey(), root.IssuerPublicKey()) {
		return errors.New("root certificate [0] is not self-issued: issuer public key mismatch")
	}
	if !VerifySignature(root.IssuerPublicKey(), root.PublicKey(), root.Signature()) {
		return errors.New("root certificate [0] signature is invalid")
	}

	// 2. Verify the rest of the chain
	for i := 1; i < len(chain); i++ {
		current := chain[i]
		issuer := chain[i-1]

		if !bytes.Equal(current.IssuerPublicKey(), issuer.PublicKey()) {
			return fmt.Errorf("certificate [%d] issuer public key does not match certificate [%d] public key", i, i-1)
		}
		if !VerifySignature(current.IssuerPublicKey(), current.PublicKey(), current.Signature()) {
			return fmt.Errorf("certificate [%d] signature is invalid", i)
		}
	}
	return nil
}

// VerifySignature only needs a public key
func VerifySignature(publicKey ed25519.PublicKey, data []byte, signature []byte) bool {
	if data == nil || signature == nil {
		return false
	}
	return ed25519.Verify(publicKey, data, signature)
}
