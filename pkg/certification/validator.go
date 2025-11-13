package certification

import (
	"crypto/ed25519"
)

// VerifySignature only needs a public key
func VerifySignature(publicKey ed25519.PublicKey, data []byte, signature []byte) bool {
	if data == nil || signature == nil {
		return false
	}
	return ed25519.Verify(publicKey, data, signature)
}

func (c *SimpleCertificate) Verify() bool {
	if c.PubKey == nil || c.IssuerPubKey == nil || c.IssuerRef == "" || c.Sig == nil {
		return false
	}
	
	return ed25519.Verify(c.IssuerPublicKey(), c.dataToSign(), c.Signature())
}
