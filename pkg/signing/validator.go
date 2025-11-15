package signing

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

var SignatureAlgorithmEd25519 = "ed25519"
var SignatureAlgorithmSKEd25519 = "sk-ssh-ed25519"

// VerifySignature only needs a public key
func VerifySignature(algorithm string, publicKey ed25519.PublicKey, data []byte, signature []byte) (bool, error) {
	if data == nil || signature == nil {
		return false, fmt.Errorf("data or signature is nil")
	}
	switch algorithm {
	case "", SignatureAlgorithmEd25519:
		return ed25519.Verify(publicKey, data, signature), nil
	case SignatureAlgorithmSKEd25519:
		return verifySSHSignature(publicKey, data, signature)
	}
	return false, fmt.Errorf("unknown signature algorithm: %s", algorithm)
}

func verifySSHSignature(publicKey []byte, data []byte, signature []byte) (bool, error) {
	sshSig, err := parseSSHSignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse SSH signature: %w", err)
	}

	skSig, err := parseSkSignature(sshSig.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse SecurityKey/FIDO2 signature: %w", err)
	}

	// First, construct the payload that is covered by the outer SSH signature.
	// This is what `ssh-keygen` creates internally before it asks the FIDO key to sign.
	sshPayload, err := buildSSHSignaturePayload(sshSig.Namespace, sshSig.HashAlgorithm, data)
	if err != nil {
		return false, fmt.Errorf("failed to build SSH signature payload: %w", err)
	}

	// Now, construct the final message that the FIDO authenticator signed.
	// This includes the application ID hash, flags, counter, and a hash of the payload from 3a.
	// The AppID for ssh-keygen is "ssh:".
	messageToVerify := buildFIDO2VerifiableMessage("ssh:", sshPayload, skSig)

	sigPubKey, err := parseRawPubKey(sshSig.PublicKey)
	if !bytes.Equal(publicKey, sigPubKey) {
		return false, fmt.Errorf("signature public key mismatch: %s != %s", publicKey, sigPubKey)
	}

	// Use the raw Ed25519 public key to verify the raw signature against the message we just built.
	return ed25519.Verify(publicKey, messageToVerify, skSig.RawSignature), nil
}
