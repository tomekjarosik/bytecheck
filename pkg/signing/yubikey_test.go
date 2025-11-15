package signing

import (
	"crypto/ed25519"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifySignature_whenSignedByYubikey_2(t *testing.T) {
	testSignature := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgPnlzMB
8sDWOtiRDoS6cHBX+9rpWG5nJy55W/3Gi40+sAAAAEc3NoOgAAAARmaWxlAAAAAAAAAAZz
aGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQB2mBm2HW2T76E
XqTjm1q4Al3w2gYuC0GcpR6GZ5XitBUXXxI+flccYPMEUW+WPybABU1fcYtn7KSh4FaKqY
4QAFAAABiA==
-----END SSH SIGNATURE-----`

	block, _ := pem.Decode([]byte(testSignature))
	require.NotNil(t, block)
	require.Equal(t, block.Type, "SSH SIGNATURE")

	sshSig, err := parseSSHSignature(block.Bytes)
	require.NoError(t, err)

	skSig, err := parseSkSignature(sshSig.Signature)
	require.NoError(t, err)

	originalData := []byte("test")

	// First, construct the payload that is covered by the outer SSH signature.
	// This is what `ssh-keygen` creates internally before it asks the FIDO key to sign.
	sshPayload, err := buildSSHSignaturePayload(sshSig.Namespace, sshSig.HashAlgorithm, originalData)
	require.NoError(t, err)

	// Now, construct the final message that the FIDO authenticator signed.
	// This includes the application ID hash, flags, counter, and a hash of the payload from 3a.
	// The AppID for ssh-keygen is "ssh:".
	messageToVerify := buildFIDO2VerifiableMessage("ssh:", sshPayload, skSig)

	// --- 4. Get the public key ---
	// In a real scenario, you would fetch this from a trusted source.
	// Here, we extract it from the signature for self-contained verification.
	pubKey, err := parseRawPubKey(sshSig.PublicKey)
	require.NoError(t, err)

	// --- 5. Perform the verification ---
	// Use the raw Ed25519 public key to verify the raw signature against the message we just built.
	res := ed25519.Verify(pubKey, messageToVerify, skSig.RawSignature)
	assert.True(t, res, "Signature verification failed")
}
