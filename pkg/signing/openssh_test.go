package signing

import (
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseOpenSSHSignature(t *testing.T) {
	// The signature you provided
	testSignature := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgPnlzMB
8sDWOtiRDoS6cHBX+9rpWG5nJy55W/3Gi40+sAAAAEc3NoOgAAAARmaWxlAAAAAAAAAAZz
aGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQBeN28INjY2GT0
wfFJfRUnmjkYzyKQDfaWUeXMjTqVMpXLE+68viao5/yVdEgRt/4WgbOgeVb2KGtujse9CI
jwcFAAABhA==
-----END SSH SIGNATURE-----`

	// Decode the PEM block
	block, _ := pem.Decode([]byte(testSignature))
	require.NotNil(t, block)
	require.Equal(t, block.Type, "SSH SIGNATURE")

	// --- Step 1: Parse the outer SSH Signature structure ---
	sshSig, err := parseSSHSignature(block.Bytes)
	require.NoError(t, err)

	fmt.Printf("--- Outer SSH Signature (PROTOCOL.sshsig) ---\n")
	fmt.Printf("Magic: %s\n", string(sshSig.Magic[:]))
	fmt.Printf("Version: %d\n", sshSig.Version)
	fmt.Printf("Namespace: %s\n", sshSig.Namespace)
	fmt.Printf("Reserved1: %s\n", sshSig.Reserved)
	fmt.Printf("Reserved2 (empty): %s\n", sshSig.Reserved2)
	fmt.Printf("Hash Algorithm: %s\n", sshSig.HashAlgorithm)
	fmt.Printf("Inner Signature Blob length: %d\n", len(sshSig.Signature))
	fmt.Println("-----------------------------------------------")

	assert.EqualValues(t, string(sshSig.Magic[:]), "SSHSIG")
	assert.Equal(t, sshSig.Namespace, "file")
	assert.Equal(t, sshSig.HashAlgorithm, "sha512")

	// --- Step 2: Parse the inner SK Signature blob ---
	// The .Signature field from the outer struct is passed here.
	// This only applies to "sk-" key types.
	require.Contains(t, sshSig.HashAlgorithm, "sha512")

	skSig, err := parseSkSignature(sshSig.Signature)
	require.NoError(t, err)

	fmt.Printf("--- Inner SK Signature (sk-specific) ---\n")
	fmt.Printf("Key Type: %s\n", skSig.KeyType)
	fmt.Printf("Flags: 0x%x\n", skSig.Flags)
	fmt.Printf("Counter: %d\n", skSig.Counter)
	fmt.Printf("\n✅ Extracted Raw Ed25519 Signature (64 bytes):\n%x\n", skSig.RawSignature)

	// Verify this is the 64-byte raw signature you wanted
	assert.Equal(t, 64, len(skSig.RawSignature))
}
