package certification

import (
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"os"
)

// Ed25519KeyReader provides functionality to read ed25519 SSH keys
type Ed25519KeyReader struct{}

// NewEd25519KeyReader creates a new instance of Ed25519KeyReader
func NewEd25519KeyReader() *Ed25519KeyReader {
	return &Ed25519KeyReader{}
}

// ReadKeyFromFile reads an ed25519 SSH key from a file
// If the key is encrypted, password must be provided
func (r *Ed25519KeyReader) ReadKeyFromFile(filePath string) (ed25519.PrivateKey, error) {
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return r.ReadKeyFromBytes(keyData)
}

// ReadKeyFromBytes reads an ed25519 SSH key from raw bytes
// Uses the modern golang.org/x/crypto/ssh package which handles both encrypted and unencrypted keys
func (r *Ed25519KeyReader) ReadKeyFromBytes(keyData []byte) (ed25519.PrivateKey, error) {

	cryptoKey, err := ssh.ParseRawPrivateKey(keyData)

	var passphraseErr *ssh.PassphraseMissingError
	if errors.As(err, &passphraseErr) {
		fmt.Print("Enter passphrase: ")
		passwordBytes, passErr := terminal.ReadPassword(int(os.Stdin.Fd()))
		if passErr != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", passErr)
		}
		fmt.Println() // Add a newline after password entry

		cryptoKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, passwordBytes)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	cryptoSigner, ok := cryptoKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}
	ed25519PublicKey := cryptoSigner.Public().(ed25519.PublicKey)
	if len(ed25519PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid size %d for Ed25519 public key", len(ed25519PublicKey))
	}
	ed25519PrivateKey, ok := cryptoKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}
	if len(*ed25519PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid size %d for Ed25519 private key", len(*ed25519PrivateKey))
	}

	return *ed25519PrivateKey, nil
}

// ReadPublicKeyFromFile reads an ed25519 SSH public key from a file
func (r *Ed25519KeyReader) ReadPublicKeyFromFile(filePath string) (ed25519.PublicKey, error) {
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return r.ReadPublicKeyFromBytes(keyData)
}

// ReadPublicKeyFromBytes reads an ed25519 SSH public key from raw bytes
func (r *Ed25519KeyReader) ReadPublicKeyFromBytes(keyData []byte) (ed25519.PublicKey, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %w", err)
	}

	if publicKey.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("key is not ed25519, got: %s", publicKey.Type())
	}

	// Extract the ed25519 public key
	cryptoPubKey := publicKey.(ssh.CryptoPublicKey)
	ed25519PubKey := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)

	return ed25519PubKey, nil
}

// GetPublicKeyFromPrivate extracts the public key from a private key
func (r *Ed25519KeyReader) GetPublicKeyFromPrivate(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	return privateKey.Public().(ed25519.PublicKey)
}

// GenerateAndWritePrivateKey generates a new ed25519 private key and writes it to a file
// in SSH format. The file will be created with permissions 0600.
// The generated private key is returned.
func GenerateAndWritePrivateKey(filePath string) (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	// Create the file with 0600 permissions (read/write for owner only).
	// os.O_TRUNC ensures that if the file already exists, it will be truncated.
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, fmt.Errorf("failed to write PEM data to file: %w", err)
	}

	return privateKey, nil
}
