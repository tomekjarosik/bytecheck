package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
	"strings"
)

type YubiKeySigner struct {
	privateKeyPath  string
	publicKeyPath   string
	issuerReference string
}

var _ Signer = (*YubiKeySigner)(nil)

func determineIfKeyFileIsYubikeyBased(privateKeyPath string, publicKeyPath string) error {
	_, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("private key file not found: %w", err)
	}
	publicKey, err := os.ReadFile(privateKeyPath + ".pub")
	if err != nil {
		return fmt.Errorf("public key file not found: %w", err)
	}
	if !strings.Contains(string(publicKey), "sk-ssh-ed25519") {
		return fmt.Errorf("public key file does not appear to be a YubiKey public key")
	}
	// Do not check private key as an SSH library does not seem to handle YubiKey-based ones
	return nil
}

func NewYubiKeySigner(privateKeyPath string, issuerReference string) (*YubiKeySigner, error) {
	err := determineIfKeyFileIsYubikeyBased(privateKeyPath, privateKeyPath+".pub")
	if err != nil {
		return nil, err
	}
	return &YubiKeySigner{
		privateKeyPath:  privateKeyPath,
		publicKeyPath:   privateKeyPath + ".pub",
		issuerReference: issuerReference,
	}, nil
}

func (y *YubiKeySigner) Sign(data []byte) ([]byte, error) {

	// Use ssh-keygen to sign, just like Git does
	fmt.Printf("Signing with YubiKey - you will need to touch it\n")
	cmd := exec.Command("ssh-keygen", "-Y", "sign",
		"-f", y.privateKeyPath,
		"-n", "file",
		"-q")

	cmd.Stdin = bytes.NewReader(data)

	signatureOutput, err := cmd.Output()
	if err != nil {
		// Attempt to include stderr in the error message for better debugging
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("ssh-keygen signing failed: %s: %w", string(exitErr.Stderr), err)
		}
		return nil, fmt.Errorf("ssh-keygen signing failed: %w", err)
	}
	block, _ := pem.Decode(signatureOutput)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from ssh-keygen output")
	}
	if block.Type != "SSH SIGNATURE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s, expected 'SSH SIGNATURE'", block.Type)
	}

	return block.Bytes, nil
}

func (y *YubiKeySigner) PublicKey() (ed25519.PublicKey, error) {
	pubKeyData, err := os.ReadFile(y.privateKeyPath + ".pub")
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %v", err)
	}

	if pubKey.Type() != ssh.KeyAlgoSKED25519 {
		return nil, fmt.Errorf("key is not an sk-ed25519 key. Found type: %s", pubKey.Type())
	}

	// Type assertion to get the underlying ed25519.PublicKey
	// Note: The ssh.PublicKey interface is usually implemented by an internal type
	// (e.g., *ed25519PublicKey) which wraps the standard crypto/ed25519.PublicKey.
	// You must assert it to the correct type to extract the raw bytes.
	ed25519PubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("Failed to assert ssh.PublicKey to ssh.CryptoPublicKey")
	}

	// Extract the standard crypto.PublicKey interface
	cryptoPubKey := ed25519PubKey.CryptoPublicKey()

	// Final type assertion to get the specific ed25519.PublicKey type
	standardEd25519Key, ok := cryptoPubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert to standard ed25519.PublicKey")
	}
	return standardEd25519Key, nil
}

func (y *YubiKeySigner) Reference() string {
	return y.issuerReference
}

func (y *YubiKeySigner) Algorithm() string {
	return SignatureAlgorithmSKEd25519
}

func (y *YubiKeySigner) Close() error {
	// Nothing to close for file-based approach
	return nil
}
