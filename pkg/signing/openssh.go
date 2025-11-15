package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/minio/sha256-simd"
	"io"
)

// sshSignature defines the structure described in OpenSSH PROTOCOL.sshsig
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
type sshSignature struct {
	Magic         [6]byte // "SSHSIG"
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      string // In the example, this is "file"
	Reserved2     string // In the example, this is ""
	HashAlgorithm string // This is "sk-ssh-ed25519@openssh.com"
	Signature     []byte // This is the *inner* sk-signature blob
}

// skSignature defines the inner blob format for sk-signatures
type skSignature struct {
	KeyType      string
	RawSignature []byte // This is the 64-byte Ed25519 signature
	Flags        byte
	Counter      uint32
}

// parseSSHSignature correctly parses the outer signature format.
func parseSSHSignature(data []byte) (*sshSignature, error) {
	r := bytes.NewReader(data)
	var sig sshSignature
	var err error

	// 1. Read "SSHSIG" magic (6 bytes, *not* length-prefixed)
	if _, err := io.ReadFull(r, sig.Magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if string(sig.Magic[:]) != "SSHSIG" {
		return nil, fmt.Errorf("invalid magic string: %s", string(sig.Magic[:]))
	}

	// 2. Read version (uint32)
	if err := binary.Read(r, binary.BigEndian, &sig.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	// 3. Read public key blob
	sig.PublicKey, err = readBytes(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// 4. Read namespace
	sig.Namespace, err = readString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read namespace: %w", err)
	}

	// 5. Read first reserved field (in this case, "file")
	sig.Reserved, err = readString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read reserved field 1: %w", err)
	}

	// 7. Read hash algorithm (for sk keys, this is the key type)
	sig.HashAlgorithm, err = readString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read hash algorithm: %w", err)
	}

	// 8. Read the inner signature blob
	sig.Signature, err = readBytes(r)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	return &sig, nil
}

// parseSkSignature parses the inner signature blob from an sk-key
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f look for:
// "For Ed25519 keys the signature is encoded as:"
func parseSkSignature(data []byte) (*skSignature, error) {
	r := bytes.NewReader(data)
	var skSig skSignature
	var err error

	// 1. Read key type (e.g., "sk-ssh-ed25519@openssh.com")
	skSig.KeyType, err = readString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sk key type: %w", err)
	}

	// 2. Read raw signature (this is what you want)
	skSig.RawSignature, err = readBytes(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sk raw signature: %w", err)
	}

	// 3. Read flags (uint32)
	if err := binary.Read(r, binary.BigEndian, &skSig.Flags); err != nil {
		// Some U2F-only keys might not send this
		return nil, fmt.Errorf("failed to read sk flags: %w", err)
	}

	// 4. Read counter (uint32)
	if err := binary.Read(r, binary.BigEndian, &skSig.Counter); err != nil {
		return nil, fmt.Errorf("failed to read sk counter: %w", err)
	}

	return &skSig, nil
}

// buildSSHSignaturePayload constructs the data blob that is covered by the SSH signature.
// This is the data that is hashed and then signed by the security key.
// The structure is: "SSHSIG" || namespace || reserved || hash_alg || HASH(data)
func buildSSHSignaturePayload(namespace string, hashAlgo string, dataToSign []byte) ([]byte, error) {
	// 1. Hash the original data using the specified algorithm.
	var dataHash []byte
	if hashAlgo != "sha512" {
		// The example uses sha512, for now we only support that.
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlgo)
	}
	h := sha512.New()
	h.Write(dataToSign)
	dataHash = h.Sum(nil)

	// 2. Construct the "to be signed" blob.
	buf := new(bytes.Buffer)

	// Magic header is not length-prefixed.
	if _, err := buf.Write([]byte("SSHSIG")); err != nil {
		return nil, err
	}

	// Write namespace
	if err := writeString(buf, namespace); err != nil {
		return nil, err
	}

	// Write reserved field (empty)
	if err := writeString(buf, ""); err != nil {
		return nil, err
	}

	// Write hash algorithm
	if err := writeString(buf, hashAlgo); err != nil {
		return nil, err
	}

	// Write the hash of the original data
	if err := writeBytes(buf, dataHash); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// buildFIDO2VerifiableMessage constructs the final message that was signed by the
// FIDO hardware authenticator.
// Structure: SHA256(appId) || flags || counter || SHA256(message_payload)
func buildFIDO2VerifiableMessage(appId string, messagePayload []byte, sig *skSignature) []byte {
	// 1. Calculate the application hash: SHA256(appId)
	// For standard ssh-keygen signing, the appId is "ssh:".
	appHash := sha256.Sum256([]byte(appId))

	// 2. Construct the authenticator data part of the message.
	authData := new(bytes.Buffer)
	authData.Write(appHash[:])
	authData.WriteByte(sig.Flags)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, sig.Counter)
	authData.Write(counterBytes)

	// 3. Calculate the message hash: SHA256(message_payload)
	// The message_payload is the `buildSSHSignaturePayload` output.
	msgHash := sha256.Sum256(messagePayload)

	// 4. Concatenate them to create the final message signed by the hardware.
	finalMsg := new(bytes.Buffer)
	finalMsg.Write(authData.Bytes())
	finalMsg.Write(msgHash[:])

	return finalMsg.Bytes()
}

// parseRawPubKey extracts the 32-byte raw public key from an
// sk-ssh-ed25519 public key blob.
func parseRawPubKey(pkBlob []byte) (ed25519.PublicKey, error) {
	r := bytes.NewReader(pkBlob)
	keyType, err := readString(r)
	if err != nil {
		return nil, err
	}
	if keyType != "sk-ssh-ed25519@openssh.com" {
		return nil, fmt.Errorf("unexpected key type: %s", keyType)
	}

	// The next field is the raw 32-byte key
	rawKey, err := readBytes(r)
	if err != nil {
		return nil, err
	}
	if len(rawKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d key bytes, got %d", ed25519.PublicKeySize, len(rawKey))
	}
	return rawKey, nil
}

// --- Helper Functions (from your code, which are correct) ---

// readBytes reads a length-prefixed byte slice
func readBytes(r *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > uint32(r.Len()) {
		return nil, fmt.Errorf("length %d too long for remaining buffer %d", length, r.Len())
	}
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// readString reads a length-prefixed string
func readString(r *bytes.Reader) (string, error) {
	b, err := readBytes(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeBytes(w io.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func writeString(w io.Writer, s string) error {
	return writeBytes(w, []byte(s))
}
