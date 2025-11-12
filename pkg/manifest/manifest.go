package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

var DefaultName = ".bytecheck.manifest"

type Entity struct {
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
	IsDir    bool   `json:"isDir"`
}

// Certificate defines the interface for any certificate structure.
type Certificate interface {
	Name() string
	PublicKey() ed25519.PublicKey
	Signature() []byte
	IssuerPublicKey() ed25519.PublicKey
}

// SimpleCertificate implements Certificate interface
type SimpleCertificate struct {
	CertName     string            `json:"-"`
	PubKey       ed25519.PublicKey `json:"-"`
	Sig          []byte            `json:"-"`
	IssuerPubKey ed25519.PublicKey `json:"-"`
}

func (c *SimpleCertificate) Name() string                       { return c.CertName }
func (c *SimpleCertificate) PublicKey() ed25519.PublicKey       { return c.PubKey }
func (c *SimpleCertificate) Signature() []byte                  { return c.Sig }
func (c *SimpleCertificate) IssuerPublicKey() ed25519.PublicKey { return c.IssuerPubKey }

// CertificateData is the JSON-serializable representation
type CertificateData struct {
	Name            string `json:"name"`
	PublicKey       string `json:"publicKey"`
	Signature       string `json:"signature"`
	IssuerPublicKey string `json:"issuerPublicKey"`
}

// AuditorData is the JSON-serializable representation
type AuditorData struct {
	Timestamp         time.Time       `json:"timestamp"`
	Certificate       CertificateData `json:"certificate"`
	ManifestSignature string          `json:"manifestSignature"`
}

type Manifest struct {
	Entities []Entity     `json:"entities"`
	HMAC     string       `json:"hmac"`
	Auditor  *AuditorData `json:"auditor,omitempty"`
}

// New creates a new manifest with the given entities
func New(entities []Entity) *Manifest {
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Name < entities[j].Name
	})
	return &Manifest{
		Entities: entities,
	}
}

// SetAuditedBy sets the auditor using the Certificate interface
func (m *Manifest) SetAuditedBy(cert Certificate, manifestSignature []byte) {
	if cert == nil {
		m.Auditor = nil
		return
	}
	m.Auditor = &AuditorData{
		Timestamp: time.Now(),
		Certificate: CertificateData{
			Name:            cert.Name(),
			PublicKey:       hex.EncodeToString(cert.PublicKey()),
			Signature:       hex.EncodeToString(cert.Signature()),
			IssuerPublicKey: hex.EncodeToString(cert.IssuerPublicKey()),
		},
		ManifestSignature: hex.EncodeToString(manifestSignature),
	}
}

// GetAuditorCertificate returns the auditor's certificate as a Certificate interface
func (m *Manifest) GetAuditorCertificate() Certificate {
	if m.Auditor == nil {
		return nil
	}

	pubKey, _ := hex.DecodeString(m.Auditor.Certificate.PublicKey)
	sig, _ := hex.DecodeString(m.Auditor.Certificate.Signature)
	issuerPubKey, _ := hex.DecodeString(m.Auditor.Certificate.IssuerPublicKey)

	return &SimpleCertificate{
		CertName:     m.Auditor.Certificate.Name,
		PubKey:       pubKey,
		Sig:          sig,
		IssuerPubKey: issuerPubKey,
	}
}

// GetAuditorManifestSignature returns the decoded manifest signature
func (m *Manifest) GetAuditorManifestSignature() []byte {
	if m.Auditor == nil {
		return nil
	}
	sig, _ := hex.DecodeString(m.Auditor.ManifestSignature)
	return sig
}

// LoadManifest loads a manifest from the given directory
func LoadManifest(manifestPath string) (*Manifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No manifest exists
		}
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	sort.Slice(m.Entities, func(i, j int) bool {
		return m.Entities[i].Name < m.Entities[j].Name
	})

	loadedHMAC := m.HMAC
	err = m.calculateHMAC()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
	}
	if loadedHMAC != m.HMAC {
		return nil, fmt.Errorf("invalid HMAC")
	}

	return &m, nil
}

// Save saves the manifest to the given directory
func (m *Manifest) Save(manifestPath string) error {
	if err := m.calculateHMAC(); err != nil {
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	return os.WriteFile(manifestPath, data, 0644)
}

// Touch updates the manifest file's modification time without changing content
func (m *Manifest) Touch(manifestPath string) error {
	now := time.Now()
	return os.Chtimes(manifestPath, now, now)
}

// GetModTime returns the manifest file's modification time
func GetModTime(manifestPath string) (time.Time, error) {
	info, err := os.Stat(manifestPath)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func LoadManifestIfFresh(manifestPath string, freshnessLimit *time.Duration) (*Manifest, error) {
	if freshnessLimit == nil {
		return nil, nil
	}

	modTime, err := GetModTime(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No manifest exists
		}
		return nil, err
	}
	age := time.Since(modTime)
	if age > *freshnessLimit {
		return nil, nil
	}
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// calculateHMAC computes HMAC for the manifest (excluding the HMAC field itself)
func (m *Manifest) calculateHMAC() error {
	manifestCopy := &Manifest{
		Entities: m.Entities,
		// HMAC field is omitted
	}

	data, err := json.Marshal(manifestCopy)
	if err != nil {
		return err
	}

	m.HMAC = calculateHMAC(data)
	return nil
}

func (m *Manifest) DataWithoutAuditor() ([]byte, error) {
	manifestCopy := *m
	manifestCopy.Auditor = nil
	return json.Marshal(&manifestCopy)
}
