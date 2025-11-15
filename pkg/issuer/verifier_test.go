package issuer

import (
	"crypto/ed25519"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

// MockVerifier implements Verifier for testing
type MockVerifier struct {
	supportedSchemes map[Reference]bool
	verifyResults    map[Reference]Status
}

func NewMockVerifier() *MockVerifier {
	return &MockVerifier{
		supportedSchemes: make(map[Reference]bool),
		verifyResults:    make(map[Reference]Status),
	}
}

func (m *MockVerifier) Supports(reference Reference) bool {
	return m.supportedSchemes[reference]
}

func (m *MockVerifier) Verify(issuers []Issuer) map[Reference]Status {
	result := make(map[Reference]Status)
	for _, issuer := range issuers {
		if status, exists := m.verifyResults[issuer.Reference]; exists {
			result[issuer.Reference] = status
		}
	}
	return result
}

func (m *MockVerifier) AddSupportedScheme(scheme Reference, result Status) {
	m.supportedSchemes[scheme] = true
	m.verifyResults[scheme] = result
}

// Test data
var (
	validPublicKey   = ed25519.PublicKey("valid-public-key-12345")
	invalidPublicKey = ed25519.PublicKey("invalid-public-key-67890")

	testReference1 = Reference("github:testuser")
	testReference2 = Reference("corp://keyserver/team")
	testReference3 = Reference("unknown://scheme/test")

	testIssuer1 = Issuer{Reference: testReference1, PublicKey: validPublicKey}
	testIssuer2 = Issuer{Reference: testReference2, PublicKey: validPublicKey}
	testIssuer3 = Issuer{Reference: testReference3, PublicKey: invalidPublicKey}
)

func TestMultiSourceVerifier_NewMultiSourceVerifier(t *testing.T) {
	verifier1 := NewMockVerifier()
	verifier2 := NewMockVerifier()

	multiVerifier := NewMultiSourceVerifier(verifier1, verifier2)
	require.NotNil(t, multiVerifier)
	require.Equal(t, 2, len(multiVerifier.verifiers))
}

func TestMultiSourceVerifier_Verify_NoVerifiers(t *testing.T) {
	multiVerifier := NewMultiSourceVerifier()
	issuers := []Issuer{testIssuer1, testIssuer2}

	result := multiVerifier.Verify(issuers)
	require.NotNil(t, result)

	// All issuers should be unsupported when no verifiers are present
	for _, issuer := range issuers {
		status, exists := result[issuer.Reference]
		if !exists {
			t.Errorf("Expected status for issuer %s", issuer.Reference)
			continue
		}

		if status.Supported {
			t.Errorf("Expected issuer %s to be unsupported", issuer.Reference)
		}

		if status.Issuer.Reference != issuer.Reference {
			t.Errorf("Expected reference %s, got %s", issuer.Reference, status.Issuer.Reference)
		}
	}
}

func TestMultiSourceVerifier_Verify_WithSupportingVerifier(t *testing.T) {
	// Create mock verifiers
	githubVerifier := NewMockVerifier()
	corpVerifier := NewMockVerifier()

	// Set up github verifier to support testReference1
	expectedStatus1 := Status{
		Issuer:    testIssuer1,
		Supported: true,
		Error:     nil,
	}
	githubVerifier.AddSupportedScheme(testReference1, expectedStatus1)

	// Set up corp verifier to support testReference2
	expectedStatus2 := Status{
		Issuer:    testIssuer2,
		Supported: true,
		Error:     errors.New("key expired"),
	}
	corpVerifier.AddSupportedScheme(testReference2, expectedStatus2)

	multiVerifier := NewMultiSourceVerifier(githubVerifier, corpVerifier)
	issuers := []Issuer{testIssuer1, testIssuer2, testIssuer3}

	result := multiVerifier.Verify(issuers)
	require.NotNil(t, result)

	// Check testReference1 (handled by githubVerifier)
	status1, exists := result[testReference1]
	assert.True(t, exists)
	assert.True(t, status1.Supported)
	require.NoError(t, status1.Error)

	// Check testReference2 (handled by corpVerifier)
	status2, exists := result[testReference2]
	assert.True(t, exists)
	assert.True(t, status2.Supported)
	require.Error(t, status2.Error)

	// Check testReference3 (no verifier supports it)
	status3, exists := result[testReference3]
	require.True(t, exists)
	require.False(t, status3.Supported)
}

func TestMultiSourceVerifier_Verify_OrderMatters(t *testing.T) {
	// Create two verifiers that both support the same scheme
	verifier1 := NewMockVerifier()
	verifier2 := NewMockVerifier()

	// Both support testReference1 but return different results
	status1 := Status{
		Issuer:    testIssuer1,
		Supported: true,
		Error:     nil,
	}
	status2 := Status{
		Issuer:    testIssuer1,
		Supported: false,
		Error:     errors.New("rejected by second verifier"),
	}

	verifier1.AddSupportedScheme(testReference1, status1)
	verifier2.AddSupportedScheme(testReference1, status2)

	// Test with verifier1 first
	multiVerifier1 := NewMultiSourceVerifier(verifier1, verifier2)
	result1 := multiVerifier1.Verify([]Issuer{testIssuer1})

	status := result1[testReference1]
	if !status.Supported || status.Error != nil {
		t.Error("Expected first verifier to handle the issuer")
	}

	// Test with verifier2 first
	multiVerifier2 := NewMultiSourceVerifier(verifier2, verifier1)
	result2 := multiVerifier2.Verify([]Issuer{testIssuer1})

	status = result2[testReference1]
	if status.Supported || status.Error == nil {
		t.Error("Expected second verifier to handle the issuer when placed first")
	}
}

func TestMultiSourceVerifier_Verify_EmptyIssuers(t *testing.T) {
	verifier := NewMockVerifier()
	multiVerifier := NewMultiSourceVerifier(verifier)

	result := multiVerifier.Verify([]Issuer{})

	if result == nil {
		t.Fatal("Expected non-nil result for empty issuers")
	}

	if len(result) != 0 {
		t.Errorf("Expected empty result map, got %d entries", len(result))
	}
}

func TestMultiSourceVerifier_Verify_NilIssuers(t *testing.T) {
	verifier := NewMockVerifier()
	multiVerifier := NewMultiSourceVerifier(verifier)

	result := multiVerifier.Verify(nil)

	if result == nil {
		t.Fatal("Expected non-nil result for nil issuers")
	}

	if len(result) != 0 {
		t.Errorf("Expected empty result map for nil issuers, got %d entries", len(result))
	}
}

func TestMultiSourceVerifier_Supports(t *testing.T) {
	multiVerifier := NewMultiSourceVerifier()

	// MultiSourceVerifier should always return true for Supports
	if !multiVerifier.Supports("any://scheme") {
		t.Error("Expected Supports to always return true")
	}

	if !multiVerifier.Supports("") {
		t.Error("Expected Supports to return true for empty string")
	}

	if !multiVerifier.Supports("unknown://scheme/path") {
		t.Error("Expected Supports to return true for unknown scheme")
	}
}

func TestIssuerStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   Status
		expected string
	}{
		{
			name: "supported no error",
			status: Status{
				Issuer:    testIssuer1,
				Supported: true,
				Error:     nil,
			},
			expected: "Issuer(github:testuser): supported",
		},
		{
			name: "supported with error",
			status: Status{
				Issuer:    testIssuer2,
				Supported: true,
				Error:     errors.New("validation failed"),
			},
			expected: "Issuer(corp://keyserver/team): supported, error: validation failed",
		},
		{
			name: "unsupported",
			status: Status{
				Issuer:    testIssuer3,
				Supported: false,
				Error:     nil,
			},
			expected: "Issuer(unknown://scheme/test): unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.String()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Test helper function for String() method
func (is Status) String() string {
	status := "unsupported"
	if is.Supported {
		status = "supported"
		if is.Error != nil {
			status += ", error: " + is.Error.Error()
		}
	}
	return "Issuer(" + string(is.Reference) + "): " + status
}
