package issuer

import (
	"fmt"
	"net/url"
	"strings"
)

// SchemeConfig represents a parsed auditor scheme configuration
type SchemeConfig struct {
	Name     string
	Template string
}

// ParseSchemeConfig parses a single scheme configuration string in format "name:url-template"
func ParseSchemeConfig(schemeStr string) (*SchemeConfig, error) {
	name, template, found := strings.Cut(schemeStr, ":")
	if !found {
		return nil, fmt.Errorf("invalid scheme format: %s, expected 'name:url-template'", schemeStr)
	}

	name = strings.TrimSpace(name)
	template = strings.TrimSpace(template)

	if name == "" {
		return nil, fmt.Errorf("scheme name cannot be empty")
	}

	if template == "" {
		return nil, fmt.Errorf("url template cannot be empty")
	}

	// Validate the template format
	if err := ValidateURLTemplate(template); err != nil {
		return nil, fmt.Errorf("invalid URL template: %w", err)
	}

	return &SchemeConfig{
		Name:     name,
		Template: template,
	}, nil
}

// ValidateURLTemplate validates that a URL template has proper format
func ValidateURLTemplate(template string) error {
	// Allow 0 or 1 "%s" placeholders
	if strings.Count(template, "%s") > 1 {
		return fmt.Errorf("template can have at most one '%%s' placeholder")
	}

	// Test if it's a valid URL
	testURL := template
	// If there's a %s placeholder, replace it with a test value
	if strings.Contains(template, "%s") {
		testURL = strings.Replace(template, "%s", "test-identifier", 1)
	}

	parsed, err := url.ParseRequestURI(testURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Additional validation for supported schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "file" {
		return fmt.Errorf("unsupported URL scheme: %s, only http, https, and file are supported", parsed.Scheme)
	}

	return nil
}
