package auth

import (
	"net/http"
	"testing"
)

// Returns API key when Authorization header is correctly formatted
func TestReturnsAPIKeyWhenAuthorizationHeaderIsCorrectlyFormatted(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if apiKey != "my-secret-key" {
		t.Fatalf("expected 'my-secret-key', got %v", apiKey)
	}
}

// Returns error when Authorization header is missing
func TestReturnsErrorWhenAuthorizationHeaderIsMissing(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Fatalf("expected an error, got nil")
	}

	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

// Handles Authorization header with "ApiKey" prefix correctly
func TestHandlesAuthorizationHeaderWithApiKeyPrefixCorrectly(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if apiKey != "my-secret-key" {
		t.Fatalf("expected 'my-secret-key', got %v", apiKey)
	}
}

// Returns error when Authorization header contains "ApiKey" but no key
func TestReturnsErrorWhenAuthorizationHeaderContainsApiKeyButNoKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatalf("expected an error, got nil")
	}

	expectedErrMsg := "malformed authorization header"
	if err.Error() != expectedErrMsg {
		t.Fatalf("expected error message '%v', got '%v'", expectedErrMsg, err.Error())
	}

	if apiKey != "" {
		t.Fatalf("expected empty string for apiKey, got %v", apiKey)
	}
}

// Returns error when Authorization header does not contain "ApiKey" prefix
func TestReturnsErrorWhenAuthorizationHeaderDoesNotContainApiKeyPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key")

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}

	expectedErrMsg := "malformed authorization header"
	if err.Error() != expectedErrMsg {
		t.Fatalf("expected error message '%s', got '%s'", expectedErrMsg, err.Error())
	}

	if apiKey != "" {
		t.Fatalf("expected empty apiKey, got %s", apiKey)
	}
}
