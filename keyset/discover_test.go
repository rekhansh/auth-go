package keyset_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type MockKeySetDiscovery struct {
	TestString string
}

const (
	// TestString is a test string for the mock implementation
	ErrorEmpty = "is empty"
)

// Mock implementation of the KeysetDiscovery interface
func (m *MockKeySetDiscovery) GetKeyset() (jwk.Set, error) {
	if m.TestString == "" {
		return nil, errors.New(ErrorEmpty)
	}
	return nil, nil
}

func TestKeysetDiscovery(t *testing.T) {
	t.Run("TestKeysetDiscovery", func(t *testing.T) {
		mockKeyset := &MockKeySetDiscovery{
			TestString: "",
		}

		keyset, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", keyset)
		}
		if err.Error() != ErrorEmpty {
			t.Errorf("Expected error message: %s, got: %s", ErrorEmpty, err.Error())
		}
	})
}
