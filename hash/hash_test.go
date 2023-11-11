package hash_test

import (
	"testing"

	"github.com/emmrys-jay/devtools/hash"
)

func Test_HashPassword(t *testing.T) {
	hashPassword(t, "password1234")
}

func Test_PasswordIsValid(t *testing.T) {

	var testValues = []struct{
		name string
		password string
		passwordCheck string
		expected bool
	}{
		{name: "Valid", password: "password", passwordCheck: "password", expected: true},
		{name: "Invalid", password: "password1234", passwordCheck: "password", expected: false},
	}

	for _, tests := range testValues {
		t.Run(tests.name, func(t *testing.T) {
			hashedPassword := hashPassword(t, tests.password)

			ok := hash.PasswordIsValid(tests.passwordCheck, hashedPassword) 
			if ok != tests.expected {
				t.Errorf("Expected '%v', but got '%v'", tests.expected, ok)
			}
		})
	}
}

func Test_HashPasswordWithSalt(t *testing.T) {
	hashPasswordWithSalt(t, "password1234")
}

func Test_PasswordWithSaltIsValid(t *testing.T) {

	var testValues = []struct{
		name string
		password string
		passwordCheck string
		expected bool
	}{
		{name: "Valid", password: "password", passwordCheck: "password", expected: true},
		{name: "Invalid", password: "password1234", passwordCheck: "password", expected: false},
	}

	for _, tests := range testValues {
		t.Run(tests.name, func(t *testing.T) {
			hashedPassword, salt := hashPasswordWithSalt(t, tests.password)

			ok := hash.PasswordWithSaltIsValid(tests.passwordCheck, salt, hashedPassword) 
			if ok != tests.expected {
				t.Errorf("Expected '%v', but got '%v'", tests.expected, ok)
			}
		})
	}
}

func hashPassword(t *testing.T, password string) (string) {
	hashedPassword, err := hash.HashPassword(password)
	if err != nil {
		t.Errorf("Expected 'error' to be nil, got 'error': %v", err)
	}

	if hashedPassword == "" {
		t.Errorf("Expected 'hashedPassword' not to be empty")
	}

	return hashedPassword
}

func hashPasswordWithSalt(t *testing.T, password string) (hashedPassword, salt string) {
	var err error
	hashedPassword, salt, err = hash.HashPasswordWithSalt(password)
	if err != nil {
		t.Errorf("Expected 'error' to be nil, got 'error': %v", err)
	}

	if hashedPassword == "" {
		t.Errorf("Expected 'hash' not to be empty")
	}

	if salt == "" {
		t.Errorf("Expected 'salt' not to be empty")
	}

	return
}

