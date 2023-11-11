package hash

import (
	"math/rand"

	"golang.org/x/crypto/bcrypt"
)

var (
	saltLen int = 8
	
)

func HashPassword(password string) (hashed string, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func HashPasswordWithSalt(password string) (hashed string, salt string, err error) {
	salt = randomSalt()
	hash, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return string(hash), salt, nil
}

func PasswordIsValid(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func PasswordWithSaltIsValid(password, salt, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password+salt))
	return err == nil
}

func randomSalt() string {
	var salt string
	for i := 0; i < saltLen; i++ {
		char := rand.Int31n(122) + 41
		salt += string(char)
	}

	return salt
}
