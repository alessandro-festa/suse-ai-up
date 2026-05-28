package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword bcrypts a plaintext password with the default cost.
// Extracted from UserAuthService so HTTP handlers can hash without
// constructing the full auth service.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
